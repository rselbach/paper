package main

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	defaultAddr            = ":8080"
	defaultDBPath          = "paper.db"
	defaultSecretTTL       = 7 * 24 * time.Hour
	defaultMaxSecretBytes  = 64 * 1024
	defaultCleanupInterval = time.Hour
)

var (
	//go:embed static/index.html static/assets/*
	staticFiles embed.FS

	errSecretExists       = errors.New("secret id already exists")
	errSecretUnavailable  = errors.New("secret is unavailable or already used")
	errSecretExpired      = errors.New("secret expired")
	errSecretUnauthorized = errors.New("invalid secret key proof")
	tokenPattern          = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)
)

type config struct {
	addr            string
	dbPath          string
	publicOrigin    string
	secretTTL       time.Duration
	cleanupInterval time.Duration
	maxSecretBytes  int
}

type store struct {
	db *sql.DB
}

type storedSecret struct {
	Ciphertext      []byte
	Nonce           []byte
	ConsumeVerifier []byte
}

type server struct {
	store          *store
	logger         *slog.Logger
	index          []byte
	assets         fs.FS
	publicOrigin   string
	secretTTL      time.Duration
	maxSecretBytes int
}

type createSecretRequest struct {
	ID              string `json:"id"`
	Ciphertext      string `json:"ciphertext"`
	Nonce           string `json:"nonce"`
	ConsumeVerifier string `json:"consumeVerifier"`
}

type createSecretResponse struct {
	URL       string    `json:"url"`
	Path      string    `json:"path"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type consumeSecretResponse struct {
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
}

type consumeSecretRequest struct {
	ConsumeVerifier string `json:"consumeVerifier"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := loadConfig()
	if err != nil {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()
	store, err := openStore(ctx, cfg.dbPath)
	if err != nil {
		logger.Error("open store", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Error("close store", "error", err)
		}
	}()

	if err := store.DeleteExpired(ctx, time.Now()); err != nil {
		logger.Error("delete expired secrets", "error", err)
		os.Exit(1)
	}
	startExpiredSecretCleaner(ctx, store, logger, cfg.cleanupInterval)

	app, err := newServer(store, logger, cfg.publicOrigin, cfg.secretTTL, cfg.maxSecretBytes)
	if err != nil {
		logger.Error("create server", "error", err)
		os.Exit(1)
	}

	httpServer := &http.Server{
		Addr:              cfg.addr,
		Handler:           app.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logger.Info("listening", "addr", cfg.addr, "db", cfg.dbPath, "publicOrigin", cfg.publicOrigin, "cleanupInterval", cfg.cleanupInterval)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("serve http", "error", err)
		os.Exit(1)
	}
}

func loadConfig() (config, error) {
	cfg := config{
		addr:            getenv("PAPER_ADDR", defaultAddr),
		dbPath:          getenv("PAPER_DB", defaultDBPath),
		secretTTL:       defaultSecretTTL,
		cleanupInterval: defaultCleanupInterval,
		maxSecretBytes:  defaultMaxSecretBytes,
	}

	if value := os.Getenv("PAPER_PUBLIC_ORIGIN"); value != "" {
		publicOrigin, err := normalizePublicOrigin(value)
		if err != nil {
			return config{}, fmt.Errorf("parse PAPER_PUBLIC_ORIGIN: %w", err)
		}
		cfg.publicOrigin = publicOrigin
	}

	if value := os.Getenv("PAPER_SECRET_TTL_HOURS"); value != "" {
		hours, err := strconv.Atoi(value)
		if err != nil {
			return config{}, fmt.Errorf("parse PAPER_SECRET_TTL_HOURS: %w", err)
		}
		if hours <= 0 {
			return config{}, fmt.Errorf("PAPER_SECRET_TTL_HOURS must be positive: %d", hours)
		}
		cfg.secretTTL = time.Duration(hours) * time.Hour
	}

	if value := os.Getenv("PAPER_CLEANUP_INTERVAL_MINUTES"); value != "" {
		minutes, err := strconv.Atoi(value)
		if err != nil {
			return config{}, fmt.Errorf("parse PAPER_CLEANUP_INTERVAL_MINUTES: %w", err)
		}
		if minutes <= 0 {
			return config{}, fmt.Errorf("PAPER_CLEANUP_INTERVAL_MINUTES must be positive: %d", minutes)
		}
		cfg.cleanupInterval = time.Duration(minutes) * time.Minute
	}

	if value := os.Getenv("PAPER_MAX_SECRET_BYTES"); value != "" {
		maxBytes, err := strconv.Atoi(value)
		if err != nil {
			return config{}, fmt.Errorf("parse PAPER_MAX_SECRET_BYTES: %w", err)
		}
		if maxBytes <= 0 {
			return config{}, fmt.Errorf("PAPER_MAX_SECRET_BYTES must be positive: %d", maxBytes)
		}
		cfg.maxSecretBytes = maxBytes
	}

	return cfg, nil
}

func normalizePublicOrigin(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("scheme must be http or https")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("host is required")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("query and fragment are not allowed")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("path is not supported")
	}
	parsed.Path = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func getenv(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func openStore(ctx context.Context, path string) (*store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	store := &store{db: db}
	if err := store.configure(ctx); err != nil {
		closeErr := db.Close()
		if closeErr != nil {
			return nil, fmt.Errorf("%w; close sqlite after configure failure: %v", err, closeErr)
		}
		return nil, err
	}

	return store, nil
}

func (s *store) configure(ctx context.Context) error {
	s.db.SetMaxOpenConns(1)
	statements := []string{
		"PRAGMA busy_timeout = 5000",
		"PRAGMA foreign_keys = ON",
		"PRAGMA secure_delete = ON",
		"PRAGMA journal_mode = WAL",
		`CREATE TABLE IF NOT EXISTS secrets (
			id TEXT PRIMARY KEY,
			ciphertext BLOB NOT NULL,
			nonce BLOB NOT NULL,
			consume_verifier BLOB,
			created_at_unix INTEGER NOT NULL,
			expires_at_unix INTEGER NOT NULL
		) STRICT`,
		"ALTER TABLE secrets ADD COLUMN consume_verifier BLOB",
		"CREATE INDEX IF NOT EXISTS secrets_expires_at_idx ON secrets(expires_at_unix)",
	}

	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			if statement == "ALTER TABLE secrets ADD COLUMN consume_verifier BLOB" && isDuplicateColumnError(err) {
				continue
			}
			return fmt.Errorf("exec sqlite statement %q: %w", statement, err)
		}
	}

	return nil
}

func isDuplicateColumnError(err error) bool {
	return strings.Contains(err.Error(), "duplicate column name")
}

func (s *store) Close() error {
	return s.db.Close()
}

func (s *store) Create(ctx context.Context, id string, ciphertext []byte, nonce []byte, consumeVerifier []byte, now time.Time, ttl time.Duration) (time.Time, error) {
	expiresAt := now.UTC().Add(ttl)
	result, err := s.db.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO secrets (
			id, ciphertext, nonce, consume_verifier, created_at_unix, expires_at_unix
		) VALUES (?, ?, ?, ?, ?, ?)`,
		id,
		ciphertext,
		nonce,
		consumeVerifier,
		now.UTC().Unix(),
		expiresAt.Unix(),
	)
	if err != nil {
		return time.Time{}, fmt.Errorf("insert secret: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return time.Time{}, fmt.Errorf("read inserted row count: %w", err)
	}
	if rowsAffected == 0 {
		return time.Time{}, errSecretExists
	}

	return expiresAt, nil
}

func (s *store) Consume(ctx context.Context, id string, consumeVerifier []byte, now time.Time) (*storedSecret, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin consume transaction: %w", err)
	}

	var secret storedSecret
	var expiresAtUnix int64
	row := tx.QueryRowContext(
		ctx,
		"SELECT ciphertext, nonce, consume_verifier, expires_at_unix FROM secrets WHERE id = ?",
		id,
	)
	if err := row.Scan(&secret.Ciphertext, &secret.Nonce, &secret.ConsumeVerifier, &expiresAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, rollbackWithError(tx, errSecretUnavailable)
		}
		return nil, rollbackWithError(tx, fmt.Errorf("select secret: %w", err))
	}

	if now.UTC().Unix() >= expiresAtUnix {
		if _, err := tx.ExecContext(ctx, "DELETE FROM secrets WHERE id = ?", id); err != nil {
			return nil, rollbackWithError(tx, fmt.Errorf("delete expired secret: %w", err))
		}
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit expired secret deletion: %w", err)
		}
		return nil, errSecretExpired
	}

	if len(secret.ConsumeVerifier) != 32 || subtle.ConstantTimeCompare(secret.ConsumeVerifier, consumeVerifier) != 1 {
		return nil, rollbackWithError(tx, errSecretUnauthorized)
	}

	if _, err := tx.ExecContext(ctx, "DELETE FROM secrets WHERE id = ?", id); err != nil {
		return nil, rollbackWithError(tx, fmt.Errorf("delete consumed secret: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit consumed secret deletion: %w", err)
	}

	return &secret, nil
}

func (s *store) DeleteExpired(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(
		ctx,
		"DELETE FROM secrets WHERE expires_at_unix <= ?",
		now.UTC().Unix(),
	)
	if err != nil {
		return fmt.Errorf("delete expired secrets: %w", err)
	}
	return nil
}

func startExpiredSecretCleaner(ctx context.Context, store *store, logger *slog.Logger, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := store.DeleteExpired(ctx, time.Now()); err != nil {
					logger.Error("delete expired secrets", "error", err)
				}
			}
		}
	}()
}

func rollbackWithError(tx *sql.Tx, err error) error {
	rollbackErr := tx.Rollback()
	if rollbackErr != nil {
		return fmt.Errorf("%w; rollback failed: %v", err, rollbackErr)
	}
	return err
}

func newServer(store *store, logger *slog.Logger, publicOrigin string, secretTTL time.Duration, maxSecretBytes int) (*server, error) {
	index, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		return nil, fmt.Errorf("read embedded index: %w", err)
	}

	assets, err := fs.Sub(staticFiles, "static/assets")
	if err != nil {
		return nil, fmt.Errorf("load embedded assets: %w", err)
	}

	return &server{
		store:          store,
		logger:         logger,
		index:          index,
		assets:         assets,
		publicOrigin:   publicOrigin,
		secretTTL:      secretTTL,
		maxSecretBytes: maxSecretBytes,
	}, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(s.assets))))
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /s/{id}", s.handleSecretPage)
	mux.HandleFunc("POST /api/secrets", s.handleCreateSecret)
	mux.HandleFunc("POST /api/secrets/{id}/consume", s.handleConsumeSecret)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return s.securityHeaders(mux)
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("ok\n")); err != nil {
		s.logger.Error("write health response", "error", err)
	}
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.writeHTML(w)
}

func (s *server) handleSecretPage(w http.ResponseWriter, r *http.Request) {
	if !tokenPattern.MatchString(r.PathValue("id")) {
		http.NotFound(w, r)
		return
	}
	s.writeHTML(w)
}

func (s *server) writeHTML(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(s.index); err != nil {
		s.logger.Error("write index response", "error", err)
	}
}

func (s *server) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	maxBodyBytes := base64.RawURLEncoding.EncodedLen(s.maxSecretBytes+32) + 4096
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBodyBytes))
	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("close create request body", "error", err)
		}
	}()

	var request createSecretRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err), s.logger)
		return
	}

	ciphertext, nonce, consumeVerifier, err := s.validateCreateRequest(request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), s.logger)
		return
	}

	expiresAt, err := s.store.Create(r.Context(), request.ID, ciphertext, nonce, consumeVerifier, time.Now(), s.secretTTL)
	if err != nil {
		if errors.Is(err, errSecretExists) {
			writeError(w, http.StatusConflict, err.Error(), s.logger)
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("store secret: %v", err), s.logger)
		return
	}

	path := "/s/" + request.ID
	writeJSON(w, http.StatusCreated, createSecretResponse{
		URL:       s.origin(r) + path,
		Path:      path,
		ExpiresAt: expiresAt,
	}, s.logger)
}

func (s *server) validateCreateRequest(request createSecretRequest) ([]byte, []byte, []byte, error) {
	if !tokenPattern.MatchString(request.ID) {
		return nil, nil, nil, errors.New("id must be 22-64 base64url characters")
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(request.Ciphertext)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ciphertext must be base64url: %w", err)
	}
	if len(ciphertext) == 0 {
		return nil, nil, nil, errors.New("ciphertext is required")
	}
	if len(ciphertext) > s.maxSecretBytes+32 {
		return nil, nil, nil, fmt.Errorf("ciphertext exceeds %d bytes", s.maxSecretBytes+32)
	}

	nonce, err := base64.RawURLEncoding.DecodeString(request.Nonce)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("nonce must be base64url: %w", err)
	}
	if len(nonce) != 12 {
		return nil, nil, nil, fmt.Errorf("nonce must be 12 bytes, got %d", len(nonce))
	}

	consumeVerifier, err := base64.RawURLEncoding.DecodeString(request.ConsumeVerifier)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("consumeVerifier must be base64url: %w", err)
	}
	if len(consumeVerifier) != 32 {
		return nil, nil, nil, fmt.Errorf("consumeVerifier must be 32 bytes, got %d", len(consumeVerifier))
	}

	return ciphertext, nonce, consumeVerifier, nil
}

func (s *server) handleConsumeSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !tokenPattern.MatchString(id) {
		writeError(w, http.StatusNotFound, "secret not found", s.logger)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("close consume request body", "error", err)
		}
	}()

	var request consumeSecretRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err), s.logger)
		return
	}

	consumeVerifier, err := base64.RawURLEncoding.DecodeString(request.ConsumeVerifier)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("consumeVerifier must be base64url: %v", err), s.logger)
		return
	}
	if len(consumeVerifier) != 32 {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("consumeVerifier must be 32 bytes, got %d", len(consumeVerifier)), s.logger)
		return
	}

	secret, err := s.store.Consume(r.Context(), id, consumeVerifier, time.Now())
	if err != nil {
		switch {
		case errors.Is(err, errSecretUnavailable):
			writeError(w, http.StatusGone, err.Error(), s.logger)
		case errors.Is(err, errSecretExpired):
			writeError(w, http.StatusGone, err.Error(), s.logger)
		case errors.Is(err, errSecretUnauthorized):
			writeError(w, http.StatusForbidden, err.Error(), s.logger)
		default:
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("consume secret: %v", err), s.logger)
		}
		return
	}

	writeJSON(w, http.StatusOK, consumeSecretResponse{
		Ciphertext: base64.RawURLEncoding.EncodeToString(secret.Ciphertext),
		Nonce:      base64.RawURLEncoding.EncodeToString(secret.Nonce),
	}, s.logger)
}

func (s *server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'none'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), clipboard-write=(self)")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (s *server) origin(r *http.Request) string {
	if s.publicOrigin != "" {
		return s.publicOrigin
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func writeJSON(w http.ResponseWriter, status int, payload any, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logger.Error("write json response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string, logger *slog.Logger) {
	writeJSON(w, status, errorResponse{Error: message}, logger)
}
