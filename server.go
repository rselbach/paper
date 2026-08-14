package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	//go:embed static/index.html static/assets
	staticFiles embed.FS

	tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)
)

type server struct {
	store               *store
	logger              *slog.Logger
	index               []byte
	assets              fs.FS
	fingerprintedAssets map[string]fingerprintedAsset
	publicOrigin        string
	secretTTL           time.Duration
	maxSecretBytes      int
	createLimiter       *fixedWindowLimiter
	consumeLimiter      *fixedWindowLimiter
}

type fingerprintedAsset struct {
	name    string
	content []byte
	urlPath string
}

type createSecretRequest struct {
	ID              string `json:"id"`
	Ciphertext      string `json:"ciphertext"`
	Nonce           string `json:"nonce"`
	CreateVerifier  string `json:"createVerifier"`
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

func newServer(store *store, logger *slog.Logger, publicOrigin string, secretTTL time.Duration, maxSecretBytes int, createRate int) (*server, error) {
	index, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		return nil, fmt.Errorf("read embedded index: %w", err)
	}

	assets, err := fs.Sub(staticFiles, "static/assets")
	if err != nil {
		return nil, fmt.Errorf("load embedded assets: %w", err)
	}
	style, err := loadFingerprintedAsset(assets, "style.css")
	if err != nil {
		return nil, err
	}
	app, err := loadFingerprintedAsset(assets, "app.js")
	if err != nil {
		return nil, err
	}

	index = bytes.ReplaceAll(index, []byte("__PAPER_MAX_BYTES__"), []byte(strconv.Itoa(maxSecretBytes)))
	index = bytes.ReplaceAll(index, []byte("__PAPER_VERSION__"), []byte(html.EscapeString(version)))
	index = bytes.ReplaceAll(index, []byte("__PAPER_SECRET_TTL_LABEL__"), []byte(html.EscapeString(formatSecretTTLLabel(secretTTL))))
	index = bytes.ReplaceAll(index, []byte("__PAPER_STYLE_URL__"), []byte(style.urlPath))
	index = bytes.ReplaceAll(index, []byte("__PAPER_APP_URL__"), []byte(app.urlPath))

	return &server{
		store:  store,
		logger: logger,
		index:  index,
		assets: assets,
		fingerprintedAssets: map[string]fingerprintedAsset{
			style.urlPath: style,
			app.urlPath:   app,
		},
		publicOrigin:   publicOrigin,
		secretTTL:      secretTTL,
		maxSecretBytes: maxSecretBytes,
		createLimiter: &fixedWindowLimiter{
			limit:      createRate,
			window:     time.Minute,
			maxClients: maxRateLimitClients,
		},
		// Reveals are far rarer than creates, so the create budget is a
		// generous ceiling that still meters id probing.
		consumeLimiter: &fixedWindowLimiter{
			limit:      createRate,
			window:     time.Minute,
			maxClients: maxRateLimitClients,
		},
	}, nil
}

func loadFingerprintedAsset(assets fs.FS, name string) (fingerprintedAsset, error) {
	content, err := fs.ReadFile(assets, name)
	if err != nil {
		return fingerprintedAsset{}, fmt.Errorf("read embedded asset %q: %w", name, err)
	}

	extension := path.Ext(name)
	base := strings.TrimSuffix(name, extension)
	sum := sha256.Sum256(content)
	fingerprint := hex.EncodeToString(sum[:6])

	return fingerprintedAsset{
		name:    name,
		content: content,
		urlPath: "/assets/" + base + "." + fingerprint + extension,
	}, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	for urlPath := range s.fingerprintedAssets {
		mux.HandleFunc("GET "+urlPath, s.handleFingerprintedAsset)
	}
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(s.assets))))
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /s/{id}", s.handleSecretPage)
	mux.HandleFunc("POST /api/secrets", s.handleCreateSecret)
	mux.HandleFunc("POST /api/secrets/{id}/consume", s.handleConsumeSecret)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return s.securityHeaders(mux)
}

func (s *server) handleFingerprintedAsset(w http.ResponseWriter, r *http.Request) {
	asset, ok := s.fingerprintedAssets[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	http.ServeContent(w, r, asset.name, time.Time{}, bytes.NewReader(asset.content))
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
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json", s.logger)
		return
	}

	if !s.createLimiter.Allow(clientKey(r), time.Now()) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "secret creation rate limit exceeded", s.logger)
		return
	}

	maxBodyBytes := base64.RawURLEncoding.EncodedLen(s.maxSecretBytes+32) + 4096
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBodyBytes))
	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("close create request body", "error", err)
		}
	}()

	var request createSecretRequest
	if err := decodeJSON(r.Body, &request); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode request: %v", err), s.logger)
		return
	}

	ciphertext, nonce, consumeVerifier, err := s.validateCreateRequest(request)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), s.logger)
		return
	}

	now := time.Now()
	expiresAt, err := s.store.Create(r.Context(), request.ID, ciphertext, nonce, consumeVerifier, now, s.secretTTL)
	switch {
	case err == nil:
	case errors.Is(err, errSecretExists):
		// Never replace the committed note or expose its stored metadata when a
		// non-identical request reuses its id.
		expiresAt = now.UTC().Add(s.secretTTL).Truncate(time.Second)
	case errors.Is(err, errStoreCapacity):
		writeError(w, http.StatusInsufficientStorage, err.Error(), s.logger)
		return
	default:
		s.logger.Error("store secret", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error", s.logger)
		return
	}

	path := "/s/" + request.ID
	writeJSON(w, http.StatusCreated, createSecretResponse{
		URL:       s.shareURL(path),
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

	createVerifier, err := base64.RawURLEncoding.DecodeString(request.CreateVerifier)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("createVerifier must be base64url: %w", err)
	}
	if len(createVerifier) != 32 {
		return nil, nil, nil, fmt.Errorf("createVerifier must be 32 bytes, got %d", len(createVerifier))
	}
	if request.ID != secretIDForCreateVerifier(createVerifier) {
		return nil, nil, nil, errors.New("id does not match createVerifier")
	}

	return ciphertext, nonce, consumeVerifier, nil
}

func secretIDForCreateVerifier(createVerifier []byte) string {
	const context = "paper id v1\x00"
	input := make([]byte, len(context)+len(createVerifier))
	copy(input, context)
	copy(input[len(context):], createVerifier)
	sum := sha256.Sum256(input)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func (s *server) handleConsumeSecret(w http.ResponseWriter, r *http.Request) {
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json", s.logger)
		return
	}

	if !s.consumeLimiter.Allow(clientKey(r), time.Now()) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "secret reveal rate limit exceeded", s.logger)
		return
	}

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
	if err := decodeJSON(r.Body, &request); err != nil {
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
	if err != nil && secret != nil {
		s.logger.Error("truncate sqlite WAL after consume", "error", err)
	}
	if err != nil && secret == nil {
		switch {
		case errors.Is(err, errSecretUnavailable),
			errors.Is(err, errSecretExpired),
			errors.Is(err, errSecretUnauthorized):
			// Same status and body for missing, expired, and wrong proof so
			// path-only observers cannot probe whether a note is still live.
			writeError(w, http.StatusGone, errSecretUnavailable.Error(), s.logger)
		default:
			s.logger.Error("consume secret", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error", s.logger)
		}
		return
	}

	writeJSON(w, http.StatusOK, consumeSecretResponse{
		Ciphertext: base64.RawURLEncoding.EncodeToString(secret.Ciphertext),
		Nonce:      base64.RawURLEncoding.EncodeToString(secret.Nonce),
	}, s.logger)
}

func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func decodeJSON(body io.Reader, destination any) error {
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain one JSON value")
		}
		return fmt.Errorf("read trailing request data: %w", err)
	}
	return nil
}

func (s *server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=3600")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'none'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), clipboard-write=(self)")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// shareURL returns an absolute URL only from the configured public origin.
// When that origin is unset, it returns the path alone so request Host
// headers cannot mint attacker-controlled share links.
func (s *server) shareURL(path string) string {
	if s.publicOrigin == "" {
		return path
	}
	return s.publicOrigin + path
}

func formatSecretTTLLabel(ttl time.Duration) string {
	hours := int(ttl / time.Hour)
	if hours <= 0 {
		return "a short time"
	}
	if hours%24 == 0 {
		days := hours / 24
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	if hours == 1 {
		return "1 hour"
	}
	return fmt.Sprintf("%d hours", hours)
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
