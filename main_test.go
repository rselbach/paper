package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStoreConsumeDeletesSecret(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	store := newTestStore(t)

	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	id := "aaaaaaaaaaaaaaaaaaaaaa"
	ciphertext := []byte("encrypted Greendale map")
	nonce := []byte("123456789012")
	consumeVerifier := bytes.Repeat([]byte{1}, 32)

	expiresAt, err := store.Create(ctx, id, ciphertext, nonce, consumeVerifier, now, time.Hour)
	r.NoError(err)
	r.Equal(now.Add(time.Hour), expiresAt)

	secret, err := store.Consume(ctx, id, consumeVerifier, now.Add(time.Minute))
	r.NoError(err)
	r.Equal(ciphertext, secret.Ciphertext)
	r.Equal(nonce, secret.Nonce)

	secret, err = store.Consume(ctx, id, consumeVerifier, now.Add(2*time.Minute))
	r.Nil(secret)
	r.ErrorIs(err, errSecretUnavailable)
}

func TestStoreConsumeRejectsWrongVerifierWithoutDeletingSecret(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	store := newTestStore(t)

	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	id := "eeeeeeeeeeeeeeeeeeeeee"
	ciphertext := []byte("encrypted Shirley")
	nonce := []byte("123456789012")
	consumeVerifier := bytes.Repeat([]byte{2}, 32)
	wrongVerifier := bytes.Repeat([]byte{3}, 32)

	_, err := store.Create(ctx, id, ciphertext, nonce, consumeVerifier, now, time.Hour)
	r.NoError(err)

	secret, err := store.Consume(ctx, id, wrongVerifier, now.Add(time.Minute))
	r.Nil(secret)
	r.ErrorIs(err, errSecretUnauthorized)

	secret, err = store.Consume(ctx, id, consumeVerifier, now.Add(2*time.Minute))
	r.NoError(err)
	r.Equal(ciphertext, secret.Ciphertext)
	r.Equal(nonce, secret.Nonce)
}

func TestStoreConsumeExpiredSecretDeletesIt(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	store := newTestStore(t)

	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	id := "bbbbbbbbbbbbbbbbbbbbbb"
	consumeVerifier := bytes.Repeat([]byte{4}, 32)
	_, err := store.Create(ctx, id, []byte("encrypted Troy"), []byte("123456789012"), consumeVerifier, now, time.Hour)
	r.NoError(err)

	secret, err := store.Consume(ctx, id, consumeVerifier, now.Add(2*time.Hour))
	r.Nil(secret)
	r.ErrorIs(err, errSecretExpired)

	secret, err = store.Consume(ctx, id, consumeVerifier, now.Add(2*time.Hour))
	r.Nil(secret)
	r.ErrorIs(err, errSecretUnavailable)
}

func TestExpiredSecretCleanerDeletesExpiredSecrets(t *testing.T) {
	r := require.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newTestStore(t)

	now := time.Now().UTC()
	expiredID := "kkkkkkkkkkkkkkkkkkkkkk"
	activeID := "llllllllllllllllllllll"
	consumeVerifier := bytes.Repeat([]byte{10}, 32)

	_, err := store.Create(ctx, expiredID, []byte("expired ciphertext"), []byte("123456789012"), consumeVerifier, now.Add(-2*time.Hour), time.Hour)
	r.NoError(err)
	_, err = store.Create(ctx, activeID, []byte("active ciphertext"), []byte("123456789012"), consumeVerifier, now, time.Hour)
	r.NoError(err)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	startExpiredSecretCleaner(ctx, store, logger, 5*time.Millisecond)

	require.Eventually(t, func() bool {
		return secretCount(t, store, expiredID) == 0
	}, time.Second, 10*time.Millisecond)
	r.Equal(1, secretCount(t, store, activeID))
}

func TestCreateAndConsumeHandlers(t *testing.T) {
	r := require.New(t)
	app := newTestServer(t)

	id := "cccccccccccccccccccccc"
	ciphertext := base64.RawURLEncoding.EncodeToString([]byte("encrypted Human Being mascot"))
	nonce := base64.RawURLEncoding.EncodeToString([]byte("123456789012"))
	consumeVerifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	body := bytes.NewBufferString(`{"id":"` + id + `","ciphertext":"` + ciphertext + `","nonce":"` + nonce + `","consumeVerifier":"` + consumeVerifier + `"}`)

	request := httptest.NewRequest(http.MethodPost, "/api/secrets", body)
	request.Header.Set("Content-Type", "application/json")
	request.Host = "paper.test"
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)

	r.Equal(http.StatusCreated, response.Code)
	r.Equal("no-store", response.Header().Get("Cache-Control"))
	r.Contains(response.Header().Get("Content-Security-Policy"), "default-src 'self'")

	var created createSecretResponse
	r.NoError(json.Unmarshal(response.Body.Bytes(), &created))
	r.Equal("http://paper.test/s/"+id, created.URL)
	r.Equal("/s/"+id, created.Path)

	consumeBody := bytes.NewBufferString(`{"consumeVerifier":"` + consumeVerifier + `"}`)
	consumeRequest := httptest.NewRequest(http.MethodPost, "/api/secrets/"+id+"/consume", consumeBody)
	consumeResponse := httptest.NewRecorder()
	app.ServeHTTP(consumeResponse, consumeRequest)

	r.Equal(http.StatusOK, consumeResponse.Code)
	var consumed consumeSecretResponse
	r.NoError(json.Unmarshal(consumeResponse.Body.Bytes(), &consumed))
	r.Equal(ciphertext, consumed.Ciphertext)
	r.Equal(nonce, consumed.Nonce)

	secondRequest := httptest.NewRequest(http.MethodPost, "/api/secrets/"+id+"/consume", bytes.NewBufferString(`{"consumeVerifier":"`+consumeVerifier+`"}`))
	secondResponse := httptest.NewRecorder()
	app.ServeHTTP(secondResponse, secondRequest)
	r.Equal(http.StatusGone, secondResponse.Code)
}

func TestCreateHandlerUsesConfiguredPublicOrigin(t *testing.T) {
	r := require.New(t)
	app := newTestServerWithOrigin(t, "https://paper.example")

	id := "iiiiiiiiiiiiiiiiiiiiii"
	ciphertext := base64.RawURLEncoding.EncodeToString([]byte("encrypted Pierce"))
	nonce := base64.RawURLEncoding.EncodeToString([]byte("123456789012"))
	consumeVerifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	body := bytes.NewBufferString(`{"id":"` + id + `","ciphertext":"` + ciphertext + `","nonce":"` + nonce + `","consumeVerifier":"` + consumeVerifier + `"}`)

	request := httptest.NewRequest(http.MethodPost, "/api/secrets", body)
	request.Host = "attacker.example"
	request.Header.Set("X-Forwarded-Proto", "http")
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)

	r.Equal(http.StatusCreated, response.Code)

	var created createSecretResponse
	r.NoError(json.Unmarshal(response.Body.Bytes(), &created))
	r.Equal("https://paper.example/s/"+id, created.URL)
	r.Equal("/s/"+id, created.Path)
}

func TestConsumeHandlerRejectsWrongVerifierWithoutDeletingSecret(t *testing.T) {
	r := require.New(t)
	app := newTestServer(t)

	id := "ffffffffffffffffffffff"
	ciphertext := base64.RawURLEncoding.EncodeToString([]byte("encrypted Annie"))
	nonce := base64.RawURLEncoding.EncodeToString([]byte("123456789012"))
	consumeVerifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{6}, 32))
	wrongVerifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	createBody := bytes.NewBufferString(`{"id":"` + id + `","ciphertext":"` + ciphertext + `","nonce":"` + nonce + `","consumeVerifier":"` + consumeVerifier + `"}`)

	createRequest := httptest.NewRequest(http.MethodPost, "/api/secrets", createBody)
	createResponse := httptest.NewRecorder()
	app.ServeHTTP(createResponse, createRequest)
	r.Equal(http.StatusCreated, createResponse.Code)

	wrongRequest := httptest.NewRequest(http.MethodPost, "/api/secrets/"+id+"/consume", bytes.NewBufferString(`{"consumeVerifier":"`+wrongVerifier+`"}`))
	wrongResponse := httptest.NewRecorder()
	app.ServeHTTP(wrongResponse, wrongRequest)
	r.Equal(http.StatusForbidden, wrongResponse.Code)

	rightRequest := httptest.NewRequest(http.MethodPost, "/api/secrets/"+id+"/consume", bytes.NewBufferString(`{"consumeVerifier":"`+consumeVerifier+`"}`))
	rightResponse := httptest.NewRecorder()
	app.ServeHTTP(rightResponse, rightRequest)
	r.Equal(http.StatusOK, rightResponse.Code)
}

func TestConsumeHandlerRequiresVerifier(t *testing.T) {
	r := require.New(t)
	app := newTestServer(t)

	request := httptest.NewRequest(http.MethodPost, "/api/secrets/gggggggggggggggggggggg/consume", nil)
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)

	r.Equal(http.StatusBadRequest, response.Code)
	r.Contains(response.Body.String(), "decode request")
}

func TestCreateHandlerRejectsBadNonce(t *testing.T) {
	r := require.New(t)
	app := newTestServer(t)

	consumeVerifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
	body := bytes.NewBufferString(`{"id":"dddddddddddddddddddddd","ciphertext":"YWJj","nonce":"c2hvcnQ","consumeVerifier":"` + consumeVerifier + `"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/secrets", body)
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)

	r.Equal(http.StatusBadRequest, response.Code)
	r.Contains(response.Body.String(), "nonce must be 12 bytes")
}

func TestCreateHandlerRejectsBadConsumeVerifier(t *testing.T) {
	r := require.New(t)
	app := newTestServer(t)

	body := bytes.NewBufferString(`{"id":"hhhhhhhhhhhhhhhhhhhhhh","ciphertext":"YWJj","nonce":"MTIzNDU2Nzg5MDEy","consumeVerifier":"c2hvcnQ"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/secrets", body)
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)

	r.Equal(http.StatusBadRequest, response.Code)
	r.Contains(response.Body.String(), "consumeVerifier must be 32 bytes")
}

func TestIndexInjectsMaxBytesMeta(t *testing.T) {
	r := require.New(t)
	store := newTestStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := newServer(store, logger, "", time.Hour, 12345)
	r.NoError(err)

	r.Contains(string(srv.index), `<meta name="paper-max-bytes" content="12345">`)
	r.NotContains(string(srv.index), "__PAPER_MAX_BYTES__")
}

func TestNormalizePublicOrigin(t *testing.T) {
	r := require.New(t)

	origin, err := normalizePublicOrigin("https://paper.example/")
	r.NoError(err)
	r.Equal("https://paper.example", origin)

	origin, err = normalizePublicOrigin("http://localhost:8081")
	r.NoError(err)
	r.Equal("http://localhost:8081", origin)

	_, err = normalizePublicOrigin("paper.example")
	r.Error(err)

	_, err = normalizePublicOrigin("https://paper.example/app")
	r.Error(err)

	_, err = normalizePublicOrigin("https://paper.example?x=1")
	r.Error(err)
}

func TestLoadConfigParsesCleanupInterval(t *testing.T) {
	r := require.New(t)
	t.Setenv("PAPER_ADDR", "")
	t.Setenv("PAPER_DB", "")
	t.Setenv("PAPER_PUBLIC_ORIGIN", "")
	t.Setenv("PAPER_SECRET_TTL_HOURS", "")
	t.Setenv("PAPER_MAX_SECRET_BYTES", "")
	t.Setenv("PAPER_CLEANUP_INTERVAL_MINUTES", "15")

	cfg, err := loadConfig()
	r.NoError(err)
	r.Equal(15*time.Minute, cfg.cleanupInterval)
}

func TestOpenStoreMigratesLegacyDatabase(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "paper-legacy.db")

	db, err := sql.Open("sqlite", path)
	r.NoError(err)
	_, err = db.ExecContext(ctx, `CREATE TABLE secrets (
		id TEXT PRIMARY KEY,
		ciphertext BLOB NOT NULL,
		nonce BLOB NOT NULL,
		created_at_unix INTEGER NOT NULL,
		expires_at_unix INTEGER NOT NULL
	) STRICT`)
	r.NoError(err)
	r.NoError(db.Close())

	store, err := openStore(ctx, path)
	r.NoError(err)
	defer func() {
		r.NoError(store.Close())
	}()

	rows, err := store.db.QueryContext(ctx, "PRAGMA table_info(secrets)")
	r.NoError(err)
	defer func() {
		r.NoError(rows.Close())
	}()

	hasConsumeVerifier := false
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull int
		var defaultValue any
		var primaryKey int
		r.NoError(rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey))
		if name == "consume_verifier" {
			hasConsumeVerifier = true
			r.Equal("BLOB", columnType)
		}
	}
	r.NoError(rows.Err())
	r.True(hasConsumeVerifier)
}

func newTestStore(t *testing.T) *store {
	t.Helper()
	store, err := openStore(context.Background(), filepath.Join(t.TempDir(), "paper-test.db"))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, store.Close())
	})
	return store
}

func secretCount(t *testing.T, store *store, id string) int {
	t.Helper()
	var count int
	require.NoError(t, store.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM secrets WHERE id = ?", id).Scan(&count))
	return count
}

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	return newTestServerWithOrigin(t, "")
}

func newTestServerWithOrigin(t *testing.T, publicOrigin string) http.Handler {
	t.Helper()
	store := newTestStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := newServer(store, logger, publicOrigin, time.Hour, defaultMaxSecretBytes)
	require.NoError(t, err)
	return server.routes()
}
