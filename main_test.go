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
	"os"
	"path/filepath"
	"strings"
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

func TestStoreConsumeRemovesCiphertextFromDatabaseFiles(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "paper-wal.db")
	store, err := openStore(ctx, path, defaultMaxStoredBytes, defaultMaxStoredItems)
	r.NoError(err)
	t.Cleanup(func() {
		r.NoError(store.Close())
	})

	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	id := "walciphertextmarker0000"
	ciphertext := []byte("PAPER_UNIQUE_CIPHERTEXT_MARKER_4f19b8")
	consumeVerifier := bytes.Repeat([]byte{1}, 32)
	_, err = store.Create(ctx, id, ciphertext, []byte("123456789012"), consumeVerifier, now, time.Hour)
	r.NoError(err)

	databaseFiles, err := filepath.Glob(path + "*")
	r.NoError(err)
	foundCiphertext := false
	for _, databaseFile := range databaseFiles {
		contents, err := os.ReadFile(databaseFile)
		r.NoError(err)
		foundCiphertext = foundCiphertext || bytes.Contains(contents, ciphertext)
	}
	r.True(foundCiphertext)

	_, err = store.Consume(ctx, id, consumeVerifier, now)
	r.NoError(err)
	databaseFiles, err = filepath.Glob(path + "*")
	r.NoError(err)
	for _, databaseFile := range databaseFiles {
		contents, err := os.ReadFile(databaseFile)
		r.NoError(err)
		r.NotContains(contents, ciphertext, databaseFile)
	}
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

func TestStoreEnforcesCapacity(t *testing.T) {
	tests := map[string]struct {
		maxStoredBytes int64
		maxStoredItems int
	}{
		"stored bytes": {
			maxStoredBytes: 3,
			maxStoredItems: 2,
		},
		"stored items": {
			maxStoredBytes: 100,
			maxStoredItems: 1,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			ctx := context.Background()
			store := newTestStoreWithLimits(t, tc.maxStoredBytes, tc.maxStoredItems)
			now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
			consumeVerifier := bytes.Repeat([]byte{1}, 32)

			_, err := store.Create(
				ctx,
				"capacityfirstnote00000",
				[]byte("abc"),
				[]byte("123456789012"),
				consumeVerifier,
				now,
				time.Hour,
			)
			r.NoError(err)

			_, err = store.Create(
				ctx,
				"capacitysecondnote0000",
				[]byte("d"),
				[]byte("123456789012"),
				consumeVerifier,
				now,
				time.Hour,
			)
			r.ErrorIs(err, errStoreCapacity)

			_, err = store.Consume(ctx, "capacityfirstnote00000", consumeVerifier, now)
			r.NoError(err)
			_, err = store.Create(
				ctx,
				"capacitysecondnote0000",
				[]byte("d"),
				[]byte("123456789012"),
				consumeVerifier,
				now,
				time.Hour,
			)
			r.NoError(err)
		})
	}
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

func TestHealthEndpoint(t *testing.T) {
	r := require.New(t)
	app := newTestServer(t)

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)

	r.Equal(http.StatusOK, response.Code)
	r.Equal("text/plain; charset=utf-8", response.Header().Get("Content-Type"))
	r.Equal("ok\n", response.Body.String())
}

func TestSecretPageValidatesID(t *testing.T) {
	r := require.New(t)
	app := newTestServer(t)

	validRequest := httptest.NewRequest(http.MethodGet, "/s/aaaaaaaaaaaaaaaaaaaaaa", nil)
	validResponse := httptest.NewRecorder()
	app.ServeHTTP(validResponse, validRequest)
	r.Equal(http.StatusOK, validResponse.Code)
	r.Contains(validResponse.Body.String(), `<section class="panel reveal-panel" id="reveal-view"`)

	invalidRequest := httptest.NewRequest(http.MethodGet, "/s/not-valid!", nil)
	invalidResponse := httptest.NewRecorder()
	app.ServeHTTP(invalidResponse, invalidRequest)
	r.Equal(http.StatusNotFound, invalidResponse.Code)
}

func TestSecurityHeadersAndAssetCaching(t *testing.T) {
	r := require.New(t)
	app := newTestServer(t)

	indexRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	indexResponse := httptest.NewRecorder()
	app.ServeHTTP(indexResponse, indexRequest)
	r.Equal(http.StatusOK, indexResponse.Code)
	r.Equal("no-store", indexResponse.Header().Get("Cache-Control"))
	r.Equal("no-referrer", indexResponse.Header().Get("Referrer-Policy"))
	r.Equal("nosniff", indexResponse.Header().Get("X-Content-Type-Options"))
	r.Equal("same-origin", indexResponse.Header().Get("Cross-Origin-Opener-Policy"))
	r.Contains(indexResponse.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")

	assetRequest := httptest.NewRequest(http.MethodGet, "/assets/style.css", nil)
	assetResponse := httptest.NewRecorder()
	app.ServeHTTP(assetResponse, assetRequest)
	r.Equal(http.StatusOK, assetResponse.Code)
	r.Equal("public, max-age=3600", assetResponse.Header().Get("Cache-Control"))
	r.Contains(assetResponse.Body.String(), ":root")
}

func TestCreateHandlerRejectsDuplicateID(t *testing.T) {
	r := require.New(t)
	app := newTestServer(t)

	id := "mmmmmmmmmmmmmmmmmmmmmm"
	ciphertext := base64.RawURLEncoding.EncodeToString([]byte("encrypted first payload"))
	nonce := base64.RawURLEncoding.EncodeToString([]byte("123456789012"))
	consumeVerifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32))
	body := `{"id":"` + id + `","ciphertext":"` + ciphertext + `","nonce":"` + nonce + `","consumeVerifier":"` + consumeVerifier + `"}`

	firstRequest := httptest.NewRequest(http.MethodPost, "/api/secrets", bytes.NewBufferString(body))
	firstResponse := httptest.NewRecorder()
	app.ServeHTTP(firstResponse, firstRequest)
	r.Equal(http.StatusCreated, firstResponse.Code)

	secondRequest := httptest.NewRequest(http.MethodPost, "/api/secrets", bytes.NewBufferString(body))
	secondResponse := httptest.NewRecorder()
	app.ServeHTTP(secondResponse, secondRequest)
	r.Equal(http.StatusConflict, secondResponse.Code)
	r.Contains(secondResponse.Body.String(), "secret id already exists")
}

func TestCreateHandlerRateLimitsRequests(t *testing.T) {
	r := require.New(t)
	store := newTestStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := newServer(store, logger, "", time.Hour, defaultMaxSecretBytes, 1)
	r.NoError(err)
	app := server.routes()
	consumeVerifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{14}, 32))

	firstBody := bytes.NewBufferString(`{"id":"ratelimitfirstnote0000","ciphertext":"YWJj","nonce":"MTIzNDU2Nzg5MDEy","consumeVerifier":"` + consumeVerifier + `"}`)
	firstRequest := httptest.NewRequest(http.MethodPost, "/api/secrets", firstBody)
	firstResponse := httptest.NewRecorder()
	app.ServeHTTP(firstResponse, firstRequest)
	r.Equal(http.StatusCreated, firstResponse.Code)

	secondBody := bytes.NewBufferString(`{"id":"ratelimitsecondnote000","ciphertext":"YWJj","nonce":"MTIzNDU2Nzg5MDEy","consumeVerifier":"` + consumeVerifier + `"}`)
	secondRequest := httptest.NewRequest(http.MethodPost, "/api/secrets", secondBody)
	secondResponse := httptest.NewRecorder()
	app.ServeHTTP(secondResponse, secondRequest)
	r.Equal(http.StatusTooManyRequests, secondResponse.Code)
	r.Equal("60", secondResponse.Header().Get("Retry-After"))
}

func TestCreateHandlerRejectsRequestsAtStorageCapacity(t *testing.T) {
	r := require.New(t)
	store := newTestStoreWithLimits(t, 2, defaultMaxStoredItems)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := newServer(store, logger, "", time.Hour, defaultMaxSecretBytes, defaultCreateRate)
	r.NoError(err)
	app := server.routes()
	consumeVerifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{15}, 32))
	body := bytes.NewBufferString(`{"id":"storagecapacitynote000","ciphertext":"YWJj","nonce":"MTIzNDU2Nzg5MDEy","consumeVerifier":"` + consumeVerifier + `"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/secrets", body)
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)

	r.Equal(http.StatusInsufficientStorage, response.Code)
	r.Contains(response.Body.String(), errStoreCapacity.Error())
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

func TestCreateHandlerRejectsUnknownField(t *testing.T) {
	r := require.New(t)
	app := newTestServer(t)

	body := bytes.NewBufferString(`{"id":"nnnnnnnnnnnnnnnnnnnnnn","ciphertext":"YWJj","nonce":"MTIzNDU2Nzg5MDEy","consumeVerifier":"` + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{12}, 32)) + `","extra":true}`)
	request := httptest.NewRequest(http.MethodPost, "/api/secrets", body)
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)

	r.Equal(http.StatusBadRequest, response.Code)
	r.Contains(response.Body.String(), "unknown field")
}

func TestCreateHandlerRejectsOversizedCiphertext(t *testing.T) {
	r := require.New(t)
	store := newTestStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := newServer(store, logger, "", time.Hour, 3, defaultCreateRate)
	r.NoError(err)
	app := server.routes()

	body := bytes.NewBufferString(`{"id":"oooooooooooooooooooooo","ciphertext":"` + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte("x"), 36)) + `","nonce":"MTIzNDU2Nzg5MDEy","consumeVerifier":"` + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{13}, 32)) + `"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/secrets", body)
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)

	r.Equal(http.StatusBadRequest, response.Code)
	r.Contains(response.Body.String(), "ciphertext exceeds 35 bytes")
}

func TestIndexInjectsMaxBytesAndVersion(t *testing.T) {
	r := require.New(t)
	originalVersion := version
	version = "abc123"
	t.Cleanup(func() {
		version = originalVersion
	})

	store := newTestStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := newServer(store, logger, "", time.Hour, 12345, defaultCreateRate)
	r.NoError(err)

	r.Contains(string(srv.index), `<meta name="paper-max-bytes" content="12345">`)
	r.Contains(string(srv.index), `<meta name="paper-version" content="abc123">`)
	r.Contains(string(srv.index), `version abc123`)
	r.Contains(string(srv.index), "one reveal attempt")
	r.Contains(string(srv.index), "network failure can burn an unread note")
	r.NotContains(string(srv.index), "__PAPER_MAX_BYTES__")
	r.NotContains(string(srv.index), "__PAPER_VERSION__")
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

func TestLoadConfigParsesTTLAndMaxBytes(t *testing.T) {
	r := require.New(t)
	t.Setenv("PAPER_ADDR", "")
	t.Setenv("PAPER_DB", "")
	t.Setenv("PAPER_PUBLIC_ORIGIN", "")
	t.Setenv("PAPER_SECRET_TTL_HOURS", "12")
	t.Setenv("PAPER_MAX_SECRET_BYTES", "2048")
	t.Setenv("PAPER_MAX_STORED_BYTES", "1048576")
	t.Setenv("PAPER_MAX_STORED_SECRETS", "250")
	t.Setenv("PAPER_CREATE_RATE_PER_MINUTE", "12")
	t.Setenv("PAPER_CLEANUP_INTERVAL_MINUTES", "")

	cfg, err := loadConfig()
	r.NoError(err)
	r.Equal(12*time.Hour, cfg.secretTTL)
	r.Equal(2048, cfg.maxSecretBytes)
	r.Equal(int64(1048576), cfg.maxStoredBytes)
	r.Equal(250, cfg.maxStoredItems)
	r.Equal(12, cfg.createRate)
}

func TestLoadConfigRejectsNonPositiveNumericValues(t *testing.T) {
	t.Run("ttl", func(t *testing.T) {
		r := require.New(t)
		t.Setenv("PAPER_SECRET_TTL_HOURS", "0")

		_, err := loadConfig()
		r.Error(err)
		r.Contains(err.Error(), "PAPER_SECRET_TTL_HOURS must be positive")
	})

	t.Run("cleanup interval", func(t *testing.T) {
		r := require.New(t)
		t.Setenv("PAPER_CLEANUP_INTERVAL_MINUTES", "-1")

		_, err := loadConfig()
		r.Error(err)
		r.Contains(err.Error(), "PAPER_CLEANUP_INTERVAL_MINUTES must be positive")
	})

	t.Run("max bytes", func(t *testing.T) {
		r := require.New(t)
		t.Setenv("PAPER_MAX_SECRET_BYTES", "0")

		_, err := loadConfig()
		r.Error(err)
		r.Contains(err.Error(), "PAPER_MAX_SECRET_BYTES must be positive")
	})

	t.Run("max stored bytes", func(t *testing.T) {
		r := require.New(t)
		t.Setenv("PAPER_MAX_STORED_BYTES", "0")

		_, err := loadConfig()
		r.Error(err)
		r.Contains(err.Error(), "PAPER_MAX_STORED_BYTES must be positive")
	})

	t.Run("max stored secrets", func(t *testing.T) {
		r := require.New(t)
		t.Setenv("PAPER_MAX_STORED_SECRETS", "0")

		_, err := loadConfig()
		r.Error(err)
		r.Contains(err.Error(), "PAPER_MAX_STORED_SECRETS must be positive")
	})

	t.Run("create rate", func(t *testing.T) {
		r := require.New(t)
		t.Setenv("PAPER_CREATE_RATE_PER_MINUTE", "0")

		_, err := loadConfig()
		r.Error(err)
		r.Contains(err.Error(), "PAPER_CREATE_RATE_PER_MINUTE must be positive")
	})
}

func TestLoadConfigRejectsOverflowingDurations(t *testing.T) {
	tests := map[string]struct {
		key   string
		value string
		want  string
	}{
		"ttl": {
			key:   "PAPER_SECRET_TTL_HOURS",
			value: "2562048",
			want:  "PAPER_SECRET_TTL_HOURS is too large",
		},
		"cleanup interval": {
			key:   "PAPER_CLEANUP_INTERVAL_MINUTES",
			value: "153722868",
			want:  "PAPER_CLEANUP_INTERVAL_MINUTES is too large",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			t.Setenv(tc.key, tc.value)

			_, err := loadConfig()
			r.Error(err)
			r.Contains(err.Error(), tc.want)
		})
	}
}

func TestDeploymentArtifactsMatchExpectedServiceBehavior(t *testing.T) {
	r := require.New(t)

	serviceBytes, err := os.ReadFile(filepath.Join("deploy", "paper.service"))
	r.NoError(err)
	service := string(serviceBytes)
	for _, expected := range []string{
		"[Unit]",
		"Description=Paper one-time secret sharing service",
		"After=network-online.target",
		"Wants=network-online.target",
		"[Service]",
		"Type=simple",
		"User=paper",
		"Group=paper",
		"WorkingDirectory=/var/lib/paper",
		"ExecStart=/usr/local/bin/paper",
		"Restart=on-failure",
		"Environment=PAPER_ADDR=127.0.0.1:8080",
		"Environment=PAPER_DB=/var/lib/paper/paper.db",
		"Environment=PAPER_SECRET_TTL_HOURS=168",
		"Environment=PAPER_CLEANUP_INTERVAL_MINUTES=60",
		"Environment=PAPER_MAX_SECRET_BYTES=65536",
		"Environment=PAPER_MAX_STORED_BYTES=1073741824",
		"Environment=PAPER_MAX_STORED_SECRETS=10000",
		"Environment=PAPER_CREATE_RATE_PER_MINUTE=60",
		"NoNewPrivileges=true",
		"PrivateTmp=true",
		"ProtectHome=true",
		"ProtectSystem=strict",
		"ReadWritePaths=/var/lib/paper",
		"[Install]",
		"WantedBy=multi-user.target",
	} {
		r.Contains(service, expected)
	}

	installPath := filepath.Join("deploy", "install.sh")
	installInfo, err := os.Stat(installPath)
	r.NoError(err)
	r.NotZero(installInfo.Mode() & 0o111)

	installBytes, err := os.ReadFile(installPath)
	r.NoError(err)
	installScript := string(installBytes)
	for _, expected := range []string{
		"set -euo pipefail",
		`readonly SERVICE_NAME="paper"`,
		`readonly BINARY_NAME="paper"`,
		`readonly INSTALL_PATH="${INSTALL_DIR}/${BINARY_NAME}"`,
		"CGO_ENABLED=0 go build",
		`sudo_run install -m 0755 "${BUILD_DIR}/${BINARY_NAME}" "${INSTALL_PATH}"`,
		`sudo_run systemctl start "${SERVICE_NAME}.service"`,
		`sudo_run systemctl is-active --quiet "${SERVICE_NAME}.service"`,
		"trap cleanup EXIT",
	} {
		r.Contains(installScript, expected)
	}
	r.True(strings.HasPrefix(installScript, "#!/usr/bin/env bash\n"))
}

func TestOpenStoreMigratesLegacyDatabase(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "paper-legacy.db")
	legacyID := "legacygreendalenote000"
	ciphertext := []byte("encrypted Greendale bylaws")
	nonce := []byte("123456789012")
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)

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
	_, err = db.ExecContext(
		ctx,
		"INSERT INTO secrets (id, ciphertext, nonce, created_at_unix, expires_at_unix) VALUES (?, ?, ?, ?, ?)",
		legacyID,
		ciphertext,
		nonce,
		now.Unix(),
		now.Add(time.Hour).Unix(),
	)
	r.NoError(err)
	r.NoError(db.Close())

	store, err := openStore(ctx, path, defaultMaxStoredBytes, defaultMaxStoredItems)
	r.NoError(err)
	defer func() {
		r.NoError(store.Close())
	}()

	rows, err := store.db.QueryContext(ctx, "PRAGMA table_info(secrets)")
	r.NoError(err)

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
	r.NoError(rows.Close())

	secret, err := store.Consume(ctx, legacyID, bytes.Repeat([]byte{1}, 32), now)
	r.NoError(err)
	r.Equal(ciphertext, secret.Ciphertext)
	r.Equal(nonce, secret.Nonce)
}

func newTestStore(t *testing.T) *store {
	t.Helper()
	return newTestStoreWithLimits(t, defaultMaxStoredBytes, defaultMaxStoredItems)
}

func newTestStoreWithLimits(t *testing.T, maxStoredBytes int64, maxStoredItems int) *store {
	t.Helper()
	store, err := openStore(
		context.Background(),
		filepath.Join(t.TempDir(), "paper-test.db"),
		maxStoredBytes,
		maxStoredItems,
	)
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
	server, err := newServer(store, logger, publicOrigin, time.Hour, defaultMaxSecretBytes, defaultCreateRate)
	require.NoError(t, err)
	return server.routes()
}
