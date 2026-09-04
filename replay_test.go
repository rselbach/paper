package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCreateReplayCannotRestoreConsumedSecret(t *testing.T) {
	r := require.New(t)
	app := newTestServer(t)
	proof := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	id, body := testCreateRequestBody(t, "YWJj", "MTIzNDU2Nzg5MDEy", proof, bytes.Repeat([]byte{6}, 32))
	consumeBody := `{"consumeVerifier":"` + proof + `"}`
	steps := []struct {
		path string
		body string
		want int
	}{
		{"/api/secrets", body, http.StatusCreated},
		{"/api/secrets/" + id + "/consume", consumeBody, http.StatusOK},
		{"/api/secrets", body, http.StatusGone},
		{"/api/secrets/" + id + "/consume", consumeBody, http.StatusGone},
	}
	for _, step := range steps {
		response := httptest.NewRecorder()
		app.ServeHTTP(response, newJSONRequest(step.path, strings.NewReader(step.body)))
		r.Equal(step.want, response.Code, response.Body.String())
	}
}

func TestCreationTimeCommitment(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	proof := bytes.Repeat([]byte{6}, 32)
	s := &server{maxSecretBytes: defaultMaxSecretBytes}
	tests := map[string]struct {
		createdAt int64
		wantError string
	}{
		"current":         {now.Unix(), ""},
		"before deadline": {now.Add(-createRetryWindow + time.Second).Unix(), ""},
		"at deadline":     {now.Add(-createRetryWindow).Unix(), errCreateExpired.Error()},
		"past deadline":   {now.Add(-createRetryWindow - time.Second).Unix(), errCreateExpired.Error()},
		"allowed skew":    {now.Add(createClockSkew).Unix(), ""},
		"future":          {now.Add(createClockSkew + time.Second).Unix(), "creation time is in the future"},
		"extreme future":  {1<<63 - 1, "creation time is in the future"},
		"negative time":   {-1, "id must include its creation time"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			request := createSecretRequest{
				ID:              secretIDForCreateVerifier(proof, tc.createdAt),
				Ciphertext:      "YWJj",
				Nonce:           "MTIzNDU2Nzg5MDEy",
				CreateVerifier:  base64.RawURLEncoding.EncodeToString(proof),
				ConsumeVerifier: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)),
			}
			_, err := s.validateCreateRequest(request, now)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				return
			}
			require.NoError(t, err)
			_, suffix, ok := strings.Cut(request.ID, "_")
			require.True(t, ok)
			request.ID = strconv.FormatInt(tc.createdAt+1, 36) + "_" + suffix
			_, err = s.validateCreateRequest(request, now)
			require.ErrorContains(t, err, "id does not match createVerifier")
		})
	}
}

func TestCreateReceiptSurvivesRestartAndExpiresSafely(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "paper.db")
	s, err := openStore(ctx, path, defaultMaxStoredBytes, defaultMaxStoredItems)
	r.NoError(err)
	proof := bytes.Repeat([]byte{5}, 32)
	id, body := testCreateRequestBody(t, "YWJj", "MTIzNDU2Nzg5MDEy", base64.RawURLEncoding.EncodeToString(proof), bytes.Repeat([]byte{6}, 32))
	now := time.Now()
	_, err = s.Create(ctx, id, []byte("abc"), []byte("123456789012"), proof, now, time.Hour)
	r.NoError(err)
	_, err = s.Consume(ctx, id, proof, now)
	r.NoError(err)
	r.NoError(s.Close())

	s, err = openStore(ctx, path, defaultMaxStoredBytes, defaultMaxStoredItems)
	r.NoError(err)
	t.Cleanup(func() { r.NoError(s.Close()) })
	_, err = s.Create(ctx, id, []byte("abc"), []byte("123456789012"), proof, now, time.Hour)
	r.ErrorIs(err, errSecretUnavailable)
	r.Equal(0, secretCount(t, s, id))

	later := now.Add(createRetryWindow + createClockSkew)
	r.NoError(s.DeleteExpired(ctx, later))
	var receipts int
	r.NoError(s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM create_receipts").Scan(&receipts))
	r.Zero(receipts)
	var request createSecretRequest
	r.NoError(json.Unmarshal([]byte(body), &request))
	app := &server{maxSecretBytes: defaultMaxSecretBytes}
	_, err = app.validateCreateRequest(request, later)
	r.ErrorIs(err, errCreateExpired)
}

func TestCreateReceiptsHaveBoundedCapacity(t *testing.T) {
	r := require.New(t)
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now()
	_, err := s.db.ExecContext(ctx, `WITH RECURSIVE numbers(n) AS (
		SELECT 1 UNION ALL SELECT n + 1 FROM numbers WHERE n < ?
	) INSERT INTO create_receipts (id, expires_at_unix)
	SELECT 'Greendale-' || n, ? FROM numbers`, maxCreateReceipts, now.Add(time.Minute).Unix())
	r.NoError(err)
	proof := bytes.Repeat([]byte{5}, 32)
	_, err = s.Create(ctx, "Troy-Barnes", []byte("abc"), []byte("123456789012"), proof, now, time.Hour)
	r.ErrorIs(err, errStoreCapacity)
	r.Equal(0, secretCount(t, s, "Troy-Barnes"))
	_, err = s.Create(ctx, "Troy-Barnes", []byte("abc"), []byte("123456789012"), proof, now.Add(time.Minute), time.Hour)
	r.NoError(err)
	var receipts int
	r.NoError(s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM create_receipts").Scan(&receipts))
	r.Equal(1, receipts)
}
