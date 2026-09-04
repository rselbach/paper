package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStoreReplacementConnectionSecurelyDeletesSecrets(t *testing.T) {
	for name, uri := range map[string]bool{"filename": false, "URI with options": true} {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "paper.db")
			dsn := path
			if uri {
				dsn = "file:" + path + "?mode=rwc"
			}
			s, err := openStore(ctx, dsn, defaultMaxStoredBytes, defaultMaxStoredItems)
			r.NoError(err)
			t.Cleanup(func() { r.NoError(s.Close()) })

			// Force replacement of the initial connection, as after cancellation.
			s.db.SetMaxIdleConns(0)
			s.db.SetMaxIdleConns(1)
			for pragma, want := range map[string]int{
				"secure_delete":      1,
				"foreign_keys":       1,
				"busy_timeout":       5000,
				"journal_size_limit": 0,
			} {
				var got int
				r.NoError(s.db.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got))
				r.Equal(want, got, pragma)
			}

			ciphertext := []byte("encrypted Greendale Community College marker")
			verifier := bytes.Repeat([]byte{8}, 32)
			now := time.Now()
			_, err = s.Create(ctx, "greendale-replacement", ciphertext, []byte("123456789012"), verifier, now, time.Hour)
			r.NoError(err)
			_, err = s.Consume(ctx, "greendale-replacement", verifier, now)
			r.NoError(err)
			files, err := filepath.Glob(path + "*")
			r.NoError(err)
			for _, file := range files {
				contents, err := os.ReadFile(file)
				r.NoError(err)
				r.NotContains(contents, ciphertext, file)
			}
		})
	}
}
