package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	errSecretExists       = errors.New("secret id already exists")
	errSecretUnavailable  = errors.New("secret is unavailable or already used")
	errSecretExpired      = errors.New("secret expired")
	errSecretUnauthorized = errors.New("invalid secret key proof")
	errStoreCapacity      = errors.New("secret storage capacity reached")
)

type store struct {
	db             *sql.DB
	maxStoredBytes int64
	maxStoredItems int
}

type storedSecret struct {
	Ciphertext      []byte
	Nonce           []byte
	ConsumeVerifier []byte
}

func openStore(ctx context.Context, path string, maxStoredBytes int64, maxStoredItems int) (*store, error) {
	// The driver applies these settings to every connection, including replacements.
	pragmas := url.Values{"_pragma": {
		"busy_timeout = 5000",
		"foreign_keys = ON",
		"secure_delete = ON",
		"journal_mode = WAL",
		"journal_size_limit = 0",
	}}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	db, err := sql.Open("sqlite", path+separator+pragmas.Encode())
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	store := &store{
		db:             db,
		maxStoredBytes: maxStoredBytes,
		maxStoredItems: maxStoredItems,
	}
	db.SetMaxOpenConns(1)
	if err := store.migrate(ctx); err != nil {
		closeErr := db.Close()
		if closeErr != nil {
			return nil, fmt.Errorf("%w; close sqlite after migration failure: %v", err, closeErr)
		}
		return nil, err
	}

	return store, nil
}

func (s *store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY
	) STRICT`); err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}

	var current int
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&current); err != nil {
		return fmt.Errorf("read schema_version: %w", err)
	}

	if current < 1 {
		if err := s.applyMigrationV1(ctx); err != nil {
			return fmt.Errorf("apply migration v1: %w", err)
		}
		if _, err := s.db.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (1)"); err != nil {
			return fmt.Errorf("record schema_version 1: %w", err)
		}
		current = 1
	}
	if current < 2 {
		if err := s.applyMigrationV2(ctx); err != nil {
			return fmt.Errorf("apply migration v2: %w", err)
		}
		if _, err := s.db.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (2)"); err != nil {
			return fmt.Errorf("record schema_version 2: %w", err)
		}
		current = 2
	}
	if current < 3 {
		if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS create_receipts (
			id TEXT PRIMARY KEY,
			expires_at_unix INTEGER NOT NULL
		) STRICT`); err != nil {
			return fmt.Errorf("create retry receipts: %w", err)
		}
		if _, err := s.db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS create_receipts_expiry_idx ON create_receipts(expires_at_unix)"); err != nil {
			return fmt.Errorf("index retry receipts: %w", err)
		}
		if _, err := s.db.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (3)"); err != nil {
			return fmt.Errorf("record schema_version 3: %w", err)
		}
	}
	return nil
}

func (s *store) applyMigrationV1(ctx context.Context) error {
	exists, err := s.tableExists(ctx, "secrets")
	if err != nil {
		return err
	}
	if !exists {
		if _, err := s.db.ExecContext(ctx, `CREATE TABLE secrets (
			id TEXT PRIMARY KEY,
			ciphertext BLOB NOT NULL,
			nonce BLOB NOT NULL,
			consume_verifier BLOB,
			created_at_unix INTEGER NOT NULL,
			expires_at_unix INTEGER NOT NULL
		) STRICT`); err != nil {
			return fmt.Errorf("create secrets: %w", err)
		}
	} else {
		hasVerifier, err := s.columnExists(ctx, "secrets", "consume_verifier")
		if err != nil {
			return err
		}
		if !hasVerifier {
			if _, err := s.db.ExecContext(ctx, "ALTER TABLE secrets ADD COLUMN consume_verifier BLOB"); err != nil {
				return fmt.Errorf("add consume_verifier column: %w", err)
			}
		}
	}
	if _, err := s.db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS secrets_expires_at_idx ON secrets(expires_at_unix)"); err != nil {
		return fmt.Errorf("create expires_at index: %w", err)
	}
	return nil
}

// applyMigrationV2 removes secrets that predate consume proofs. Those rows
// could be burned with only the path id; deleting them closes that hole.
func (s *store) applyMigrationV2(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM secrets
		WHERE consume_verifier IS NULL
		   OR length(consume_verifier) != 32
	`); err != nil {
		return fmt.Errorf("delete secrets without consume proofs: %w", err)
	}
	return nil
}

func (s *store) tableExists(ctx context.Context, name string) (bool, error) {
	var got string
	err := s.db.QueryRowContext(ctx, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query sqlite_master for %q: %w", name, err)
	}
	return true, nil
}

func (s *store) columnExists(ctx context.Context, table, column string) (exists bool, returnErr error) {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%q)", table))
	if err != nil {
		return false, fmt.Errorf("read table info for %q: %w", table, err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			if returnErr != nil {
				returnErr = fmt.Errorf("%w; close table info for %q: %v", returnErr, table, err)
				return
			}
			returnErr = fmt.Errorf("close table info for %q: %w", table, err)
		}
	}()

	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dflt any
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			return false, fmt.Errorf("scan table info for %q: %w", table, err)
		}
		if name == column {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate table info for %q: %w", table, err)
	}
	return false, nil
}

func (s *store) Close() error {
	return s.db.Close()
}

func (s *store) Ready(ctx context.Context) error {
	var exists bool
	if err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM secrets)").Scan(&exists); err != nil {
		return fmt.Errorf("query secrets: %w", err)
	}
	return nil
}

func (s *store) Create(ctx context.Context, id string, ciphertext []byte, nonce []byte, consumeVerifier []byte, now time.Time, ttl time.Duration) (time.Time, error) {
	expiresAt := now.UTC().Add(ttl).Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("begin create transaction: %w", err)
	}

	// Drop expired rows before measuring. Excluding them from the count
	// instead would let them sit on disk until the cleanup ticker ran, so the
	// budgets would bound live ciphertext but not the size of the database.
	if _, err := tx.ExecContext(
		ctx,
		"DELETE FROM secrets WHERE expires_at_unix <= ?",
		now.UTC().Unix(),
	); err != nil {
		return time.Time{}, rollbackWithError(tx, fmt.Errorf("delete expired secrets: %w", err))
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM create_receipts WHERE expires_at_unix <= ?", now.UTC().Unix()); err != nil {
		return time.Time{}, rollbackWithError(tx, fmt.Errorf("delete expired retry receipts: %w", err))
	}

	existingExpiry, exists, err := s.existingSecretExpiry(
		ctx,
		tx,
		id,
		ciphertext,
		nonce,
		consumeVerifier,
	)
	if err != nil {
		return time.Time{}, rollbackWithError(tx, err)
	}
	if exists {
		if err := tx.Commit(); err != nil {
			return time.Time{}, fmt.Errorf("commit retried secret: %w", err)
		}
		return existingExpiry, nil
	}

	var seen bool
	var receipts int
	if err := tx.QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM create_receipts WHERE id = ?),
		(SELECT COUNT(*) FROM create_receipts)`, id).Scan(&seen, &receipts); err != nil {
		return time.Time{}, rollbackWithError(tx, fmt.Errorf("read retry receipts: %w", err))
	}
	if seen {
		return time.Time{}, rollbackWithError(tx, errSecretUnavailable)
	}
	if receipts >= maxCreateReceipts {
		return time.Time{}, rollbackWithError(tx, errStoreCapacity)
	}

	var storedBytes int64
	var storedItems int
	if err := tx.QueryRowContext(
		ctx,
		"SELECT COALESCE(SUM(length(ciphertext)), 0), COUNT(*) FROM secrets",
	).Scan(&storedBytes, &storedItems); err != nil {
		return time.Time{}, rollbackWithError(tx, fmt.Errorf("read secret storage usage: %w", err))
	}
	if storedItems >= s.maxStoredItems || int64(len(ciphertext)) > s.maxStoredBytes-storedBytes {
		return time.Time{}, rollbackWithError(tx, errStoreCapacity)
	}

	result, err := tx.ExecContext(
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
		return time.Time{}, rollbackWithError(tx, fmt.Errorf("insert secret: %w", err))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return time.Time{}, rollbackWithError(tx, fmt.Errorf("read inserted row count: %w", err))
	}
	if rowsAffected == 0 {
		existingExpiry, exists, err = s.existingSecretExpiry(
			ctx,
			tx,
			id,
			ciphertext,
			nonce,
			consumeVerifier,
		)
		if err != nil {
			return time.Time{}, rollbackWithError(tx, err)
		}
		if !exists {
			return time.Time{}, rollbackWithError(tx, errors.New("secret insert was ignored without an existing row"))
		}
		if err := tx.Commit(); err != nil {
			return time.Time{}, fmt.Errorf("commit concurrently created secret: %w", err)
		}
		return existingExpiry, nil
	}
	// Keep only the ID until every creation request carrying it has expired.
	// The API rejects old timestamps and binds them to the ID commitment.
	receiptExpiry := now.Add(createRetryWindow + createClockSkew).UTC().Unix()
	if _, err := tx.ExecContext(ctx, "INSERT INTO create_receipts (id, expires_at_unix) VALUES (?, ?)", id, receiptExpiry); err != nil {
		return time.Time{}, rollbackWithError(tx, fmt.Errorf("record creation receipt: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, fmt.Errorf("commit created secret: %w", err)
	}

	return expiresAt, nil
}

// existingSecretExpiry recognizes an exact retry of an already committed
// create request.
func (s *store) existingSecretExpiry(
	ctx context.Context,
	tx *sql.Tx,
	id string,
	ciphertext []byte,
	nonce []byte,
	consumeVerifier []byte,
) (time.Time, bool, error) {
	var storedCiphertext, storedNonce, storedVerifier []byte
	var expiresAtUnix int64
	if err := tx.QueryRowContext(
		ctx,
		`SELECT ciphertext, nonce, consume_verifier, expires_at_unix
		 FROM secrets
		 WHERE id = ?`,
		id,
	).Scan(&storedCiphertext, &storedNonce, &storedVerifier, &expiresAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, fmt.Errorf("read existing secret: %w", err)
	}
	if !bytes.Equal(storedCiphertext, ciphertext) ||
		!bytes.Equal(storedNonce, nonce) ||
		subtle.ConstantTimeCompare(storedVerifier, consumeVerifier) != 1 {
		return time.Time{}, true, errSecretExists
	}
	return time.Unix(expiresAtUnix, 0).UTC(), true, nil
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
		if err := s.truncateWAL(); err != nil {
			return nil, err
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
	if err := s.truncateWAL(); err != nil {
		// The delete is already committed. Return the payload with the
		// maintenance error so the handler can deliver the one available copy.
		return &secret, err
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
	if _, err := s.db.ExecContext(ctx, "DELETE FROM create_receipts WHERE expires_at_unix <= ?", now.UTC().Unix()); err != nil {
		return fmt.Errorf("delete expired retry receipts: %w", err)
	}
	return s.truncateWAL()
}

func (s *store) truncateWAL() error {
	ctx, cancel := context.WithTimeout(context.Background(), walCheckpointTimeout)
	defer cancel()

	var busy, logFrames, checkpointedFrames int
	if err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointedFrames); err != nil {
		return fmt.Errorf("truncate sqlite WAL: %w", err)
	}
	if busy != 0 {
		return fmt.Errorf("truncate sqlite WAL: %d frames remain busy", logFrames-checkpointedFrames)
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
