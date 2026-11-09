// Package keys stores the registration keys the relay hands out. Only a SHA-256 hash of
// each key is kept, so a leak of the database never yields a usable key. SQLite (pure-Go
// modernc driver) keeps the relay a single container with no extra database to run.
package keys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// keyPrefix makes an issued key recognisable in logs and configs without revealing it.
const keyPrefix = "llr_"

// ErrNotFound is returned for an unknown, or revoked, key.
var ErrNotFound = errors.New("key not found")

// ErrRegistrationCeiling is returned by Issue once the relay has minted its maximum number
// of keys.
var ErrRegistrationCeiling = errors.New("keys: registration ceiling reached")

// ErrTokenLimit is returned by BindToken when a key already holds its maximum of bound tokens.
var ErrTokenLimit = errors.New("keys: token limit reached")

// pruneInterval bounds how often BindToken's lazy sweep actually runs the DELETE.
const pruneInterval = time.Hour

// MaxOwnersPerToken is how many servers may hold one device token at a time. A phone's token
// only reaches servers that phone paired with, so a handful is normal, and the cap exists so
// that one server cannot lock the phone out of another: when a fourth server arrives the
// least recently used owner makes room instead of the newcomer being refused.
const MaxOwnersPerToken = 3

// lastUsedGranularity is how often a key's last-used time is written, so a busy key does not
// turn every request into a database write.
const lastUsedGranularity = time.Minute

// Key is one issued registration key. It never carries the plaintext or the hash. Label is
// an optional admin hint that the relay's own endpoints no longer fill in.
type Key struct {
	ID         int64      `json:"id"`
	Label      string     `json:"label"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

// Store is the SQLite-backed key store.
type Store struct {
	db *sql.DB

	// Pruning piggybacks on BindToken instead of a background loop, so the store has nothing
	// extra to start and stop.
	pruneMu   sync.Mutex
	lastPrune time.Time
}

// Open opens (creating if needed) the key store at path and applies its schema.
func Open(path string) (*Store, error) {
	// busy_timeout lets a writer wait rather than fail under contention; WAL keeps reads
	// from blocking the occasional write; temp_store=MEMORY avoids needing a writable temp
	// dir, which the distroless runtime image does not provide.
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=temp_store(MEMORY)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// modernc/sqlite serialises writes on one connection cleanly; a small pool avoids
	// "database is locked" without extra coordination.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, lastPrune: time.Now()}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the underlying database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS keys (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	key_hash     TEXT NOT NULL UNIQUE,
	label        TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	last_used_at INTEGER,
	revoked_at   INTEGER
);
CREATE TABLE IF NOT EXISTS token_owners (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	token        TEXT NOT NULL,
	key_id       INTEGER NOT NULL REFERENCES keys(id),
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	UNIQUE(token, key_id)
);
CREATE INDEX IF NOT EXISTS token_owners_key_id ON token_owners(key_id);`)
	return err
}

// Issue mints a new key, stores only its hash, and returns the plaintext once. The
// plaintext is unrecoverable afterward. label is an unverified admin hint (the claimed
// public URL). max bounds the number of unrevoked keys, so revoking a key frees its slot
// and /v1/register still cannot grow the table without bound; zero or negative disables it.
//
// The count-then-insert is race-free because Open limits the pool to one connection.
func (s *Store) Issue(ctx context.Context, label string, max int64) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	plain := keyPrefix + base64.RawURLEncoding.EncodeToString(raw)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	if max > 0 {
		var count int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM keys WHERE revoked_at IS NULL`).Scan(&count); err != nil {
			return "", err
		}
		if count >= max {
			return "", ErrRegistrationCeiling
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO keys (key_hash, label, created_at) VALUES (?, ?, ?)`,
		hashKey(plain), label, time.Now().Unix()); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return plain, nil
}

// Verify returns the key for a plaintext secret if it exists and is not revoked, stamping
// its last-used time. Returns ErrNotFound for an unknown or revoked key.
func (s *Store) Verify(ctx context.Context, plain string) (*Key, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, label, created_at, last_used_at, revoked_at FROM keys WHERE key_hash = ?`,
		hashKey(plain))
	k, err := scanKey(row)
	if err != nil {
		return nil, err
	}
	if k.RevokedAt != nil {
		return nil, ErrNotFound
	}
	// Writes are throttled, and the returned key reflects what is stored.
	now := time.Now()
	if k.LastUsedAt == nil || now.Sub(*k.LastUsedAt) >= lastUsedGranularity {
		if _, err := s.db.ExecContext(ctx, `UPDATE keys SET last_used_at = ? WHERE id = ?`, now.Unix(), k.ID); err == nil {
			stamped := time.Unix(now.Unix(), 0)
			k.LastUsedAt = &stamped
		}
	}
	return k, nil
}

// List returns every issued key, newest first, for the admin view.
func (s *Store) List(ctx context.Context) ([]Key, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, label, created_at, last_used_at, revoked_at FROM keys ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

// Revoke marks a key unusable and releases every token it held, so the phones it paired
// with are free for the servers that still have them. Returns ErrNotFound if no such
// (unrevoked) key exists.
func (s *Store) Revoke(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx,
		`UPDATE keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM token_owners WHERE key_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// BindToken records that keyID sends to token. A token has at most MaxOwnersPerToken owners;
// a new one past that evicts the owner that sent least recently. maxPerKey caps how many
// tokens one key may hold, and a token the key already owns always succeeds. retention is
// how long an untouched binding lives before the lazy sweep deletes it, and only the owner's
// own sends refresh it. Zero or negative disables either limit.
func (s *Store) BindToken(ctx context.Context, keyID int64, token string, retention time.Duration, maxPerKey int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()
	res, err := tx.ExecContext(ctx,
		`UPDATE token_owners SET last_seen_at = ? WHERE token = ? AND key_id = ?`, now, token, keyID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if maxPerKey > 0 {
			var held int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_owners WHERE key_id = ?`, keyID).Scan(&held); err != nil {
				return err
			}
			if held >= maxPerKey {
				return ErrTokenLimit
			}
		}
		if _, err := tx.ExecContext(ctx, `
DELETE FROM token_owners WHERE id IN (
	SELECT id FROM token_owners WHERE token = ? ORDER BY last_seen_at ASC, id ASC
	LIMIT max(0, (SELECT COUNT(*) FROM token_owners WHERE token = ?) - ?)
)`, token, token, MaxOwnersPerToken-1); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO token_owners (token, key_id, created_at, last_seen_at) VALUES (?, ?, ?, ?)`,
			token, keyID, now, now); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.maybePruneStaleTokens(ctx, retention)
	return nil
}

// ReleaseToken drops every binding of a token the push provider reported dead. It is dead for
// all of its owners, and the slots free up if the device registers again.
func (s *Store) ReleaseToken(ctx context.Context, token string) {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM token_owners WHERE token = ?`, token); err != nil {
		log.Printf("relay: release token: %v", err)
	}
}

// OwnerCount reports how many keys currently hold a token.
func (s *Store) OwnerCount(ctx context.Context, token string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_owners WHERE token = ?`, token).Scan(&n)
	return n, err
}

// Holds reports whether keyID currently holds token.
func (s *Store) Holds(ctx context.Context, keyID int64, token string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM token_owners WHERE token = ? AND key_id = ?`, token, keyID).Scan(&n)
	return n > 0, err
}

func (s *Store) maybePruneStaleTokens(ctx context.Context, retention time.Duration) {
	if retention <= 0 {
		return
	}
	s.pruneMu.Lock()
	due := time.Since(s.lastPrune) >= pruneInterval
	if due {
		s.lastPrune = time.Now()
	}
	s.pruneMu.Unlock()
	if !due {
		return
	}
	cutoff := time.Now().Add(-retention).Unix()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM token_owners WHERE last_seen_at < ?`, cutoff); err != nil {
		log.Printf("relay: prune stale tokens: %v", err)
	}
}

func hashKey(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanKey(r rowScanner) (*Key, error) {
	var (
		k        Key
		created  int64
		lastUsed sql.NullInt64
		revoked  sql.NullInt64
	)
	if err := r.Scan(&k.ID, &k.Label, &created, &lastUsed, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	k.CreatedAt = time.Unix(created, 0)
	if lastUsed.Valid {
		t := time.Unix(lastUsed.Int64, 0)
		k.LastUsedAt = &t
	}
	if revoked.Valid {
		t := time.Unix(revoked.Int64, 0)
		k.RevokedAt = &t
	}
	return &k, nil
}
