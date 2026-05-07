package database

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fiware/VCVerifier/logging"
)

var (
	// ErrRefreshTokenNotFound is returned when a refresh token does not
	// exist in the database or has already been consumed.
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	// ErrRefreshTokenInvalidIntegrity is returned when the HMAC of a stored
	// row does not match, indicating database-level tampering.
	ErrRefreshTokenInvalidIntegrity = errors.New("refresh token integrity check failed")
)

// RefreshTokenRepository defines the data-access operations for OAuth2
// refresh tokens. Implementations must be safe for concurrent use.
type RefreshTokenRepository interface {
	// StoreRefreshToken persists a new refresh token row.
	StoreRefreshToken(ctx context.Context, row RefreshTokenRow) error

	// GetAndDeleteRefreshToken atomically retrieves and deletes a refresh
	// token (single-use). Returns ErrRefreshTokenNotFound if the token does
	// not exist.
	GetAndDeleteRefreshToken(ctx context.Context, token string) (*RefreshTokenRow, error)

	// DeleteExpiredTokens removes all refresh token rows whose expires_at
	// is in the past. Returns the number of rows deleted.
	DeleteExpiredTokens(ctx context.Context) (int64, error)

	// SetCleanupInterval starts a background goroutine that periodically calls
	// DeleteExpiredTokens at the given interval. If interval is zero or
	// negative, any running cleanup goroutine is cancelled and no new one is
	// started. Calling again with a new interval replaces the previous one.
	// The goroutine stops when ctx is cancelled.
	SetCleanupInterval(ctx context.Context, interval time.Duration)
}

// SqlRefreshTokenRepository is a RefreshTokenRepository backed by database/sql.
type SqlRefreshTokenRepository struct {
	db            *sql.DB
	dbType        string
	mu            sync.Mutex
	cancelCleanup context.CancelFunc
	hashEnabled   bool
	salt          []byte
}

// NewRefreshTokenRepository creates a new SqlRefreshTokenRepository for the
// provided database connection and driver type.
func NewRefreshTokenRepository(db *sql.DB, dbType string) *SqlRefreshTokenRepository {
	return &SqlRefreshTokenRepository{db: db, dbType: dbType}
}

// GenerateSalt returns 32 cryptographically random bytes suitable for use
// with ConfigureHashing.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate refresh token salt: %w", err)
	}
	return salt, nil
}

// ConfigureHashing enables HMAC-SHA256 hashing of tokens before storage.
// Must be called before any tokens are stored or retrieved. The salt must
// not be empty.
func (r *SqlRefreshTokenRepository) ConfigureHashing(salt []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.salt = salt
	r.hashEnabled = true
}

// tokenKey returns the value used as the DB primary key for rawToken:
// the HMAC-SHA256 hex digest when hashing is enabled, or rawToken as-is.
func (r *SqlRefreshTokenRepository) tokenKey(rawToken string) string {
	if !r.hashEnabled {
		return rawToken
	}
	mac := hmac.New(sha256.New, r.salt)
	mac.Write([]byte(rawToken))
	return hex.EncodeToString(mac.Sum(nil))
}

// rawTokenSuffix returns the last 5 characters of token for storage.
func rawTokenSuffix(token string) string {
	if len(token) <= 5 {
		return token
	}
	return token[len(token)-5:]
}

const (
	sqlInsertRefreshToken = `INSERT INTO refresh_token (token, token_suffix, client_id, claims, integrity, expires_at) VALUES (?, ?, ?, ?, ?, ?)`

	sqlSelectRefreshToken = `SELECT token, token_suffix, client_id, claims, integrity, expires_at FROM refresh_token WHERE token = ?`

	sqlDeleteRefreshToken = `DELETE FROM refresh_token WHERE token = ?`

	sqlDeleteExpiredRefreshTokens = `DELETE FROM refresh_token WHERE expires_at < ?`
)

// computeIntegrity returns HMAC-SHA256(salt, rawToken|"|"|clientId|"|"|claims|"|"|expiresAt)
// as a lowercase hex string. Returns empty string when salt is not configured,
// in which case integrity verification is skipped on retrieval.
func computeIntegrity(salt []byte, rawToken, clientId, claims string, expiresAt int64) string {
	if len(salt) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(rawToken))
	mac.Write([]byte("|"))
	mac.Write([]byte(clientId))
	mac.Write([]byte("|"))
	mac.Write([]byte(claims))
	mac.Write([]byte("|"))
	mac.Write([]byte(strconv.FormatInt(expiresAt, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// StoreRefreshToken persists a new refresh token row in the database.
// The token primary key is hashed when hashing is configured; the last 5
// characters of the raw token are always stored in token_suffix. The integrity
// HMAC is computed from the configured salt and stored alongside the claims.
func (r *SqlRefreshTokenRepository) StoreRefreshToken(ctx context.Context, row RefreshTokenRow) error {
	integrity := computeIntegrity(r.salt, row.Token, row.ClientID, row.Claims, row.ExpiresAt)
	_, err := r.db.ExecContext(ctx, r.adapt(sqlInsertRefreshToken),
		r.tokenKey(row.Token), rawTokenSuffix(row.Token), row.ClientID, row.Claims, integrity, row.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	logging.Log().Debugf("Stored refresh token (expires_at=%d)", row.ExpiresAt)
	return nil
}

// GetAndDeleteRefreshToken atomically retrieves and deletes a refresh token
// within a transaction, ensuring single-use semantics. Returns
// ErrRefreshTokenNotFound if the token does not exist, or
// ErrRefreshTokenInvalidIntegrity if the stored HMAC does not match (possible
// database-level tampering). The token is consumed regardless of the integrity
// outcome to prevent repeated use of a tampered row.
func (r *SqlRefreshTokenRepository) GetAndDeleteRefreshToken(ctx context.Context, token string) (*RefreshTokenRow, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer rollbackOnError(tx)

	var row RefreshTokenRow
	err = tx.QueryRowContext(ctx, r.adapt(sqlSelectRefreshToken), r.tokenKey(token)).Scan(
		&row.Token, &row.TokenSuffix, &row.ClientID, &row.Claims, &row.Integrity, &row.ExpiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, fmt.Errorf("select refresh token: %w", err)
	}

	if _, err := tx.ExecContext(ctx, r.adapt(sqlDeleteRefreshToken), r.tokenKey(token)); err != nil {
		return nil, fmt.Errorf("delete refresh token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	// Verify integrity after committing so the token is consumed even on failure,
	// preventing repeated use of a tampered row.
	if len(r.salt) > 0 {
		expected := computeIntegrity(r.salt, token, row.ClientID, row.Claims, row.ExpiresAt)
		if !hmac.Equal([]byte(expected), []byte(row.Integrity)) {
			logging.Log().Warnf("Refresh token integrity check failed (suffix=%s): possible database-level tampering", row.TokenSuffix)
			return nil, ErrRefreshTokenInvalidIntegrity
		}
	}

	logging.Log().Debugf("Retrieved and deleted refresh token")
	return &row, nil
}

// DeleteExpiredTokens removes all refresh token rows whose expiration time
// has passed. Returns the number of rows deleted.
func (r *SqlRefreshTokenRepository) DeleteExpiredTokens(ctx context.Context) (int64, error) {
	now := time.Now().Unix()
	result, err := r.db.ExecContext(ctx, r.adapt(sqlDeleteExpiredRefreshTokens), now)
	if err != nil {
		return 0, fmt.Errorf("delete expired refresh tokens: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}
	if n > 0 {
		logging.Log().Infof("Cleaned up %d expired refresh token(s)", n)
	}
	return n, nil
}

// SetCleanupInterval starts a background goroutine that periodically deletes
// expired refresh token rows. If interval is zero or negative, any running
// cleanup goroutine is cancelled and no new one is started. Calling again
// replaces the previous interval. The goroutine stops when ctx is cancelled.
func (r *SqlRefreshTokenRepository) SetCleanupInterval(ctx context.Context, interval time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cancelCleanup != nil {
		r.cancelCleanup()
		r.cancelCleanup = nil
	}

	if interval <= 0 {
		return
	}

	cleanupCtx, cancel := context.WithCancel(ctx)
	r.cancelCleanup = cancel

	go func() {
		runCleanup := func() {
			logging.Log().Debug("Running refresh token cleanup")
			if _, err := r.DeleteExpiredTokens(cleanupCtx); err != nil && cleanupCtx.Err() == nil {
				logging.Log().Warnf("Refresh token cleanup failed: %v", err)
			}
		}
		runCleanup()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				runCleanup()
			case <-cleanupCtx.Done():
				return
			}
		}
	}()
}

func (r *SqlRefreshTokenRepository) adapt(query string) string {
	if r.dbType != DriverTypePostgres {
		return query
	}
	var b strings.Builder
	b.Grow(len(query))
	n := 1
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			fmt.Fprintf(&b, "$%d", n)
			n++
		} else {
			b.WriteByte(query[i])
		}
	}
	return b.String()
}
