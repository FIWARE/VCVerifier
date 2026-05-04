package database

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
)

// Sentinel errors returned by repository methods.
var (
	// ErrServiceNotFound is returned when a service ID does not exist.
	ErrServiceNotFound = errors.New("service not found")
	// ErrServiceAlreadyExists is returned on a duplicate service ID insert.
	ErrServiceAlreadyExists = errors.New("service already exists")
	// ErrRefreshTokenNotFound is returned when a refresh token does not
	// exist in the database or has already been consumed.
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
)

// ServiceRepository defines the data-access operations for CCS services
// and their scope entries. Implementations must be safe for concurrent use.
type ServiceRepository interface {
	// CreateService persists a new service together with all its scope entries.
	// Returns ErrServiceAlreadyExists if a service with the same ID exists.
	CreateService(ctx context.Context, service config.ConfiguredService) error

	// GetService retrieves a single service by ID, including all scope entries.
	// Returns ErrServiceNotFound if the ID does not exist.
	GetService(ctx context.Context, id string) (config.ConfiguredService, error)

	// GetAllServices returns a page of services ordered by ID and the total
	// count across all pages. page is zero-based.
	GetAllServices(ctx context.Context, page, pageSize int) ([]config.ConfiguredService, int, error)

	// UpdateService replaces the service row and all its scope entries.
	// Returns ErrServiceNotFound if the ID does not exist. Returns the
	// updated service (re-read from DB) for response purposes.
	UpdateService(ctx context.Context, id string, service config.ConfiguredService) (config.ConfiguredService, error)

	// DeleteService removes a service and its scope entries (via CASCADE).
	// Returns ErrServiceNotFound if the ID does not exist.
	DeleteService(ctx context.Context, id string) error

	// GetServiceScopes returns the credential types required for a scope.
	// When oidcScope is nil, the service's default scope is used.
	// Returns ErrServiceNotFound when the service does not exist, or
	// config.ErrorNoSuchScope when the resolved scope is not configured.
	GetServiceScopes(ctx context.Context, id string, oidcScope *string) ([]string, error)

	// ServiceExists checks whether a service with the given ID exists.
	ServiceExists(ctx context.Context, id string) (bool, error)
}

// SqlServiceRepository is a ServiceRepository backed by database/sql.
type SqlServiceRepository struct {
	db     *sql.DB
	dbType string
}

// NewServiceRepository creates a new SqlServiceRepository for the provided
// database connection and driver type. The dbType must be one of the
// DriverType* constants and is used to adapt SQL placeholder syntax.
func NewServiceRepository(db *sql.DB, dbType string) *SqlServiceRepository {
	return &SqlServiceRepository{db: db, dbType: dbType}
}

// ---------------------------------------------------------------------------
// SQL query constants (written with ? placeholders; adapted at runtime for
// PostgreSQL which requires $N style).
// ---------------------------------------------------------------------------

const (
	sqlInsertService = `INSERT INTO service (id, default_oidc_scope, authorization_type) VALUES (?, ?, ?)`

	sqlInsertScopeEntry = `INSERT INTO scope_entry (service_id, scope_key, credentials, presentation_definition, flat_claims, dcql_query) VALUES (?, ?, ?, ?, ?, ?)`

	sqlSelectServiceByID = `SELECT id, default_oidc_scope, authorization_type FROM service WHERE id = ?`

	sqlSelectScopesByServiceID = `SELECT id, service_id, scope_key, credentials, presentation_definition, flat_claims, dcql_query FROM scope_entry WHERE service_id = ? ORDER BY id`

	sqlCountServices = `SELECT COUNT(*) FROM service`

	sqlSelectServicesPaginated = `SELECT id, default_oidc_scope, authorization_type FROM service ORDER BY id LIMIT ? OFFSET ?`

	sqlUpdateService = `UPDATE service SET default_oidc_scope = ?, authorization_type = ? WHERE id = ?`

	sqlDeleteScopesByServiceID = `DELETE FROM scope_entry WHERE service_id = ?`

	sqlDeleteServiceByID = `DELETE FROM service WHERE id = ?`

	sqlServiceExists = `SELECT 1 FROM service WHERE id = ?`

	sqlSelectScopeEntry = `SELECT credentials FROM scope_entry WHERE service_id = ? AND scope_key = ?`
)

// CreateService persists a new service and its scope entries within a single
// transaction. Returns ErrServiceAlreadyExists on duplicate ID.
func (r *SqlServiceRepository) CreateService(ctx context.Context, service config.ConfiguredService) error {
	exists, err := r.ServiceExists(ctx, service.Id)
	if err != nil {
		return fmt.Errorf("checking existence: %w", err)
	}
	if exists {
		return ErrServiceAlreadyExists
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer rollbackOnError(tx)

	svcRow := ServiceToRow(service)
	if _, err := tx.ExecContext(ctx, r.adapt(sqlInsertService),
		svcRow.ID, svcRow.DefaultOidcScope, svcRow.AuthorizationType); err != nil {
		return fmt.Errorf("insert service: %w", err)
	}

	if err := r.insertScopeEntries(ctx, tx, service.Id, service.ServiceScopes); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	logging.Log().Infof("Created service %q with %d scope(s)", service.Id, len(service.ServiceScopes))
	return nil
}

// GetService retrieves a single service by ID.
func (r *SqlServiceRepository) GetService(ctx context.Context, id string) (config.ConfiguredService, error) {
	svcRow, err := r.scanServiceRow(ctx, r.db, id)
	if err != nil {
		return config.ConfiguredService{}, err
	}

	scopeRows, err := r.scanScopeEntryRows(ctx, r.db, id)
	if err != nil {
		return config.ConfiguredService{}, err
	}

	return RowToService(svcRow, scopeRows)
}

// GetAllServices returns a page of services and the total service count.
func (r *SqlServiceRepository) GetAllServices(ctx context.Context, page, pageSize int) ([]config.ConfiguredService, int, error) {
	var total int
	if err := r.db.QueryRowContext(ctx, r.adapt(sqlCountServices)).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count services: %w", err)
	}
	if total == 0 {
		return []config.ConfiguredService{}, 0, nil
	}

	offset := page * pageSize
	rows, err := r.db.QueryContext(ctx, r.adapt(sqlSelectServicesPaginated), pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("select services: %w", err)
	}
	defer rows.Close()

	var serviceIDs []string
	svcRows := make(map[string]ServiceRow)
	for rows.Next() {
		var sr ServiceRow
		if err := rows.Scan(&sr.ID, &sr.DefaultOidcScope, &sr.AuthorizationType); err != nil {
			return nil, 0, fmt.Errorf("scan service: %w", err)
		}
		serviceIDs = append(serviceIDs, sr.ID)
		svcRows[sr.ID] = sr
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate services: %w", err)
	}

	scopeMap, err := r.batchScopeEntries(ctx, serviceIDs)
	if err != nil {
		return nil, 0, err
	}

	services := make([]config.ConfiguredService, 0, len(serviceIDs))
	for _, id := range serviceIDs {
		svc, err := RowToService(svcRows[id], scopeMap[id])
		if err != nil {
			return nil, 0, fmt.Errorf("assemble service %q: %w", id, err)
		}
		services = append(services, svc)
	}

	return services, total, nil
}

// UpdateService replaces a service's data and all its scope entries.
func (r *SqlServiceRepository) UpdateService(ctx context.Context, id string, service config.ConfiguredService) (config.ConfiguredService, error) {
	exists, err := r.ServiceExists(ctx, id)
	if err != nil {
		return config.ConfiguredService{}, fmt.Errorf("checking existence: %w", err)
	}
	if !exists {
		return config.ConfiguredService{}, ErrServiceNotFound
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return config.ConfiguredService{}, fmt.Errorf("begin tx: %w", err)
	}
	defer rollbackOnError(tx)

	svcRow := ServiceToRow(service)
	if _, err := tx.ExecContext(ctx, r.adapt(sqlUpdateService),
		svcRow.DefaultOidcScope, svcRow.AuthorizationType, id); err != nil {
		return config.ConfiguredService{}, fmt.Errorf("update service: %w", err)
	}

	// Replace all scope entries: delete old, insert new.
	if _, err := tx.ExecContext(ctx, r.adapt(sqlDeleteScopesByServiceID), id); err != nil {
		return config.ConfiguredService{}, fmt.Errorf("delete old scopes: %w", err)
	}
	if err := r.insertScopeEntries(ctx, tx, id, service.ServiceScopes); err != nil {
		return config.ConfiguredService{}, err
	}

	if err := tx.Commit(); err != nil {
		return config.ConfiguredService{}, fmt.Errorf("commit: %w", err)
	}

	logging.Log().Infof("Updated service %q", id)

	// Re-read from DB to return the persisted state.
	return r.GetService(ctx, id)
}

// DeleteService removes a service. Scope entries are cascade-deleted.
func (r *SqlServiceRepository) DeleteService(ctx context.Context, id string) error {
	exists, err := r.ServiceExists(ctx, id)
	if err != nil {
		return fmt.Errorf("checking existence: %w", err)
	}
	if !exists {
		return ErrServiceNotFound
	}

	if _, err := r.db.ExecContext(ctx, r.adapt(sqlDeleteServiceByID), id); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	logging.Log().Infof("Deleted service %q", id)
	return nil
}

// GetServiceScopes returns the credential type names required for the given
// scope. When oidcScope is nil the service's default scope is used.
func (r *SqlServiceRepository) GetServiceScopes(ctx context.Context, id string, oidcScope *string) ([]string, error) {
	// Fetch the service to verify existence and resolve default scope.
	svcRow, err := r.scanServiceRow(ctx, r.db, id)
	if err != nil {
		return nil, err
	}

	scopeKey := ""
	if oidcScope != nil {
		scopeKey = *oidcScope
	} else if svcRow.DefaultOidcScope != nil {
		scopeKey = *svcRow.DefaultOidcScope
	}
	if scopeKey == "" {
		return nil, config.ErrorNoSuchScope
	}

	var credJSON string
	err = r.db.QueryRowContext(ctx, r.adapt(sqlSelectScopeEntry), id, scopeKey).Scan(&credJSON)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, config.ErrorNoSuchScope
		}
		return nil, fmt.Errorf("query scope entry: %w", err)
	}

	var credentials []CredentialDB
	if err := json.Unmarshal([]byte(credJSON), &credentials); err != nil {
		return nil, fmt.Errorf("unmarshal credentials: %w", err)
	}

	types := make([]string, 0, len(credentials))
	for _, c := range credentials {
		types = append(types, c.Type)
	}
	return types, nil
}

// ServiceExists returns true if a service with the given ID exists.
func (r *SqlServiceRepository) ServiceExists(ctx context.Context, id string) (bool, error) {
	var dummy int
	err := r.db.QueryRowContext(ctx, r.adapt(sqlServiceExists), id).Scan(&dummy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("service exists check: %w", err)
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// queryExecer abstracts *sql.DB and *sql.Tx for shared scan helpers.
type queryExecer interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
}

// scanServiceRow reads a single service row. Returns ErrServiceNotFound when
// the ID does not exist.
func (r *SqlServiceRepository) scanServiceRow(ctx context.Context, qe queryExecer, id string) (ServiceRow, error) {
	var sr ServiceRow
	err := qe.QueryRowContext(ctx, r.adapt(sqlSelectServiceByID), id).
		Scan(&sr.ID, &sr.DefaultOidcScope, &sr.AuthorizationType)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sr, ErrServiceNotFound
		}
		return sr, fmt.Errorf("scan service %q: %w", id, err)
	}
	return sr, nil
}

// scanScopeEntryRows reads all scope entries belonging to a service.
func (r *SqlServiceRepository) scanScopeEntryRows(ctx context.Context, qe queryExecer, serviceID string) ([]ScopeEntryRow, error) {
	rows, err := qe.QueryContext(ctx, r.adapt(sqlSelectScopesByServiceID), serviceID)
	if err != nil {
		return nil, fmt.Errorf("query scopes for %q: %w", serviceID, err)
	}
	defer rows.Close()

	var result []ScopeEntryRow
	for rows.Next() {
		var sr ScopeEntryRow
		if err := rows.Scan(&sr.ID, &sr.ServiceID, &sr.ScopeKey, &sr.Credentials,
			&sr.PresentationDefinition, &sr.FlatClaims, &sr.DcqlQuery); err != nil {
			return nil, fmt.Errorf("scan scope entry: %w", err)
		}
		result = append(result, sr)
	}
	return result, rows.Err()
}

// insertScopeEntries marshals and inserts scope entries within an existing
// transaction.
func (r *SqlServiceRepository) insertScopeEntries(ctx context.Context, tx *sql.Tx, serviceID string, scopes map[string]config.ScopeEntry) error {
	scopeRows, err := ScopeEntryToRows(serviceID, scopes)
	if err != nil {
		return fmt.Errorf("marshal scope entries: %w", err)
	}
	for _, sr := range scopeRows {
		if _, err := tx.ExecContext(ctx, r.adapt(sqlInsertScopeEntry),
			sr.ServiceID, sr.ScopeKey, sr.Credentials,
			sr.PresentationDefinition, sr.FlatClaims, sr.DcqlQuery); err != nil {
			return fmt.Errorf("insert scope entry %q: %w", sr.ScopeKey, err)
		}
	}
	return nil
}

// batchScopeEntries loads scope entries for multiple service IDs in a single
// query and groups them by service ID.
func (r *SqlServiceRepository) batchScopeEntries(ctx context.Context, serviceIDs []string) (map[string][]ScopeEntryRow, error) {
	if len(serviceIDs) == 0 {
		return nil, nil
	}

	placeholders := make([]string, len(serviceIDs))
	args := make([]interface{}, len(serviceIDs))
	for i, id := range serviceIDs {
		placeholders[i] = r.ph(i + 1)
		args[i] = id
	}

	query := fmt.Sprintf(
		`SELECT id, service_id, scope_key, credentials, presentation_definition, flat_claims, dcql_query FROM scope_entry WHERE service_id IN (%s) ORDER BY id`,
		strings.Join(placeholders, ", "),
	)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("batch scope entries: %w", err)
	}
	defer rows.Close()

	result := make(map[string][]ScopeEntryRow)
	for rows.Next() {
		var sr ScopeEntryRow
		if err := rows.Scan(&sr.ID, &sr.ServiceID, &sr.ScopeKey, &sr.Credentials,
			&sr.PresentationDefinition, &sr.FlatClaims, &sr.DcqlQuery); err != nil {
			return nil, fmt.Errorf("scan batch scope entry: %w", err)
		}
		result[sr.ServiceID] = append(result[sr.ServiceID], sr)
	}
	return result, rows.Err()
}

// adapt replaces ? placeholders with $N for PostgreSQL. For MySQL and SQLite
// the query is returned unchanged.
func (r *SqlServiceRepository) adapt(query string) string {
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

// ph returns the SQL placeholder for the given 1-based parameter position,
// adapting for the database type ($N for Postgres, ? otherwise).
func (r *SqlServiceRepository) ph(pos int) string {
	if r.dbType == DriverTypePostgres {
		return fmt.Sprintf("$%d", pos)
	}
	return "?"
}

// rollbackOnError calls Rollback on a transaction. It is intended for use
// in a defer statement — if the transaction was already committed, the
// Rollback is a no-op that returns sql.ErrTxDone (which we ignore).
func rollbackOnError(tx *sql.Tx) {
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		logging.Log().Warnf("rollback failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RefreshTokenRepository — database-backed refresh token storage
// ---------------------------------------------------------------------------

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

// SQL query constants for refresh token operations (written with ?
// placeholders; adapted at runtime for PostgreSQL).
const (
	sqlInsertRefreshToken = `INSERT INTO refresh_token (token, token_suffix, client_id, jwt_payload, expires_at) VALUES (?, ?, ?, ?, ?)`

	sqlSelectRefreshToken = `SELECT token, token_suffix, client_id, jwt_payload, expires_at FROM refresh_token WHERE token = ?`

	sqlDeleteRefreshToken = `DELETE FROM refresh_token WHERE token = ?`

	sqlDeleteExpiredRefreshTokens = `DELETE FROM refresh_token WHERE expires_at < ?`
)

// StoreRefreshToken persists a new refresh token row in the database.
// The token primary key is hashed when hashing is configured; the last 5
// characters of the raw token are always stored in token_suffix.
func (r *SqlRefreshTokenRepository) StoreRefreshToken(ctx context.Context, row RefreshTokenRow) error {
	_, err := r.db.ExecContext(ctx, r.adapt(sqlInsertRefreshToken),
		r.tokenKey(row.Token), rawTokenSuffix(row.Token), row.ClientID, row.JWTPayload, row.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	logging.Log().Debugf("Stored refresh token (expires_at=%d)", row.ExpiresAt)
	return nil
}

// GetAndDeleteRefreshToken atomically retrieves and deletes a refresh token
// within a transaction, ensuring single-use semantics. Returns
// ErrRefreshTokenNotFound if the token does not exist.
func (r *SqlRefreshTokenRepository) GetAndDeleteRefreshToken(ctx context.Context, token string) (*RefreshTokenRow, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer rollbackOnError(tx)

	var row RefreshTokenRow
	err = tx.QueryRowContext(ctx, r.adapt(sqlSelectRefreshToken), r.tokenKey(token)).Scan(
		&row.Token, &row.TokenSuffix, &row.ClientID, &row.JWTPayload, &row.ExpiresAt)
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
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if _, err := r.DeleteExpiredTokens(cleanupCtx); err != nil && cleanupCtx.Err() == nil {
					logging.Log().Warnf("Refresh token cleanup failed: %v", err)
				}
			case <-cleanupCtx.Done():
				return
			}
		}
	}()
}

// adapt replaces ? placeholders with $N for PostgreSQL. For MySQL and SQLite
// the query is returned unchanged.
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
