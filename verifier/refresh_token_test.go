package verifier

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/database"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// mockRefreshTokenRepository — in-memory mock implementing
// database.RefreshTokenRepository for unit tests.
// ---------------------------------------------------------------------------

type mockRefreshTokenRepository struct {
	tokens   map[string]database.RefreshTokenRow
	storeErr error
	getErr   error
}

func newMockRefreshTokenRepo() *mockRefreshTokenRepository {
	return &mockRefreshTokenRepository{
		tokens: make(map[string]database.RefreshTokenRow),
	}
}

// StoreRefreshToken stores a token in the in-memory map.
func (m *mockRefreshTokenRepository) StoreRefreshToken(_ context.Context, row database.RefreshTokenRow) error {
	if m.storeErr != nil {
		return m.storeErr
	}
	m.tokens[row.Token] = row
	return nil
}

// GetAndDeleteRefreshToken retrieves and deletes a token from the in-memory
// map, mimicking single-use semantics.
func (m *mockRefreshTokenRepository) GetAndDeleteRefreshToken(_ context.Context, token string) (*database.RefreshTokenRow, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	row, ok := m.tokens[token]
	if !ok {
		return nil, database.ErrRefreshTokenNotFound
	}
	delete(m.tokens, token)
	return &row, nil
}

// DeleteExpiredTokens removes tokens whose ExpiresAt is in the past.
func (m *mockRefreshTokenRepository) DeleteExpiredTokens(_ context.Context) (int64, error) {
	now := time.Now().Unix()
	var count int64
	for k, v := range m.tokens {
		if v.ExpiresAt < now {
			delete(m.tokens, k)
			count++
		}
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// Helper: build a CredentialVerifier wired for refresh-token testing.
// ---------------------------------------------------------------------------

func newRefreshTokenVerifier(t *testing.T, enabled bool, repo database.RefreshTokenRepository) *CredentialVerifier {
	t.Helper()
	testKey := getECDSAKey()
	return &CredentialVerifier{
		signingKey:             testKey,
		signingAlgorithm:       "ES256",
		clock:                  mockClock{},
		tokenSigner:            mockTokenSigner{},
		host:                   "https://verifier.example.com",
		did:                    "did:key:verifier",
		jwtExpiration:          time.Hour,
		refreshTokenEnabled:    enabled,
		refreshTokenExpiration: 24 * time.Hour,
		refreshTokenRepo:       repo,
	}
}

// ---------------------------------------------------------------------------
// Tests: IsRefreshTokenEnabled
// ---------------------------------------------------------------------------

func TestIsRefreshTokenEnabled(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	t.Run("enabled", func(t *testing.T) {
		v := newRefreshTokenVerifier(t, true, newMockRefreshTokenRepo())
		assert.True(t, v.IsRefreshTokenEnabled())
	})

	t.Run("disabled", func(t *testing.T) {
		v := newRefreshTokenVerifier(t, false, nil)
		assert.False(t, v.IsRefreshTokenEnabled())
	})
}

// ---------------------------------------------------------------------------
// Tests: generateRefreshToken
// ---------------------------------------------------------------------------

func TestGenerateRefreshToken_Format(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	v := newRefreshTokenVerifier(t, true, newMockRefreshTokenRepo())
	token, err := v.generateRefreshToken()
	require.NoError(t, err)
	// 32 bytes → 43-character base64url (no padding).
	assert.Len(t, token, 43, "token should be 43 base64url chars (32 raw bytes)")
}

func TestGenerateRefreshToken_Unique(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	v := newRefreshTokenVerifier(t, true, newMockRefreshTokenRepo())
	seen := make(map[string]bool)
	const iterations = 100
	for i := 0; i < iterations; i++ {
		tok, err := v.generateRefreshToken()
		require.NoError(t, err)
		assert.False(t, seen[tok], "token collision at iteration %d", i)
		seen[tok] = true
	}
}

// ---------------------------------------------------------------------------
// Tests: CreateRefreshToken
// ---------------------------------------------------------------------------

func TestCreateRefreshToken_Success(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	repo := newMockRefreshTokenRepo()
	v := newRefreshTokenVerifier(t, true, repo)

	token, err := v.CreateRefreshToken(
		"client-1", "did:key:holder", "aud-1",
		[]string{"openid"}, []map[string]interface{}{{"role": "admin"}},
		false, "nonce-1",
	)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify it was stored in the mock repo.
	assert.Len(t, repo.tokens, 1)
	stored, ok := repo.tokens[token]
	require.True(t, ok)
	assert.Equal(t, "client-1", stored.ClientID)
	assert.Equal(t, "did:key:holder", stored.Subject)
	assert.Equal(t, "aud-1", stored.Audience)
	assert.False(t, stored.FlatClaims)
	assert.Equal(t, "nonce-1", stored.Nonce)
}

func TestCreateRefreshToken_Disabled(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	v := newRefreshTokenVerifier(t, false, nil)
	_, err := v.CreateRefreshToken(
		"client-1", "sub", "aud",
		[]string{}, []map[string]interface{}{}, false, "",
	)
	assert.ErrorIs(t, err, ErrorRefreshTokenDisabled)
}

func TestCreateRefreshToken_StoreError(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	repo := newMockRefreshTokenRepo()
	repo.storeErr = errors.New("db connection lost")
	v := newRefreshTokenVerifier(t, true, repo)

	_, err := v.CreateRefreshToken(
		"client-1", "sub", "aud",
		[]string{"openid"}, []map[string]interface{}{}, false, "",
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db connection lost")
}

// ---------------------------------------------------------------------------
// Tests: ExchangeRefreshToken
// ---------------------------------------------------------------------------

func TestExchangeRefreshToken_Success(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	repo := newMockRefreshTokenRepo()
	v := newRefreshTokenVerifier(t, true, repo)

	// Pre-populate a valid token in the repo.
	scopesJSON, _ := database.MarshalScopes([]string{"openid"})
	credsJSON, _ := database.MarshalCredentials([]map[string]interface{}{{"role": "admin"}})
	repo.tokens["original-token"] = database.RefreshTokenRow{
		Token:       "original-token",
		ClientID:    "client-1",
		Subject:     "did:key:holder",
		Audience:    "aud-1",
		Scopes:      scopesJSON,
		Credentials: credsJSON,
		FlatClaims:  false,
		Nonce:       "nonce-1",
		ExpiresAt:   9999999999, // far future
	}

	jwtString, expiration, newToken, err := v.ExchangeRefreshToken("original-token")
	require.NoError(t, err)
	assert.NotEmpty(t, jwtString, "should return a signed JWT")
	assert.Greater(t, expiration, int64(0), "expiration should be positive")
	assert.NotEmpty(t, newToken, "should return a rotated refresh token")
	assert.NotEqual(t, "original-token", newToken, "rotated token must differ")

	// The original token must have been consumed (single-use).
	_, ok := repo.tokens["original-token"]
	assert.False(t, ok, "original token must be deleted after exchange")

	// The new rotated token should be stored.
	_, ok = repo.tokens[newToken]
	assert.True(t, ok, "rotated token must be stored in repo")
}

func TestExchangeRefreshToken_Disabled(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	v := newRefreshTokenVerifier(t, false, nil)
	_, _, _, err := v.ExchangeRefreshToken("some-token")
	assert.ErrorIs(t, err, ErrorRefreshTokenDisabled)
}

func TestExchangeRefreshToken_NotFound(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	repo := newMockRefreshTokenRepo()
	v := newRefreshTokenVerifier(t, true, repo)

	_, _, _, err := v.ExchangeRefreshToken("nonexistent")
	assert.ErrorIs(t, err, ErrorRefreshTokenNotFound)
}

func TestExchangeRefreshToken_Expired(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	repo := newMockRefreshTokenRepo()
	v := newRefreshTokenVerifier(t, true, repo)

	// mockClock.Now() returns time.Unix(0, 0), so any expires_at < 0 is
	// expired. Use -1 to be safely in the past.
	scopesJSON, _ := database.MarshalScopes([]string{})
	credsJSON, _ := database.MarshalCredentials([]map[string]interface{}{})
	repo.tokens["expired-token"] = database.RefreshTokenRow{
		Token:       "expired-token",
		ClientID:    "client-1",
		Subject:     "sub",
		Audience:    "aud",
		Scopes:      scopesJSON,
		Credentials: credsJSON,
		ExpiresAt:   -1, // before epoch — mockClock returns 0
	}

	_, _, _, err := v.ExchangeRefreshToken("expired-token")
	assert.ErrorIs(t, err, ErrorRefreshTokenExpired)
}

func TestExchangeRefreshToken_Rotation_OldTokenInvalid(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	repo := newMockRefreshTokenRepo()
	v := newRefreshTokenVerifier(t, true, repo)

	scopesJSON, _ := database.MarshalScopes([]string{"openid"})
	credsJSON, _ := database.MarshalCredentials([]map[string]interface{}{{"role": "user"}})
	repo.tokens["tok-A"] = database.RefreshTokenRow{
		Token:       "tok-A",
		ClientID:    "client-1",
		Subject:     "did:key:holder",
		Audience:    "aud-1",
		Scopes:      scopesJSON,
		Credentials: credsJSON,
		Nonce:       "n1",
		ExpiresAt:   9999999999,
	}

	// Exchange tok-A → get tok-B.
	_, _, tokB, err := v.ExchangeRefreshToken("tok-A")
	require.NoError(t, err)

	// tok-A is now invalid.
	_, _, _, err = v.ExchangeRefreshToken("tok-A")
	assert.ErrorIs(t, err, ErrorRefreshTokenNotFound)

	// tok-B is valid and can be exchanged.
	_, _, tokC, err := v.ExchangeRefreshToken(tokB)
	require.NoError(t, err)
	assert.NotEmpty(t, tokC)
	assert.NotEqual(t, tokB, tokC)
}

func TestExchangeRefreshToken_RepoError(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	repo := newMockRefreshTokenRepo()
	repo.getErr = errors.New("database unavailable")
	v := newRefreshTokenVerifier(t, true, repo)

	_, _, _, err := v.ExchangeRefreshToken("any-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database unavailable")
}

// ---------------------------------------------------------------------------
// Tests: signToken
// ---------------------------------------------------------------------------

func TestSignToken_Success(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	v := newRefreshTokenVerifier(t, true, newMockRefreshTokenRepo())

	tok, err := v.generateJWT(
		[]map[string]interface{}{{"role": "admin"}},
		"did:key:holder", "aud-1", false, "nonce-1",
	)
	require.NoError(t, err)

	signed, err := v.signToken(tok)
	require.NoError(t, err)
	assert.NotEmpty(t, signed)

	// The signed string should be a valid JWT (three dot-separated parts).
	parts := 0
	for _, c := range signed {
		if c == '.' {
			parts++
		}
	}
	assert.Equal(t, 2, parts, "signed JWT should have 3 parts (2 dots)")
}

func TestSignToken_SigningError(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	sigErr := errors.New("signing failure")
	testKey := getECDSAKey()
	v := &CredentialVerifier{
		signingKey:       testKey,
		signingAlgorithm: "ES256",
		clock:            mockClock{},
		tokenSigner:      mockTokenSigner{signingError: sigErr},
		host:             "https://verifier.example.com",
		jwtExpiration:    time.Hour,
	}

	tok, err := v.generateJWT(
		[]map[string]interface{}{{"role": "admin"}},
		"sub", "aud", false, "",
	)
	require.NoError(t, err)

	_, err = v.signToken(tok)
	assert.ErrorIs(t, err, sigErr)
}

// ---------------------------------------------------------------------------
// Tests: SetRefreshTokenRepo (package-level function)
// ---------------------------------------------------------------------------

func TestSetRefreshTokenRepo(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	// Save and restore the global singleton.
	original := verifier
	defer func() { verifier = original }()

	repo := newMockRefreshTokenRepo()
	cv := &CredentialVerifier{}
	verifier = cv

	SetRefreshTokenRepo(repo)
	assert.Equal(t, repo, cv.refreshTokenRepo)
}

// TestSetRefreshTokenRepo_NilVerifier ensures no panic when the global
// verifier is nil.
func TestSetRefreshTokenRepo_NilVerifier(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	original := verifier
	defer func() { verifier = original }()

	verifier = nil
	// Should not panic.
	SetRefreshTokenRepo(newMockRefreshTokenRepo())
}

// ---------------------------------------------------------------------------
// Ensure mockRefreshTokenRepository satisfies the interface at compile time.
// ---------------------------------------------------------------------------

var _ database.RefreshTokenRepository = (*mockRefreshTokenRepository)(nil)

// Ensure unused imports for jwk are consumed (needed by newRefreshTokenVerifier).
var _ jwk.Key
