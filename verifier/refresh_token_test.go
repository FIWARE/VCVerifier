package verifier

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/database"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRSAKeyBits is the RSA key size used in tests.
const testRSAKeyBits = 2048

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

func (m *mockRefreshTokenRepository) SetCleanupInterval(_ context.Context, _ time.Duration) {}

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

	// eyJpc3MiOiJ2ZXJpZmllciJ9 base64url-decodes to {"iss":"verifier"}
	token, err := v.CreateRefreshToken("client-1", "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ2ZXJpZmllciJ9.sig")
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify it was stored with raw claims, not the full signed JWT.
	assert.Len(t, repo.tokens, 1)
	stored, ok := repo.tokens[token]
	require.True(t, ok)
	assert.Equal(t, "client-1", stored.ClientID)
	assert.Equal(t, `{"iss":"verifier"}`, stored.Claims)
}

func TestCreateRefreshToken_Disabled(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	v := newRefreshTokenVerifier(t, false, nil)
	_, err := v.CreateRefreshToken("client-1", "some-jwt")
	assert.ErrorIs(t, err, ErrorRefreshTokenDisabled)
}

func TestCreateRefreshToken_StoreError(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	repo := newMockRefreshTokenRepo()
	repo.storeErr = errors.New("db connection lost")
	v := newRefreshTokenVerifier(t, true, repo)

	signedJWT := buildTestJWT(t, v)
	_, err := v.CreateRefreshToken("client-1", signedJWT)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db connection lost")
}

// ---------------------------------------------------------------------------
// Helper: build a signed JWT to use as stored JWTPayload in tests.
// ---------------------------------------------------------------------------

// buildTestJWT generates a signed JWT string using the test verifier's key
// and signer, suitable for storing as a RefreshTokenRow.JWTPayload.
func buildTestJWT(t *testing.T, v *CredentialVerifier) string {
	t.Helper()
	tok, err := v.generateJWT(
		[]map[string]interface{}{{"role": "admin"}},
		"did:key:holder", "aud-1", false, "nonce-1",
	)
	require.NoError(t, err)
	signed, err := v.signToken(tok)
	require.NoError(t, err)
	return signed
}

// ---------------------------------------------------------------------------
// Tests: ExchangeRefreshToken
// ---------------------------------------------------------------------------

func TestExchangeRefreshToken_Success(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	repo := newMockRefreshTokenRepo()
	v := newRefreshTokenVerifier(t, true, repo)

	signedJWT := buildTestJWT(t, v)
	seedToken, err := v.CreateRefreshToken("client-1", signedJWT)
	require.NoError(t, err)

	jwtString, expiration, newToken, err := v.ExchangeRefreshToken(seedToken)
	require.NoError(t, err)
	assert.NotEmpty(t, jwtString, "should return a signed JWT")
	assert.Greater(t, expiration, int64(0), "expiration should be positive")
	assert.NotEmpty(t, newToken, "should return a rotated refresh token")
	assert.NotEqual(t, seedToken, newToken, "rotated token must differ")

	// The original token must have been consumed (single-use).
	_, ok := repo.tokens[seedToken]
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
	repo.tokens["expired-token"] = database.RefreshTokenRow{
		Token:     "expired-token",
		ClientID:  "client-1",
		Claims:    "{}",
		ExpiresAt: -1, // before epoch — mockClock returns 0
	}

	_, _, _, err := v.ExchangeRefreshToken("expired-token")
	assert.ErrorIs(t, err, ErrorRefreshTokenExpired)
}

func TestExchangeRefreshToken_Rotation_OldTokenInvalid(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	repo := newMockRefreshTokenRepo()
	v := newRefreshTokenVerifier(t, true, repo)

	signedJWT := buildTestJWT(t, v)
	tokA, err := v.CreateRefreshToken("client-1", signedJWT)
	require.NoError(t, err)

	// Exchange tok-A → get tok-B.
	_, _, tokB, err := v.ExchangeRefreshToken(tokA)
	require.NoError(t, err)

	// tok-A is now invalid.
	_, _, _, err = v.ExchangeRefreshToken(tokA)
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
// Tests: ExchangeRefreshToken — table-driven (comprehensive)
// ---------------------------------------------------------------------------

// TestExchangeRefreshToken_TableDriven is a table-driven consolidation of all
// ExchangeRefreshToken scenarios, covering the plan's requirement for
// parameterized enabled/disabled cases and error paths.
func TestExchangeRefreshToken_TableDriven(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	type testCase struct {
		name            string
		enabled         bool
		// seedFunc seeds the repo after verifier creation and returns the input token.
		// When nil, staticInputToken is used and no seeding occurs.
		seedFunc        func(v *CredentialVerifier, repo *mockRefreshTokenRepository) string
		staticInputToken string
		repoGetErr      error
		expectErr       error
		expectErrSubstr string
		expectJWT       bool
		expectRotation  bool
	}

	helperVerifier := newRefreshTokenVerifier(t, true, newMockRefreshTokenRepo())
	validJWT := buildTestJWT(t, helperVerifier)

	tests := []testCase{
		{
			name:    "successful exchange returns new JWT and rotated token",
			enabled: true,
			seedFunc: func(v *CredentialVerifier, repo *mockRefreshTokenRepository) string {
				tok, err := v.CreateRefreshToken("client-1", validJWT)
				if err != nil {
					t.Fatalf("seed CreateRefreshToken: %v", err)
				}
				return tok
			},
			expectJWT:      true,
			expectRotation: true,
		},
		{
			name:             "disabled feature returns ErrorRefreshTokenDisabled",
			enabled:          false,
			staticInputToken: "anything",
			expectErr:        ErrorRefreshTokenDisabled,
		},
		{
			name:             "missing token returns ErrorRefreshTokenNotFound",
			enabled:          true,
			staticInputToken: "nonexistent",
			expectErr:        ErrorRefreshTokenNotFound,
		},
		{
			name:    "expired token returns ErrorRefreshTokenExpired",
			enabled: true,
			seedFunc: func(_ *CredentialVerifier, repo *mockRefreshTokenRepository) string {
				repo.tokens["tok-exp"] = database.RefreshTokenRow{
					Token: "tok-exp", ClientID: "c1", Claims: "{}", ExpiresAt: -1,
				}
				return "tok-exp"
			},
			expectErr: ErrorRefreshTokenExpired,
		},
		{
			name:             "repository error propagates directly",
			enabled:          true,
			repoGetErr:       errors.New("database unavailable"),
			staticInputToken: "any-token",
			expectErrSubstr:  "database unavailable",
		},
		{
			name:             "integrity failure causes ErrorRefreshTokenInvalidSignature",
			enabled:          true,
			repoGetErr:       database.ErrRefreshTokenInvalidIntegrity,
			staticInputToken: "tok-tampered",
			expectErr:        ErrorRefreshTokenInvalidSignature,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockRefreshTokenRepo()
			if tc.repoGetErr != nil {
				repo.getErr = tc.repoGetErr
			}

			v := newRefreshTokenVerifier(t, tc.enabled, repo)

			inputToken := tc.staticInputToken
			if tc.seedFunc != nil {
				inputToken = tc.seedFunc(v, repo)
			}

			jwtString, expiration, newToken, err := v.ExchangeRefreshToken(inputToken)

			if tc.expectErr != nil {
				assert.ErrorIs(t, err, tc.expectErr)
				return
			}
			if tc.expectErrSubstr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectErrSubstr)
				return
			}

			require.NoError(t, err)
			if tc.expectJWT {
				assert.NotEmpty(t, jwtString, "should return a signed JWT")
				assert.Greater(t, expiration, int64(0), "expiration should be positive")
			}
			if tc.expectRotation {
				assert.NotEmpty(t, newToken, "should return a rotated refresh token")
				assert.NotEqual(t, inputToken, newToken, "rotated token must differ from original")
				// Original consumed.
				_, ok := repo.tokens[inputToken]
				assert.False(t, ok, "original token must be deleted")
				// New token stored.
				_, ok = repo.tokens[newToken]
				assert.True(t, ok, "rotated token must be stored")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: ExchangeRefreshToken — multi-chain rotation
// ---------------------------------------------------------------------------

// TestExchangeRefreshToken_MultiChainRotation exercises a sequence of four
// successive refresh token exchanges, verifying that each rotation consumes
// the previous token, produces a distinct new one, and remains valid.
func TestExchangeRefreshToken_MultiChainRotation(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	repo := newMockRefreshTokenRepo()
	v := newRefreshTokenVerifier(t, true, repo)

	signedJWT := buildTestJWT(t, v)
	currentToken, err := v.CreateRefreshToken("client-chain", signedJWT)
	require.NoError(t, err)

	// chainLength is the number of successive rotations to perform.
	const chainLength = 4
	seenTokens := map[string]bool{currentToken: true}

	for i := 0; i < chainLength; i++ {
		jwtStr, exp, nextToken, err := v.ExchangeRefreshToken(currentToken)
		require.NoError(t, err, "rotation %d failed", i)
		assert.NotEmpty(t, jwtStr, "rotation %d should return JWT", i)
		assert.Greater(t, exp, int64(0), "rotation %d expiration", i)
		assert.False(t, seenTokens[nextToken], "rotation %d produced duplicate token", i)

		// Previous token consumed.
		_, _, _, err = v.ExchangeRefreshToken(currentToken)
		assert.ErrorIs(t, err, ErrorRefreshTokenNotFound, "rotation %d: old token should be consumed", i)

		seenTokens[nextToken] = true
		currentToken = nextToken
	}

	// Final token should still be valid for one more exchange.
	_, _, finalNext, err := v.ExchangeRefreshToken(currentToken)
	require.NoError(t, err, "final exchange should succeed")
	assert.NotEmpty(t, finalNext)
}

// ---------------------------------------------------------------------------
// Tests: CreateRefreshToken — expiration timestamp
// ---------------------------------------------------------------------------

// TestCreateRefreshToken_ExpirationTimestamp verifies that the stored refresh
// token's ExpiresAt field is computed as now + refreshTokenExpiration.
func TestCreateRefreshToken_ExpirationTimestamp(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	repo := newMockRefreshTokenRepo()
	// refreshTokenExpiration is set to 24h in newRefreshTokenVerifier.
	v := newRefreshTokenVerifier(t, true, repo)

	signedJWT := buildTestJWT(t, v)
	token, err := v.CreateRefreshToken("client-ts", signedJWT)
	require.NoError(t, err)

	stored, ok := repo.tokens[token]
	require.True(t, ok, "token should be stored in repo")

	// mockClock.Now() returns time.Unix(0, 0); refreshTokenExpiration = 24h.
	expectedExpiresAt := time.Unix(0, 0).Add(24 * time.Hour).Unix()
	assert.Equal(t, expectedExpiresAt, stored.ExpiresAt,
		"ExpiresAt should be mockClock.Now() + refreshTokenExpiration")
}

// ---------------------------------------------------------------------------
// Tests: CreateRefreshToken — table-driven with enabled/disabled
// ---------------------------------------------------------------------------

// TestCreateRefreshToken_TableDriven consolidates enabled/disabled and error
// scenarios in a single table-driven test.
func TestCreateRefreshToken_TableDriven(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	type testCase struct {
		name      string
		enabled   bool
		storeErr  error
		expectErr error
		expectOk  bool
	}

	tests := []testCase{
		{
			name:     "success when enabled",
			enabled:  true,
			expectOk: true,
		},
		{
			name:      "disabled returns ErrorRefreshTokenDisabled",
			enabled:   false,
			expectErr: ErrorRefreshTokenDisabled,
		},
		{
			name:     "store error propagates",
			enabled:  true,
			storeErr: errors.New("disk full"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockRefreshTokenRepo()
			if tc.storeErr != nil {
				repo.storeErr = tc.storeErr
			}
			v := newRefreshTokenVerifier(t, tc.enabled, repo)

			helperV := newRefreshTokenVerifier(t, true, newMockRefreshTokenRepo())
			jwt := buildTestJWT(t, helperV)
			token, err := v.CreateRefreshToken("client-1", jwt)

			if tc.expectErr != nil {
				assert.ErrorIs(t, err, tc.expectErr)
				assert.Empty(t, token)
				return
			}
			if tc.storeErr != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.storeErr.Error())
				assert.Empty(t, token)
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, token)
			assert.Len(t, repo.tokens, 1, "exactly one token stored")
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: signToken with RS256 algorithm
// ---------------------------------------------------------------------------

// TestSignToken_RS256 verifies that signToken works correctly with the RS256
// algorithm, covering the RS256 branch in the signToken switch statement.
func TestSignToken_RS256(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	// Generate an RSA key for RS256 signing.
	rsaKey, err := rsa.GenerateKey(rand.Reader, testRSAKeyBits)
	require.NoError(t, err)
	jwkKey, err := jwk.Import(rsaKey)
	require.NoError(t, err)

	v := &CredentialVerifier{
		signingKey:       jwkKey,
		signingAlgorithm: "RS256",
		clock:            mockClock{},
		tokenSigner:      mockTokenSigner{},
		host:             "https://verifier.example.com",
		jwtExpiration:    time.Hour,
	}

	tok, err := v.generateJWT(
		[]map[string]interface{}{{"role": "admin"}},
		"did:key:holder", "aud-1", false, "nonce-1",
	)
	require.NoError(t, err)

	signed, err := v.signToken(tok)
	require.NoError(t, err)
	assert.NotEmpty(t, signed)

	// Verify it has 3 parts (header.payload.signature).
	parts := 0
	for _, c := range signed {
		if c == '.' {
			parts++
		}
	}
	assert.Equal(t, 2, parts, "signed JWT should have 3 parts (2 dots)")
}

// ---------------------------------------------------------------------------
// Tests: ExchangeRefreshToken — rotation store failure
// ---------------------------------------------------------------------------

// TestExchangeRefreshToken_RotationStoreFailure covers the case where the
// initial exchange succeeds but creating the rotated refresh token fails.
func TestExchangeRefreshToken_RotationStoreFailure(t *testing.T) {
	logging.Configure(LOGGING_CONFIG)

	repo := newMockRefreshTokenRepo()
	v := newRefreshTokenVerifier(t, true, repo)

	signedJWT := buildTestJWT(t, v)
	seedToken, err := v.CreateRefreshToken("client-1", signedJWT)
	require.NoError(t, err)

	// After the seed succeeds, make subsequent stores fail so
	// the rotation step in ExchangeRefreshToken fails.
	repo.storeErr = errors.New("rotation store failed")

	_, _, _, err = v.ExchangeRefreshToken(seedToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rotate refresh token")
}

// ---------------------------------------------------------------------------
// Ensure mockRefreshTokenRepository satisfies the interface at compile time.
// ---------------------------------------------------------------------------

var _ database.RefreshTokenRepository = (*mockRefreshTokenRepository)(nil)

// Ensure unused imports for jwk are consumed (needed by newRefreshTokenVerifier).
var _ jwk.Key
