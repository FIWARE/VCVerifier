package verifier

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	configModel "github.com/fiware/VCVerifier/config"
	"github.com/stretchr/testify/require"
)

func TestPKCEMethodValidationAndVerification(t *testing.T) {
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	digest := sha256.Sum256([]byte(verifier))
	s256Challenge := base64.RawURLEncoding.EncodeToString(digest[:])

	tests := []struct {
		name          string
		challenge     PKCEChallenge
		allowed       []string
		verifier      string
		wantErr       error
		wantVerifyErr error
	}{
		{
			name:      "S256 default method is accepted",
			challenge: PKCEChallenge{Value: s256Challenge, Method: PKCES256},
			allowed:   []string{PKCES256},
			verifier:  verifier,
		},
		{
			name:      "plain can be explicitly enabled",
			challenge: PKCEChallenge{Value: verifier, Method: PKCEPlain},
			allowed:   []string{PKCEPlain},
			verifier:  verifier,
		},
		{
			name:      "request method is case insensitive",
			challenge: PKCEChallenge{Value: s256Challenge, Method: "s256"},
			allowed:   []string{"s256"},
			verifier:  verifier,
		},
		{
			name:      "omitted method follows RFC default plain",
			challenge: PKCEChallenge{Value: verifier},
			allowed:   []string{PKCEPlain},
			verifier:  verifier,
		},
		{
			name:      "plain is rejected when only S256 is enabled",
			challenge: PKCEChallenge{Value: verifier, Method: PKCEPlain},
			allowed:   []string{PKCES256},
			wantErr:   ErrorInvalidPKCEMethod,
		},
		{
			name:          "incorrect verifier is rejected",
			challenge:     PKCEChallenge{Value: s256Challenge, Method: PKCES256},
			allowed:       []string{PKCES256},
			verifier:      verifier + "x",
			wantVerifyErr: ErrorInvalidPKCEVerifier,
		},
		{
			name:          "missing verifier is rejected",
			challenge:     PKCEChallenge{Value: s256Challenge, Method: PKCES256},
			allowed:       []string{PKCES256},
			wantVerifyErr: ErrorInvalidPKCEVerifier,
		},
		{
			name:      "method without challenge is rejected",
			challenge: PKCEChallenge{Method: PKCES256},
			allowed:   []string{PKCES256},
			wantErr:   ErrorInvalidPKCEChallenge,
		},
		{
			name:      "empty challenge parameter is rejected",
			challenge: PKCEChallenge{ChallengeSet: true},
			allowed:   []string{PKCES256},
			wantErr:   ErrorInvalidPKCEChallenge,
		},
		{
			name:      "empty method parameter is rejected",
			challenge: PKCEChallenge{Value: verifier, MethodSet: true},
			allowed:   []string{PKCEPlain},
			wantErr:   ErrorInvalidPKCEMethod,
		},
		{
			name:      "S256 challenge must be 43 characters",
			challenge: PKCEChallenge{Value: verifier, Method: PKCES256},
			allowed:   []string{PKCES256},
			wantErr:   ErrorInvalidPKCEChallenge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			normalized, validationErr := validatePKCEChallenge(tt.challenge, tt.allowed)
			if tt.wantErr != nil {
				require.Error(t, validationErr)
				require.True(t, errors.Is(validationErr, tt.wantErr), "got error %v, want %v", validationErr, tt.wantErr)
				return
			}
			require.NoError(t, validationErr)
			verifyErr := verifyPKCE(normalized, tt.verifier)
			if tt.wantVerifyErr != nil {
				require.ErrorIs(t, verifyErr, tt.wantVerifyErr)
				return
			}
			require.NoError(t, verifyErr)
		})
	}
}

func TestValidatePKCEConfigurationDefaultsToS256(t *testing.T) {
	methods, err := validatePKCEConfiguration(nil)
	require.NoError(t, err)
	require.Equal(t, []string{PKCES256}, methods)

	methods, err = validatePKCEConfiguration([]string{PKCES256, PKCEPlain, PKCES256})
	require.NoError(t, err)
	require.Equal(t, []string{PKCES256, PKCEPlain}, methods)

	methods, err = validatePKCEConfiguration([]string{"s256", "PLAIN"})
	require.NoError(t, err)
	require.Equal(t, []string{PKCES256, PKCEPlain}, methods)

	_, err = validatePKCEConfiguration([]string{"future-method"})
	require.ErrorIs(t, err, ErrorInvalidPKCEMethod)
}

func TestVerifyConfigDefaultsPKCEToS256AndRejectsUnknownMethods(t *testing.T) {
	cfg := configModel.Verifier{
		Did:            "did:key:verifier",
		TirAddress:     "https://tir.example",
		ValidationMode: "none",
		SupportedModes: []string{"urlEncoded"},
		RequestMode:    "urlEncoded",
	}
	require.NoError(t, verifyConfig(&cfg))
	require.Equal(t, []string{PKCES256}, cfg.AllowedCodeChallengeMethods)

	cfg.AllowedCodeChallengeMethods = []string{PKCEPlain}
	require.NoError(t, verifyConfig(&cfg))
	require.Equal(t, []string{PKCEPlain}, cfg.AllowedCodeChallengeMethods)

	cfg.AllowedCodeChallengeMethods = []string{"unsupported"}
	require.ErrorIs(t, verifyConfig(&cfg), ErrorInvalidPKCEMethod)
}
