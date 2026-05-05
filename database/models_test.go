package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// RefreshTokenRow — basic struct instantiation tests
// ---------------------------------------------------------------------------

func TestRefreshTokenRow_Fields(t *testing.T) {
	tests := []struct {
		name       string
		row        RefreshTokenRow
		wantToken  string
		wantSuffix string
		wantClient string
		wantClaims string
		wantExp    int64
	}{
		{
			name: "all fields populated",
			row: RefreshTokenRow{
				Token:       "tok-abc",
				TokenSuffix: "k-abc",
				ClientID:    "client-1",
				Claims:      `{"iss":"https://verifier.example.com","sub":"did:key:holder"}`,
				ExpiresAt:   9999999999,
			},
			wantToken:  "tok-abc",
			wantSuffix: "k-abc",
			wantClient: "client-1",
			wantClaims: `{"iss":"https://verifier.example.com","sub":"did:key:holder"}`,
			wantExp:    9999999999,
		},
		{
			name: "empty suffix and claims",
			row: RefreshTokenRow{
				Token:     "tok-empty",
				ClientID:  "client-2",
				Claims:    "",
				ExpiresAt: 0,
			},
			wantToken:  "tok-empty",
			wantSuffix: "",
			wantClient: "client-2",
			wantClaims: "",
			wantExp:    0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantToken, tc.row.Token)
			assert.Equal(t, tc.wantSuffix, tc.row.TokenSuffix)
			assert.Equal(t, tc.wantClient, tc.row.ClientID)
			assert.Equal(t, tc.wantClaims, tc.row.Claims)
			assert.Equal(t, tc.wantExp, tc.row.ExpiresAt)
		})
	}
}
