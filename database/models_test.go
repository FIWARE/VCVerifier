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
		wantClient string
		wantJWT    string
		wantExp    int64
	}{
		{
			name: "all fields populated",
			row: RefreshTokenRow{
				Token:      "tok-abc",
				ClientID:   "client-1",
				JWTPayload: `{"iss":"https://verifier.example.com","sub":"did:key:holder"}`,
				ExpiresAt:  9999999999,
			},
			wantToken:  "tok-abc",
			wantClient: "client-1",
			wantJWT:    `{"iss":"https://verifier.example.com","sub":"did:key:holder"}`,
			wantExp:    9999999999,
		},
		{
			name: "empty JWT payload",
			row: RefreshTokenRow{
				Token:      "tok-empty",
				ClientID:   "client-2",
				JWTPayload: "",
				ExpiresAt:  0,
			},
			wantToken:  "tok-empty",
			wantClient: "client-2",
			wantJWT:    "",
			wantExp:    0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantToken, tc.row.Token)
			assert.Equal(t, tc.wantClient, tc.row.ClientID)
			assert.Equal(t, tc.wantJWT, tc.row.JWTPayload)
			assert.Equal(t, tc.wantExp, tc.row.ExpiresAt)
		})
	}
}
