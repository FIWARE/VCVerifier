package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseCredentialStatus covers the shapes VCDM 2.0 allows for
// credentialStatus: a single object or an array of them.
func TestParseCredentialStatus(t *testing.T) {
	tests := []struct {
		name     string
		raw      interface{}
		wantNil  bool
		wantID   string
		wantType string
	}{
		{
			name:     "single object",
			raw:      map[string]interface{}{"id": "https://example.com/status/1#42", "type": "BitstringStatusListEntry"},
			wantID:   "https://example.com/status/1#42",
			wantType: "BitstringStatusListEntry",
		},
		{
			name: "array takes the first entry",
			raw: []interface{}{
				map[string]interface{}{"id": "https://example.com/status/1#42", "type": "BitstringStatusListEntry"},
				map[string]interface{}{"id": "https://example.com/status/2#7", "type": "BitstringStatusListEntry"},
			},
			wantID:   "https://example.com/status/1#42",
			wantType: "BitstringStatusListEntry",
		},
		{
			name: "array skips non-object entries",
			raw: []interface{}{
				"not-an-object",
				map[string]interface{}{"id": "https://example.com/status/2#7", "type": "StatusList2021Entry"},
			},
			wantID:   "https://example.com/status/2#7",
			wantType: "StatusList2021Entry",
		},
		{name: "absent", raw: nil, wantNil: true},
		{name: "wrong shape", raw: "https://example.com/status/1", wantNil: true},
		{name: "empty array", raw: []interface{}{}, wantNil: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status := ParseCredentialStatus(tc.raw)
			if tc.wantNil {
				assert.Nil(t, status)
				return
			}
			require.NotNil(t, status)
			assert.Equal(t, tc.wantID, status.ID)
			assert.Equal(t, tc.wantType, status.Type)
		})
	}
}

// TestParseCredentialJSONPopulatesStatus is the regression test for a silent
// fail-open: credentialStatus was listed in the standardKeys set, so it was
// neither copied into contents.Status nor kept as a custom field. Nothing
// errored - revocation checking simply had nothing to check.
func TestParseCredentialJSONPopulatesStatus(t *testing.T) {
	raw := []byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"id": "urn:uuid:test",
		"type": ["VerifiableCredential"],
		"issuer": "did:web:issuer.example.com",
		"credentialSubject": {"id": "did:web:subject.example.com"},
		"credentialStatus": {
			"id": "https://example.com/status/1#42",
			"type": "BitstringStatusListEntry",
			"statusPurpose": "revocation",
			"statusListIndex": "42"
		}
	}`)

	cred, err := ParseCredentialJSON(raw)
	require.NoError(t, err)

	status := cred.Contents().Status
	require.NotNil(t, status, "credentialStatus must reach contents.Status or revocation checking is disabled")
	assert.Equal(t, "https://example.com/status/1#42", status.ID)
	assert.Equal(t, "BitstringStatusListEntry", status.Type)
}
