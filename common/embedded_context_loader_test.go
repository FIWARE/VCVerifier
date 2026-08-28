package common

import (
	"errors"
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errFallbackCalled marks that the fallback loader was reached.
var errFallbackCalled = errors.New("fallback called")

// recordingLoader is a fallback loader that records the URL it was asked for.
type recordingLoader struct {
	requested string
}

// LoadDocument records the requested URL and always fails, so tests can tell
// delegation from an embedded hit.
func (r *recordingLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	r.requested = u
	return nil, errFallbackCalled
}

// TestEmbeddedContextLoader verifies that the security-relevant contexts are
// served from the binary and everything else is delegated.
func TestEmbeddedContextLoader(t *testing.T) {
	fallback := &recordingLoader{}
	loader, err := NewEmbeddedContextLoader(fallback)
	require.NoError(t, err)

	tests := []struct {
		name         string
		url          string
		wantEmbedded bool
	}{
		{name: "credentials_v1_embedded", url: ContextCredentialsV1, wantEmbedded: true},
		{name: "jws_2020_suite_embedded", url: ContextSecuritySuiteJWS2020, wantEmbedded: true},
		{name: "unknown_context_delegated", url: "https://example.com/custom/v1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fallback.requested = ""
			doc, err := loader.LoadDocument(tc.url)

			if tc.wantEmbedded {
				require.NoError(t, err)
				require.NotNil(t, doc)
				assert.Equal(t, tc.url, doc.DocumentURL)
				assert.Empty(t, fallback.requested, "an embedded context must not reach the fallback")
				return
			}
			assert.ErrorIs(t, err, errFallbackCalled)
			assert.Equal(t, tc.url, fallback.requested)
		})
	}
}

// TestEmbeddedContextLoaderWithoutFallback verifies the offline-only mode used
// by the tests: an unknown URL fails instead of hitting the network.
func TestEmbeddedContextLoaderWithoutFallback(t *testing.T) {
	loader, err := NewEmbeddedContextLoader(nil)
	require.NoError(t, err)

	_, err = loader.LoadDocument("https://example.com/custom/v1")
	assert.Error(t, err)
}
