package common

import (
	"embed"
	"encoding/json"
	"fmt"

	"github.com/fiware/VCVerifier/logging"
	"github.com/piprate/json-gold/ld"
)

// embeddedContexts holds the vendored copies of the JSON-LD contexts that are
// security-relevant for Linked Data Proof verification. Serving them from the
// binary removes a network dependency from the signature-verification path:
// a failing or hijacked context host must never be able to change what a
// canonicalized document looks like.
//
//go:embed contexts/*.jsonld
var embeddedContexts embed.FS

// Paths of the vendored context files inside the embedded file system.
const (
	contextFileW3CVCV1 = "contexts/credentials-v1.jsonld"
	contextFileJWS2020 = "contexts/jws-2020-v1.jsonld"
)

// embeddedContextFiles maps context URLs to the vendored file that serves them.
// The paths are named constants rather than inline literals: a literal keyed by
// ContextCredentialsV1 reads to gosec as a hardcoded credential (G101), which
// it is not — these are public JSON-LD context URLs and file names.
var embeddedContextFiles = map[string]string{
	ContextCredentialsV1:        contextFileW3CVCV1,
	ContextSecuritySuiteJWS2020: contextFileJWS2020,
}

// EmbeddedContextLoader is an ld.DocumentLoader that serves a fixed set of
// well-known JSON-LD contexts from the binary and delegates everything else
// to a fallback loader.
type EmbeddedContextLoader struct {
	documents map[string]*ld.RemoteDocument
	fallback  ld.DocumentLoader
}

// NewEmbeddedContextLoader creates an EmbeddedContextLoader serving the
// vendored W3C credentials/v1 and JsonWebSignature2020 contexts. Any other
// URL is passed to fallback. Passing a nil fallback makes the loader reject
// every URL it does not have a vendored copy of.
func NewEmbeddedContextLoader(fallback ld.DocumentLoader) (*EmbeddedContextLoader, error) {
	documents := make(map[string]*ld.RemoteDocument, len(embeddedContextFiles))
	for contextURL, fileName := range embeddedContextFiles {
		raw, err := embeddedContexts.ReadFile(fileName)
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded context %s: %w", fileName, err)
		}
		var parsed interface{}
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, fmt.Errorf("failed to parse embedded context %s: %w", fileName, err)
		}
		documents[contextURL] = &ld.RemoteDocument{
			DocumentURL: contextURL,
			Document:    parsed,
		}
	}
	return &EmbeddedContextLoader{documents: documents, fallback: fallback}, nil
}

// LoadDocument returns the vendored context for u when one exists, otherwise
// it delegates to the fallback loader.
func (ecl *EmbeddedContextLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	if doc, hit := ecl.documents[u]; hit {
		return doc, nil
	}
	if ecl.fallback == nil {
		return nil, fmt.Errorf("no embedded context for %s and no fallback loader configured", u)
	}
	return ecl.fallback.LoadDocument(u)
}

// NewVerificationDocumentLoader combines the embedded contexts with a caching
// layer in front of remoteLoader. If the embedded contexts cannot be read the
// caching loader is returned on its own and the failure is logged, so a
// packaging problem degrades to the previous behaviour instead of preventing
// startup.
func NewVerificationDocumentLoader(cachingLoader ld.DocumentLoader) ld.DocumentLoader {
	embedded, err := NewEmbeddedContextLoader(cachingLoader)
	if err != nil {
		logging.Log().Errorf("Failed to initialize embedded JSON-LD contexts, falling back to remote resolution: %v", err)
		return cachingLoader
	}
	return embedded
}
