package did

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const (
	MethodWeb           = "web"
	wellKnownDIDPath    = "/.well-known/did.json"
	didDocumentFilename = "/did.json"
)

// WebVDR resolves did:web DIDs by fetching the DID document over HTTPS.
type WebVDR struct {
	HTTPClient *http.Client
}

// NewWebVDR creates a new did:web resolver.
func NewWebVDR() *WebVDR {
	return &WebVDR{HTTPClient: http.DefaultClient}
}

// Accept returns true for the "web" method.
func (w *WebVDR) Accept(method string) bool {
	return method == MethodWeb
}

// Read resolves a did:web DID by fetching the DID document from the web.
// See https://w3c-ccg.github.io/did-method-web/
func (w *WebVDR) Read(didStr string) (*DocResolution, error) {
	logging.Log().Debugf("Resolving did:web: %s", didStr)

	docURL, err := didWebToURL(didStr)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:web did --> %w", err)
	}

	logging.Log().Debugf("Fetching DID document from %s", docURL)

	resp, err := w.HTTPClient.Get(docURL)
	if err != nil {
		logging.Log().Infof("HTTP request failed for did:web %s at %s: %v", didStr, docURL, err)
		return nil, fmt.Errorf("error resolving did:web did --> http request unsuccessful --> %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logging.Log().Infof("Unexpected HTTP status %d when resolving did:web %s from %s", resp.StatusCode, didStr, docURL)
		return nil, fmt.Errorf("error resolving did:web did --> http status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error resolving did:web did --> reading body --> %w", err)
	}

	logging.Log().Debugf("Received DID document (%d bytes) for %s", len(body), didStr)

	doc, err := parseDIDDocument(body)
	if err != nil {
		logging.Log().Infof("Failed to parse DID document for %s: %v", didStr, err)
		return nil, fmt.Errorf("error resolving did:web did --> parsing document --> %w", err)
	}

	logging.Log().Debugf("Successfully resolved did:web %s with %d verification methods", didStr, len(doc.VerificationMethod))

	return &DocResolution{DIDDocument: doc}, nil
}

// didWebToURL converts a did:web DID to an HTTPS URL.
// did:web:example.com -> https://example.com/.well-known/did.json
// did:web:example.com:path:to:doc -> https://example.com/path/to/doc/did.json
func didWebToURL(didStr string) (string, error) {
	parts := strings.SplitN(didStr, ":", 3)
	if len(parts) < 3 {
		return "", fmt.Errorf("%w: %s", ErrInvalidDID, didStr)
	}

	// The method-specific-id is everything after "did:web:"
	methodSpecificID := parts[2]

	// Split on colons to get path segments
	segments := strings.Split(methodSpecificID, ":")

	// First segment is the host (percent-decoded)
	host, err := url.PathUnescape(segments[0])
	if err != nil {
		return "", fmt.Errorf("invalid host in did:web: %w", err)
	}

	var docPath string
	if len(segments) == 1 {
		docPath = wellKnownDIDPath
	} else {
		// Remaining segments become path components
		pathParts := make([]string, 0, len(segments)-1)
		for _, seg := range segments[1:] {
			decoded, err := url.PathUnescape(seg)
			if err != nil {
				return "", fmt.Errorf("invalid path segment in did:web: %w", err)
			}
			pathParts = append(pathParts, decoded)
		}
		docPath = "/" + strings.Join(pathParts, "/") + didDocumentFilename
	}

	return "https://" + host + docPath, nil
}

// parseDIDDocument parses a JSON DID document into our Doc type.
func parseDIDDocument(data []byte) (*Doc, error) {
	var raw struct {
		ID                 string            `json:"id"`
		VerificationMethod []json.RawMessage `json:"verificationMethod"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	doc := &Doc{ID: raw.ID}

	for i, vmRaw := range raw.VerificationMethod {
		vm, err := parseVerificationMethod(vmRaw)
		if err != nil {
			logging.Log().Infof("Failed to parse verification method %d in DID document %s: %v", i, raw.ID, err)
			return nil, err
		}
		doc.VerificationMethod = append(doc.VerificationMethod, *vm)
	}

	return doc, nil
}

// parseVerificationMethod parses a single verification method from JSON.
func parseVerificationMethod(data []byte) (*VerificationMethod, error) {
	var raw struct {
		ID                 string          `json:"id"`
		Type               string          `json:"type"`
		Controller         string          `json:"controller"`
		PublicKeyJwk       json.RawMessage `json:"publicKeyJwk,omitempty"`
		PublicKeyMultibase string          `json:"publicKeyMultibase,omitempty"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	vm := &VerificationMethod{
		ID:         raw.ID,
		Type:       raw.Type,
		Controller: raw.Controller,
	}

	if len(raw.PublicKeyJwk) > 0 {
		key, err := jwk.ParseKey(raw.PublicKeyJwk)
		if err != nil {
			logging.Log().Debugf("Failed to parse publicKeyJwk for verification method %s: %v", raw.ID, err)
			return nil, fmt.Errorf("failed to parse publicKeyJwk for %s: %w", raw.ID, err)
		}
		vm.jsonWebKey = key
		vm.Value = raw.PublicKeyJwk
		logging.Log().Debugf("Parsed JWK for verification method %s (type: %s)", raw.ID, raw.Type)
	} else if raw.PublicKeyMultibase != "" {
		vm.Value = []byte(raw.PublicKeyMultibase)
		logging.Log().Debugf("Stored multibase key for verification method %s (type: %s)", raw.ID, raw.Type)
	} else {
		logging.Log().Debugf("Verification method %s has no publicKeyJwk or publicKeyMultibase", raw.ID)
	}

	return vm, nil
}
