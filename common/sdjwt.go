package common

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/fiware/VCVerifier/logging"
)

const (
	SDJWTSeparator    = "~"
	SDJWTClaimSd      = "_sd"
	SDJWTClaimSdAlg   = "_sd_alg"
	SDJWTAlgSHA256    = "sha-256"
	SDJWTJWTSeparator = "."
)

var (
	ErrorInvalidDisclosure  = errors.New("invalid_sd_jwt_disclosure")
	ErrorMissingSdAlg       = errors.New("_sd_alg must be present in SD-JWT")
	ErrorUnsupportedSdAlg   = errors.New("unsupported _sd_alg")
	ErrorInvalidSDJWTFormat = errors.New("invalid SD-JWT format")
)

// ParseSDJWT parses an SD-JWT combined format token and returns the reconstructed claims.
// The combined format is: <issuer-JWT>~<disclosure1>~<disclosure2>~...~[<KB-JWT>]
// A plain JWT (without ~ separators) is also accepted per the SD-JWT spec.
//
// verifyFunc is called with the raw issuer JWT bytes and should return the payload if
// signature verification succeeds. If verifyFunc is nil, the payload is extracted without
// verification.
func ParseSDJWT(combined string, verifyFunc func([]byte) ([]byte, error)) (map[string]interface{}, error) {
	parts := strings.Split(combined, SDJWTSeparator)

	issuerJWT := parts[0]
	if issuerJWT == "" {
		logging.Log().Warn("SD-JWT has empty issuer JWT")
		return nil, ErrorInvalidSDJWTFormat
	}

	// Verify and extract the issuer JWT payload
	var payload []byte
	var err error
	if verifyFunc != nil {
		payload, err = verifyFunc([]byte(issuerJWT))
	} else {
		payload, err = extractPayload(issuerJWT)
	}
	if err != nil {
		logging.Log().Warnf("Failed to extract/verify SD-JWT payload: %v", err)
		return nil, err
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		logging.Log().Warnf("Failed to unmarshal SD-JWT payload: %v", err)
		return nil, err
	}

	// Plain JWT (no ~ separator) — return claims directly
	if len(parts) == 1 {
		return claims, nil
	}

	// Check _sd_alg — required when SD claims are present
	sdAlgRaw, hasAlg := claims[SDJWTClaimSdAlg]
	if !hasAlg {
		// If there are no _sd digests either, treat as plain JWT with trailing ~
		if _, hasSd := claims[SDJWTClaimSd]; !hasSd {
			return claims, nil
		}
		logging.Log().Warn("SD-JWT contains _sd but is missing _sd_alg")
		return nil, ErrorMissingSdAlg
	}
	sdAlg, ok := sdAlgRaw.(string)
	if !ok || sdAlg != SDJWTAlgSHA256 {
		logging.Log().Warnf("Unsupported _sd_alg: %v", sdAlgRaw)
		return nil, ErrorUnsupportedSdAlg
	}

	// Collect disclosures (skip empty strings — the trailing ~ produces one)
	var disclosures []string
	for _, d := range parts[1:] {
		if d != "" {
			// Skip key binding JWT (a JWT has dots)
			if !strings.Contains(d, SDJWTJWTSeparator) {
				disclosures = append(disclosures, d)
			}
		}
	}

	// Decode disclosures and build hash → (name, value) map
	hashToDisclosure := make(map[string]disclosureEntry)
	for _, d := range disclosures {
		name, value, err := decodeDisclosure(d)
		if err != nil {
			logging.Log().Warnf("Failed to decode SD-JWT disclosure: %v", err)
			return nil, err
		}
		h := hashDisclosure(d)
		hashToDisclosure[h] = disclosureEntry{Name: name, Value: value}
	}

	// Reconstruct claims from _sd digests
	reconstructClaims(claims, hashToDisclosure)

	// Clean up SD-JWT specific fields
	delete(claims, SDJWTClaimSd)
	delete(claims, SDJWTClaimSdAlg)

	return claims, nil
}

// decodeDisclosure decodes a base64url-encoded disclosure.
// A disclosure is a JSON array: [salt, claim_name, claim_value]
func decodeDisclosure(d string) (name string, value interface{}, err error) {
	decoded, err := base64.RawURLEncoding.DecodeString(d)
	if err != nil {
		return "", nil, ErrorInvalidDisclosure
	}

	var arr []interface{}
	if err := json.Unmarshal(decoded, &arr); err != nil {
		return "", nil, ErrorInvalidDisclosure
	}

	if len(arr) != 3 {
		return "", nil, ErrorInvalidDisclosure
	}

	name, ok := arr[1].(string)
	if !ok {
		return "", nil, ErrorInvalidDisclosure
	}

	return name, arr[2], nil
}

// hashDisclosure computes the SHA-256 hash of a disclosure (base64url-encoded).
func hashDisclosure(disclosure string) string {
	h := sha256.Sum256([]byte(disclosure))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

type disclosureEntry struct {
	Name  string
	Value interface{}
}

// reconstructClaims resolves _sd digests in the claims map using the provided disclosures.
func reconstructClaims(claims map[string]interface{}, hashToDisclosure map[string]disclosureEntry) {
	sdRaw, ok := claims[SDJWTClaimSd]
	if !ok {
		return
	}
	sdArray, ok := sdRaw.([]interface{})
	if !ok {
		return
	}

	for _, digest := range sdArray {
		digestStr, ok := digest.(string)
		if !ok {
			continue
		}
		if entry, found := hashToDisclosure[digestStr]; found {
			claims[entry.Name] = entry.Value
		}
	}
}

// extractPayload extracts the payload from a JWT without verification.
func extractPayload(jwt string) ([]byte, error) {
	parts := strings.SplitN(jwt, SDJWTJWTSeparator, 3)
	if len(parts) < 2 {
		logging.Log().Warn("Invalid JWT format: missing payload segment")
		return nil, ErrorInvalidSDJWTFormat
	}
	return base64.RawURLEncoding.DecodeString(parts[1])
}
