package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// buildSDJWT creates a test SD-JWT with the given payload claims and disclosures.
// Claims listed in sdClaims are moved to the _sd array and returned as disclosures.
func buildSDJWT(t *testing.T, claims map[string]interface{}, sdClaims []string, sign bool) string {
	t.Helper()

	// Build disclosures for selective claims
	var disclosures []string
	sdDigests := []interface{}{}
	for _, claimName := range sdClaims {
		val, ok := claims[claimName]
		if !ok {
			continue
		}
		delete(claims, claimName)

		disclosure := []interface{}{"test-salt", claimName, val}
		disclosureJSON, _ := json.Marshal(disclosure)
		encoded := base64.RawURLEncoding.EncodeToString(disclosureJSON)
		disclosures = append(disclosures, encoded)

		h := sha256.Sum256([]byte(encoded))
		digest := base64.RawURLEncoding.EncodeToString(h[:])
		sdDigests = append(sdDigests, digest)
	}

	claims["_sd"] = sdDigests
	claims["_sd_alg"] = "sha-256"

	payloadBytes, _ := json.Marshal(claims)

	var issuerJWT string
	if sign {
		privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		jwkKey, _ := jwk.Import(privKey)
		hdrs := jws.NewHeaders()
		if err := hdrs.Set(jws.AlgorithmKey, jwa.ES256()); err != nil {
			t.Fatalf("Failed to set hdrs Algorithm: %v", err)
		}
		if err := hdrs.Set("typ", "vc+sd-jwt"); err != nil {
			t.Fatalf("Failed to set hdrs typ: %v", err)
		}
		signed, err := jws.Sign(payloadBytes, jws.WithKey(jwa.ES256(), jwkKey, jws.WithProtectedHeaders(hdrs)))
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}
		issuerJWT = string(signed)
	} else {
		headerBytes, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "vc+sd-jwt"})
		issuerJWT = base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
			base64.RawURLEncoding.EncodeToString(payloadBytes) + ".fakesig"
	}

	// Build combined format: issuerJWT~disclosure1~disclosure2~...~
	combined := issuerJWT
	for _, d := range disclosures {
		combined += "~" + d
	}
	combined += "~" // trailing ~ per spec

	return combined
}

func TestParseSDJWT_Basic(t *testing.T) {
	claims := map[string]interface{}{
		"iss":   "did:key:test-issuer",
		"vct":   "TestCredential",
		"email": "test@example.com",
	}

	token := buildSDJWT(t, claims, []string{"email"}, false)

	result, err := ParseSDJWT(token, nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result["iss"] != "did:key:test-issuer" {
		t.Errorf("Expected iss=did:key:test-issuer, got %v", result["iss"])
	}
	if result["vct"] != "TestCredential" {
		t.Errorf("Expected vct=TestCredential, got %v", result["vct"])
	}
	if result["email"] != "test@example.com" {
		t.Errorf("Expected email=test@example.com, got %v", result["email"])
	}
	// _sd and _sd_alg should be removed
	if _, ok := result["_sd"]; ok {
		t.Error("_sd should be removed from result")
	}
	if _, ok := result["_sd_alg"]; ok {
		t.Error("_sd_alg should be removed from result")
	}
}

func TestParseSDJWT_MultipleDisclosures(t *testing.T) {
	claims := map[string]interface{}{
		"iss":       "did:key:test-issuer",
		"vct":       "TestCredential",
		"firstName": "Alice",
		"lastName":  "Smith",
		"age":       float64(30),
	}

	token := buildSDJWT(t, claims, []string{"firstName", "lastName", "age"}, false)

	result, err := ParseSDJWT(token, nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result["firstName"] != "Alice" {
		t.Errorf("Expected firstName=Alice, got %v", result["firstName"])
	}
	if result["lastName"] != "Smith" {
		t.Errorf("Expected lastName=Smith, got %v", result["lastName"])
	}
	if result["age"] != float64(30) {
		t.Errorf("Expected age=30, got %v", result["age"])
	}
}

func TestParseSDJWT_NoDisclosures(t *testing.T) {
	// SD-JWT with _sd array but no disclosures provided
	claims := map[string]interface{}{
		"iss":   "did:key:test-issuer",
		"vct":   "TestCredential",
		"email": "visible@example.com",
	}

	token := buildSDJWT(t, claims, []string{"email"}, false)
	// Remove the disclosure from the token (keep only issuer JWT + trailing ~)
	parts := token[:len(token)-1] // remove trailing ~
	idx := len(parts) - 1
	for idx >= 0 && parts[idx] != '~' {
		idx--
	}
	token = parts[:idx+1] // keep up to and including ~

	result, err := ParseSDJWT(token, nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// email should NOT be in result (disclosure not provided)
	if _, ok := result["email"]; ok {
		t.Error("email should not be in result when disclosure is not provided")
	}
}

func TestParseSDJWT_PlainJWT(t *testing.T) {
	// A plain JWT (no ~ separator) should be accepted per the SD-JWT spec
	result, err := ParseSDJWT("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.fakesig", nil)
	if err != nil {
		t.Fatalf("Expected no error for plain JWT, got %v", err)
	}
	if result["iss"] != "test" {
		t.Errorf("Expected iss=test, got %v", result["iss"])
	}
}

func TestParseSDJWT_MissingSdAlg(t *testing.T) {
	// JWT payload without _sd_alg
	headerBytes, _ := json.Marshal(map[string]string{"alg": "ES256"})
	payloadBytes, _ := json.Marshal(map[string]interface{}{"iss": "test", "_sd": []string{}})
	token := base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes) + ".fakesig~"

	_, err := ParseSDJWT(token, nil)
	if err != ErrorMissingSdAlg {
		t.Errorf("Expected ErrorMissingSdAlg, got %v", err)
	}
}

func TestParseSDJWT_WithVerification(t *testing.T) {
	claims := map[string]interface{}{
		"iss":   "did:key:test-issuer",
		"vct":   "TestCredential",
		"email": "test@example.com",
	}

	token := buildSDJWT(t, claims, []string{"email"}, true)

	// Extract the signing key from the JWT to verify
	issuerJWT := token[:len(token)-1] // remove trailing ~
	idx := len(issuerJWT) - 1
	for idx >= 0 && issuerJWT[idx] != '~' {
		idx--
	}
	issuerJWT = token[:idx] // just the JWT part (before first ~)
	parts := issuerJWT
	_ = parts

	// Use a mock verifyFunc that extracts payload
	verifyFunc := func(token []byte) ([]byte, error) {
		// Just extract payload without real verification for this test
		return extractPayload(string(token))
	}

	result, err := ParseSDJWT(token, verifyFunc)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result["email"] != "test@example.com" {
		t.Errorf("Expected email=test@example.com, got %v", result["email"])
	}
}

func TestParseSDJWT_VerificationFailure(t *testing.T) {
	claims := map[string]interface{}{
		"iss":   "did:key:test-issuer",
		"vct":   "TestCredential",
		"email": "test@example.com",
	}

	token := buildSDJWT(t, claims, []string{"email"}, false)

	verifyFunc := func(token []byte) ([]byte, error) {
		return nil, ErrorInvalidSDJWTFormat
	}

	_, err := ParseSDJWT(token, verifyFunc)
	if err != ErrorInvalidSDJWTFormat {
		t.Errorf("Expected ErrorInvalidSDJWTFormat, got %v", err)
	}
}

func TestParseSDJWT_InvalidDisclosure(t *testing.T) {
	headerBytes, _ := json.Marshal(map[string]string{"alg": "ES256"})
	payloadBytes, _ := json.Marshal(map[string]interface{}{
		"iss":     "test",
		"_sd":     []string{},
		"_sd_alg": "sha-256",
	})
	token := base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes) + ".fakesig~!!!invalid-base64!!!~"

	_, err := ParseSDJWT(token, nil)
	if err != ErrorInvalidDisclosure {
		t.Errorf("Expected ErrorInvalidDisclosure, got %v", err)
	}
}
