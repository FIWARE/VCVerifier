package helpers

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// CreateJWTVC creates a signed JWT-VC (Verifiable Credential in JWT format).
// The credential contains the given type and subject claims, signed by the issuer.
func CreateJWTVC(issuer *TestIdentity, credType string, subject map[string]interface{}) (string, error) {
	return createJWTVCInternal(issuer, credType, subject, nil)
}

// CreateJWTVCWithHolder creates a signed JWT-VC with claim-based holder binding.
// The holderDID is added to the credentialSubject under the "holder" key.
func CreateJWTVCWithHolder(issuer *TestIdentity, credType string, subject map[string]interface{}, holderDID string) (string, error) {
	subjectWithHolder := copyMap(subject)
	subjectWithHolder["holder"] = holderDID
	return createJWTVCInternal(issuer, credType, subjectWithHolder, nil)
}

// CreateJWTVCWithCnf creates a signed JWT-VC with confirmation (cnf) holder binding.
// The holder's public key JWK is embedded in the credentialSubject.cnf.jwk field.
func CreateJWTVCWithCnf(issuer *TestIdentity, credType string, subject map[string]interface{}, holderJWK jwk.Key) (string, error) {
	// Serialize the holder's public JWK to a map for embedding.
	jwkBytes, err := json.Marshal(holderJWK)
	if err != nil {
		return "", fmt.Errorf("marshaling holder JWK: %w", err)
	}
	var jwkMap map[string]interface{}
	if err := json.Unmarshal(jwkBytes, &jwkMap); err != nil {
		return "", fmt.Errorf("unmarshaling holder JWK: %w", err)
	}

	cnf := map[string]interface{}{
		"jwk": jwkMap,
	}
	return createJWTVCInternal(issuer, credType, subject, cnf)
}

// createJWTVCInternal builds and signs a JWT-VC with optional cnf claim.
func createJWTVCInternal(issuer *TestIdentity, credType string, subject map[string]interface{}, cnf map[string]interface{}) (string, error) {
	now := time.Now()

	credentialSubject := copyMap(subject)
	if cnf != nil {
		credentialSubject["cnf"] = cnf
	}

	vcClaim := map[string]interface{}{
		"@context": []string{
			"https://www.w3.org/2018/credentials/v1",
		},
		"type":              []string{"VerifiableCredential", credType},
		"credentialSubject": credentialSubject,
	}

	builder := jwt.NewBuilder().
		Issuer(issuer.DID).
		IssuedAt(now).
		Expiration(now.Add(24 * time.Hour))
	builder.Claim("vc", vcClaim)

	token, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("building JWT-VC token: %w", err)
	}

	return signJWT(token, issuer)
}

// CreateVPToken creates a signed VP (Verifiable Presentation) JWT wrapping one or more VC JWTs.
// The nonce and audience are included for replay protection.
func CreateVPToken(holder *TestIdentity, nonce string, audience string, vcJWTs ...string) (string, error) {
	now := time.Now()

	vpClaim := map[string]interface{}{
		"@context":             []string{"https://www.w3.org/2018/credentials/v1"},
		"type":                 "VerifiablePresentation",
		"holder":               holder.DID,
		"verifiableCredential": vcJWTs,
	}

	builder := jwt.NewBuilder().
		Issuer(holder.DID).
		Audience([]string{audience}).
		IssuedAt(now).
		Expiration(now.Add(5 * time.Minute))

	if nonce != "" {
		builder.Claim("nonce", nonce)
	}
	builder.Claim("vp", vpClaim)

	token, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("building VP token: %w", err)
	}

	return signJWT(token, holder)
}

// CreateSDJWT creates an SD-JWT credential string.
// The issuer signs the JWT containing the claims, and disclosed claims are added as disclosures.
// For simplicity in integration tests, all claims are disclosed (no selective disclosure).
func CreateSDJWT(issuer *TestIdentity, vct string, claims map[string]interface{}) (string, error) {
	now := time.Now()

	builder := jwt.NewBuilder().
		Issuer(issuer.DID).
		IssuedAt(now).
		Expiration(now.Add(24 * time.Hour))
	builder.Claim("vct", vct)
	// _sd_alg is required by the verifier's SD-JWT parser even when no claims use selective disclosure.
	builder.Claim("_sd_alg", "sha-256")

	for k, v := range claims {
		builder.Claim(k, v)
	}

	token, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("building SD-JWT token: %w", err)
	}

	signed, err := signJWT(token, issuer)
	if err != nil {
		return "", err
	}

	// SD-JWT format: <issuer-jwt>~
	// The trailing ~ indicates no key binding JWT.
	// No disclosures are added since all claims are plaintext (no _sd hashes).
	return signed + "~", nil
}

// CreateVPWithSDJWT creates a signed VP JWT that contains SD-JWT credentials
// in the verifiableCredential array. The VP JWT is signed by the holder.
func CreateVPWithSDJWT(holder *TestIdentity, nonce string, audience string, sdJWTs ...string) (string, error) {
	// SD-JWT VPs use the same structure as regular VPs but with SD-JWT strings as credentials.
	return CreateVPToken(holder, nonce, audience, sdJWTs...)
}

// CreateVPTokenWithMismatchedSigner creates a VP JWT where the issuer/holder DID
// comes from claimedHolder, but the JWT is actually signed by actualSigner's key.
// This produces a VP whose signature cannot be verified against the claimed holder's public key.
func CreateVPTokenWithMismatchedSigner(claimedHolder, actualSigner *TestIdentity, nonce string, audience string, vcJWTs ...string) (string, error) {
	now := time.Now()

	vpClaim := map[string]interface{}{
		"@context":             []string{"https://www.w3.org/2018/credentials/v1"},
		"type":                 "VerifiablePresentation",
		"holder":               claimedHolder.DID,
		"verifiableCredential": vcJWTs,
	}

	builder := jwt.NewBuilder().
		Issuer(claimedHolder.DID).
		Audience([]string{audience}).
		IssuedAt(now).
		Expiration(now.Add(5 * time.Minute))

	if nonce != "" {
		builder.Claim("nonce", nonce)
	}
	builder.Claim("vp", vpClaim)

	token, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("building mismatched VP token: %w", err)
	}

	// Sign with actualSigner's key but use claimedHolder's kid in the header.
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, claimedHolder.KeyID); err != nil {
		return "", fmt.Errorf("setting kid header: %w", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), actualSigner.PrivateKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("signing mismatched VP: %w", err)
	}

	return string(signed), nil
}

// CreateDCQLResponse builds the JSON-encoded vp_token value for a DCQL response.
// The queryResponses map keys are DCQL credential query IDs and values are VP JWT strings.
func CreateDCQLResponse(queryResponses map[string]string) (string, error) {
	jsonBytes, err := json.Marshal(queryResponses)
	if err != nil {
		return "", fmt.Errorf("marshaling DCQL response: %w", err)
	}
	return string(jsonBytes), nil
}

// signJWT signs a JWT token with the identity's private key using ES256.
func signJWT(token jwt.Token, identity *TestIdentity) (string, error) {
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, identity.KeyID); err != nil {
		return "", fmt.Errorf("setting kid header: %w", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), identity.PrivateKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	return string(signed), nil
}

// copyMap creates a shallow copy of a map.
func copyMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}
