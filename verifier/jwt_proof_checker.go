package verifier

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/eidas"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// httpsIssuerPrefix is the URL scheme prefix used to identify HTTPS-based credential issuers.
const httpsIssuerPrefix = "https://"

// JWSHeaderX5C is the JWS header parameter name for the X.509 certificate chain.
const JWSHeaderX5C = "x5c"

// DidElsiPrefix is the DID method prefix for did:elsi (Alastria's eIDAS-based DID method).
const DidElsiPrefix = "did:elsi:"

// oidOrganizationIdentifier is the ASN.1 OID 2.5.4.97 for the
// organizationIdentifier attribute in X.509 certificate subjects,
// as defined by ETSI EN 319 412-1.
var oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}

var ErrorNoSignatures = errors.New("no_signatures_in_jwt")
var ErrorNoDIDInJWT = errors.New("no_did_found_in_jwt")

// ErrorIssuerKeyMismatch is returned when the `kid` header names a DID other than
// the one in the `iss` claim. The key is resolved from the kid while the asserted
// identity is read from iss, so the two have to agree - otherwise the signature
// would authenticate a document attributed to someone else.
var ErrorIssuerKeyMismatch = errors.New("issuer_key_mismatch")
var ErrorNoCertInHeader = errors.New("no_certificate_found_in_jwt_header")
var ErrorCertHeaderEmpty = errors.New("cert_header_is_empty")
var ErrorPemDecodeFailed = errors.New("failed_to_decode_pem_from_header")

// ErrorHttpsIssuerNotSupported indicates that the JWT has an HTTPS-based issuer but
// no HttpsIssuerResolver is configured to handle it.
var ErrorHttpsIssuerNotSupported = errors.New("https_issuer_not_supported")

// ErrorEidasRequiredForElsi is returned when a did:elsi JWT is encountered
// but no eIDAS trust store is configured for certificate chain validation.
var ErrorEidasRequiredForElsi = errors.New("eidas_trust_store_required_for_did_elsi")

// ErrorIssuerValidationFailed is returned when the did:elsi DID's
// method-specific identifier does not match the organizationIdentifier
// (OID 2.5.4.97) in the issuer's X.509 certificate.
var ErrorIssuerValidationFailed = errors.New("did_elsi_issuer_validation_failed")

// ErrorElsiUntrustedCertificate is returned when the issuer's certificate
// does not chain up to any trusted CA in the eIDAS trust list.
var ErrorElsiUntrustedCertificate = errors.New("did_elsi_certificate_not_trusted")

// JWTProofChecker verifies JWT signatures using DID-resolved keys.
// Supports standard DID methods via the did.Registry, HTTPS-based
// issuer identifiers via HttpsIssuerResolver, and did:elsi issuers
// via eIDAS trust list validation of the X.509 certificate chain.
type JWTProofChecker struct {
	registry      *did.Registry
	httpsResolver HttpsIssuerResolver
	trustStore    *eidas.TrustStore
	// revocationChecker consults OCSP/CRL for the certificates on a did:elsi
	// chain. A nil checker disables revocation checking.
	revocationChecker *eidas.RevocationChecker
}

// NewJWTProofChecker creates a new JWTProofChecker that resolves signing
// keys through the given DID registry.
func NewJWTProofChecker(registry *did.Registry) *JWTProofChecker {
	return &JWTProofChecker{
		registry: registry,
	}
}

// WithHttpsResolver sets the HttpsIssuerResolver for verifying JWTs from HTTPS-based
// credential issuers. When set, JWTs with an iss claim starting with "https://" are
// verified using the resolver's discovered keys instead of DID resolution.
// Returns the checker to allow method chaining.
func (jpc *JWTProofChecker) WithHttpsResolver(resolver HttpsIssuerResolver) *JWTProofChecker {
	jpc.httpsResolver = resolver
	return jpc
}

// WithTrustStore sets the eIDAS TrustStore for verifying did:elsi JWTs.
// When set, JWTs from did:elsi issuers have their X.509 certificate chain
// validated against the trusted CAs in the EU Trusted Lists.
// Returns the checker to allow method chaining.
func (jpc *JWTProofChecker) WithTrustStore(store *eidas.TrustStore) *JWTProofChecker {
	jpc.trustStore = store
	return jpc
}

// WithRevocationChecker sets the revocation checker used when validating the
// certificate chain of a did:elsi JWT. When unset, no revocation checking is
// performed. Returns the checker to allow method chaining.
func (jpc *JWTProofChecker) WithRevocationChecker(checker *eidas.RevocationChecker) *JWTProofChecker {
	jpc.revocationChecker = checker
	return jpc
}

// VerifyJWT verifies the JWT signature using DID-resolved keys and returns the payload.
func (jpc *JWTProofChecker) VerifyJWT(token []byte) ([]byte, error) {
	payload, _, err := jpc.VerifyJWTAndReturnKey(token)
	return payload, err
}

// VerifyJWTAndReturnKey verifies the JWT signature and returns both the payload and the
// resolved signer key. The identity the signature is checked against is taken from the
// token envelope: the `kid` header, falling back to the `iss` claim.
//
// This is the right entry point for every token that names its signer in the envelope -
// classic jwt_vc credentials, JWT VPs, SD-JWTs. VC-JOSE-COSE tokens do not: their issuer
// and holder live in the payload document, so they go through VerifyJWTForIssuer instead.
func (jpc *JWTProofChecker) VerifyJWTAndReturnKey(token []byte) ([]byte, jwk.Key, error) {
	msg, err := jws.Parse(token)
	if err != nil {
		return nil, nil, err
	}

	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, nil, ErrorNoSignatures
	}

	headers := sigs[0].ProtectedHeaders()
	kid, _ := headers.KeyID()
	issFromPayload := extractIssFromPayload(msg.Payload())

	// The signing key is resolved from the kid, while the identity the document
	// asserts - the credential issuer, or the presentation holder - is read from the
	// iss claim. If both name a DID, they must be the same DID: otherwise a key the
	// signer generated themselves would authenticate a document attributed to
	// somebody else, since nothing downstream re-checks who actually signed it.
	//
	// A kid that is not a DID (a bare key id, a relative fragment) carries no
	// identity of its own, so it is not compared; the iss claim alone then decides.
	kidDID := extractDIDFromKid(kid)
	if kidDID != "" && issFromPayload != "" && kidDID != issFromPayload {
		logging.Log().Warnf("JWT rejected: the kid names DID %q but the iss claim names %q - the signing key is not the claimed issuer's",
			kidDID, issFromPayload)
		return nil, nil, ErrorIssuerKeyMismatch
	}

	// Determine issuer DID: prefer kid (contains the key reference), fall back to iss.
	issuerDID := kidDID
	if issuerDID == "" {
		issuerDID = issFromPayload
	}
	if issuerDID == "" {
		return nil, nil, ErrorNoDIDInJWT
	}

	// A did:elsi identity has to come from something the payload asserts, not from the
	// kid: the certificate carries the key, so a did:elsi kid is only a key reference
	// with no DID document behind it. The general kid/iss check above already rejects a
	// differing iss, so what remains here is a did:elsi kid with no iss claim at all.
	if IsDidElsi(issuerDID) && !IsDidElsi(issFromPayload) {
		logging.Log().Warnf("did:elsi dispatch triggered by kid (%s) but iss claim (%s) is not a did:elsi DID", issuerDID, issFromPayload)
		return nil, nil, ErrorNoDIDInJWT
	}

	return jpc.verifyForIssuer(token, msg, issuerDID)
}

// VerifyJWTForIssuer verifies the JWS against a key belonging to the given issuer
// identifier - one the caller read from the secured document itself rather than from a
// JOSE header or a registered claim - and returns the payload and the key that verified it.
//
// VC-JOSE-COSE (https://www.w3.org/TR/vc-jose-cose/) has no iss claim: in a vc+jwt the
// JWT payload *is* the credential, so the signer is its `issuer` property, and in a vp+jwt
// it is the presentation's `holder`. Neither is part of the envelope, so the envelope
// cannot say who the key must belong to. Callers read the identity out of the payload and
// pass it here, which keeps the "the key must belong to the claimed issuer" invariant in
// one place instead of giving the JOSE path its own answer to the same question.
//
// The caller must treat the payload it read for this purpose as unverified and use only
// the payload this method returns.
func (jpc *JWTProofChecker) VerifyJWTForIssuer(token []byte, issuer string) ([]byte, jwk.Key, error) {
	if issuer == "" {
		return nil, nil, ErrorNoDIDInJWT
	}

	msg, err := jws.Parse(token)
	if err != nil {
		return nil, nil, err
	}
	if len(msg.Signatures()) == 0 {
		return nil, nil, ErrorNoSignatures
	}

	return jpc.verifyForIssuer(token, msg, issuer)
}

// verifyForIssuer resolves a key for the given issuer identifier and verifies the JWS
// against it. It is the shared tail of VerifyJWTAndReturnKey and VerifyJWTForIssuer:
// the two differ only in where the issuer comes from, never in what is done with it.
//
// The kid still selects *which* of the issuer's keys to use, but a kid naming a different
// DID is rejected - that is the signature of a token signed with a key its claimed issuer
// does not control.
func (jpc *JWTProofChecker) verifyForIssuer(token []byte, msg *jws.Message, issuer string) ([]byte, jwk.Key, error) {
	headers := msg.Signatures()[0].ProtectedHeaders()
	kid, _ := headers.KeyID()

	if kidDID := extractDIDFromKid(kid); kidDID != "" && kidDID != issuer {
		logging.Log().Warnf("JWT rejected: the kid names DID %q but the document is attributed to %q - the signing key is not the claimed issuer's",
			kidDID, issuer)
		return nil, nil, ErrorIssuerKeyMismatch
	}

	// Handle did:elsi issuers via X.509 certificate chain + eIDAS trust list.
	if IsDidElsi(issuer) {
		return jpc.verifyElsiJWT(token, issuer, headers)
	}

	// Handle HTTPS-based issuer identifiers via metadata discovery
	if isHttpsIssuer(issuer) {
		return jpc.verifyHttpsIssuerJWT(token, issuer, kid, headers)
	}

	// Resolve DID → public key(s). Without a kid every verification method the
	// document declares is a candidate; verifyJWSWithCandidateKeys tries each.
	keys, err := jpc.resolveKeys(issuer, kid)
	if err != nil {
		return nil, nil, err
	}

	payload, verifiedKey, err := verifyJWSWithCandidateKeys(token, headers, keys)
	if err != nil {
		logging.Log().Warnf("JWT signature verification failed for %s: %v", issuer, err)
		return nil, nil, err
	}
	return payload, verifiedKey, nil
}

// isHttpsIssuer returns true if the issuer identifier is an HTTPS URL.
func isHttpsIssuer(issuer string) bool {
	return strings.HasPrefix(issuer, httpsIssuerPrefix)
}

// verifyHttpsIssuerJWT verifies a JWT whose issuer is an HTTPS URL by resolving the
// signing key via the configured HttpsIssuerResolver and then verifying the JWS signature.
func (jpc *JWTProofChecker) verifyHttpsIssuerJWT(token []byte, issuerURL string, kid string, headers jws.Headers) ([]byte, jwk.Key, error) {
	if jpc.httpsResolver == nil {
		logging.Log().Warnf("HTTPS issuer %s encountered but no HttpsIssuerResolver configured", issuerURL)
		return nil, nil, ErrorHttpsIssuerNotSupported
	}

	// The verification chain carries no context down to here yet, so the
	// resolver's own request timeout is the only bound on the lookup.
	keys, err := jpc.httpsResolver.ResolveIssuerKeys(context.Background(), issuerURL, kid)
	if err != nil {
		logging.Log().Warnf("Failed to resolve key for HTTPS issuer %s: %v", issuerURL, err)
		return nil, nil, err
	}

	payload, key, err := verifyJWSWithCandidateKeys(token, headers, keys)
	if err != nil {
		logging.Log().Warnf("JWT signature verification failed for HTTPS issuer %s: %v", issuerURL, err)
		return nil, nil, err
	}
	return payload, key, nil
}

// resolveKeys delegates to the shared ResolveCandidateKeysFromDID function, which
// narrows to a single verification method when a kid is present and offers all of
// them when it is not.
func (jpc *JWTProofChecker) resolveKeys(didStr, kid string) ([]jwk.Key, error) {
	return ResolveCandidateKeysFromDID(jpc.registry, didStr, kid)
}

// extractDIDFromKid extracts the DID from a kid header value.
// e.g., "did:web:example.com#key-1" → "did:web:example.com"
func extractDIDFromKid(kid string) string {
	if !strings.HasPrefix(kid, "did:") {
		return ""
	}
	if idx := strings.Index(kid, "#"); idx > 0 {
		return kid[:idx]
	}
	return kid
}

// extractIssFromPayload extracts the "iss" claim from a JWT payload.
func extractIssFromPayload(payload []byte) string {
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	iss, _ := claims[common.JWTClaimIss].(string)
	return iss
}

// extractX5CFromToken extracts the x5c certificate chain from a JWT token's
// protected header. Returns the base64-encoded certificate strings.
func extractX5CFromToken(token []byte) ([]string, error) {
	parts := strings.SplitN(string(token), ".", 3)
	if len(parts) < 2 {
		return nil, ErrorInvalidJWTFormat
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}
	x5cRaw, ok := header[JWSHeaderX5C]
	if !ok {
		return nil, ErrorNoCertInHeader
	}
	x5cArray, ok := x5cRaw.([]interface{})
	if !ok {
		return nil, ErrorCertHeaderEmpty
	}
	result := make([]string, len(x5cArray))
	for i, v := range x5cArray {
		s, ok := v.(string)
		if !ok {
			return nil, ErrorCertHeaderEmpty
		}
		result[i] = s
	}
	return result, nil
}

// parseCertificate decodes a base64-encoded DER X.509 certificate and parses it.
// Delegates to common.ParseBase64Certificate for the shared parsing logic.
func parseCertificate(certBase64 string) (*x509.Certificate, error) {
	cert, err := common.ParseBase64Certificate(certBase64)
	if err != nil {
		logging.Log().Warnf("Failed to parse certificate header: %v", err)
		return nil, ErrorPemDecodeFailed
	}
	return cert, nil
}

// validateElsiIssuer verifies that the did:elsi DID's method-specific
// identifier matches the organizationIdentifier (OID 2.5.4.97) in the X.509
// certificate's Subject. This binds the DID to the certificate holder.
func validateElsiIssuer(certificate *x509.Certificate, issuerDid string) error {
	// Extract the method-specific identifier from the DID
	// (everything after "did:elsi:").
	expectedOrgId := strings.TrimPrefix(issuerDid, DidElsiPrefix)
	if expectedOrgId == "" {
		return fmt.Errorf("%w: DID has empty method-specific identifier", ErrorIssuerValidationFailed)
	}

	// Extract organizationIdentifier (OID 2.5.4.97) from the certificate's Subject.
	orgId := extractOrganizationIdentifier(certificate)
	if orgId == "" {
		return fmt.Errorf("%w: certificate has no organizationIdentifier (OID 2.5.4.97)", ErrorIssuerValidationFailed)
	}

	if orgId != expectedOrgId {
		logging.Log().Warnf("did:elsi issuer mismatch: DID suffix %q does not match certificate organizationIdentifier %q",
			expectedOrgId, orgId)
		return fmt.Errorf("%w: DID suffix %q does not match certificate organizationIdentifier %q",
			ErrorIssuerValidationFailed, expectedOrgId, orgId)
	}

	return nil
}

// extractOrganizationIdentifier extracts the organizationIdentifier
// (OID 2.5.4.97) from an X.509 certificate's Subject. Returns an empty
// string if the OID is not present or cannot be parsed.
func extractOrganizationIdentifier(cert *x509.Certificate) string {
	for _, name := range cert.Subject.Names {
		if name.Type.Equal(oidOrganizationIdentifier) {
			if s, ok := name.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}

// verifyElsiJWT verifies a JWT from a did:elsi issuer by:
//  1. Checking the eIDAS trust store is configured.
//  2. Extracting and parsing the X.509 certificate chain from the x5c header.
//  3. Validating the DID's method-specific identifier against the certificate's
//     organizationIdentifier (OID 2.5.4.97).
//  4. Verifying the JWT signature using the certificate's public key.
//  5. Verifying the certificate chains to a trusted CA in the EU Trusted Lists.
func (jpc *JWTProofChecker) verifyElsiJWT(token []byte, issuerDID string, headers jws.Headers) ([]byte, jwk.Key, error) {
	if jpc.trustStore == nil {
		logging.Log().Warnf("did:elsi issuer %s encountered but no eIDAS trust store configured", issuerDID)
		return nil, nil, ErrorEidasRequiredForElsi
	}

	// Extract the x5c certificate chain from the JWT header.
	certChain, err := extractX5CFromToken(token)
	if err != nil {
		logging.Log().Warnf("Failed to extract x5c from did:elsi JWT: %v", err)
		return nil, nil, err
	}
	if len(certChain) == 0 {
		return nil, nil, ErrorNoCertInHeader
	}

	// Parse the leaf certificate.
	leafCert, err := parseCertificate(certChain[0])
	if err != nil {
		return nil, nil, err
	}

	// Validate the DID's method-specific identifier against the certificate.
	if err := validateElsiIssuer(leafCert, issuerDID); err != nil {
		return nil, nil, err
	}

	// Convert the leaf certificate's public key to a JWK for signature verification.
	pubKey, err := jwk.Import(leafCert.PublicKey)
	if err != nil {
		logging.Log().Warnf("Failed to import public key from did:elsi certificate: %v", err)
		return nil, nil, fmt.Errorf("failed to import certificate public key: %w", err)
	}

	// Verify the JWT signature using the certificate's public key.
	payload, verifiedKey, err := verifyJWSWithCandidateKeys(token, headers, []jwk.Key{pubKey})
	if err != nil {
		logging.Log().Warnf("JWT signature verification failed for did:elsi issuer %s: %v", issuerDID, err)
		return nil, nil, err
	}

	// Parse any intermediate certificates from the chain.
	var intermediates []*x509.Certificate
	for i := 1; i < len(certChain); i++ {
		intermediateCert, err := parseCertificate(certChain[i])
		if err != nil {
			logging.Log().Warnf("Failed to parse intermediate certificate at index %d: %v", i, err)
			return nil, nil, err
		}
		intermediates = append(intermediates, intermediateCert)
	}

	// Verify the certificate chains to a trusted CA via the eIDAS trust store.
	// Search all countries (empty country code) since did:elsi itself does not
	// carry per-credential country/qualified filters.
	if err := eidas.VerifyCertificateChain(leafCert, intermediates, jpc.trustStore, "", allCertificateServiceTypes,
		eidas.WithRevocationCheck(jpc.revocationChecker)); err != nil {
		logging.Log().Warnf("did:elsi certificate trust verification failed for %s: %v", issuerDID, err)
		return nil, nil, ErrorElsiUntrustedCertificate
	}

	logging.Log().Debugf("did:elsi JWT verified successfully for issuer %s", issuerDID)
	return payload, verifiedKey, nil
}

