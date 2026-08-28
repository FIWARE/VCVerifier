package verifier

// credential_status_client.go implements the cached HTTP client responsible
// for fetching status-list resources referenced from a Verifiable
// Credential's status entry. It supports both:
//   - W3C Bitstring Status List / StatusList2021 credentials
//   - IETF OAuth 2.0 Token Status List JWTs (draft-ietf-oauth-status-list)
//
// The client keeps parsed results in an in-memory cache so the verifier
// does not re-fetch the same list on every presentation. TTL and HTTP
// timeout are parametrised through config.Verifier
// (StatusListCacheExpiry / StatusListHttpTimeout) — see config/config.go.

import (
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/did"
	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/patrickmn/go-cache"
)

// Named constants consumed by the status-list client. The values are kept in
// one place so reviewers can audit the Accept header and the cache cleanup
// cadence without hunting through the implementation.
const (
	// ContentTypeCredentialJson is the MIME type for JSON-LD encoded
	// Verifiable Credentials, per the W3C VC Data Model 2.0.
	ContentTypeCredentialJson = "application/vc+ld+json"

	// ContentTypeCredentialJWT is the MIME type for JWT-encoded Verifiable
	// Credentials, per the W3C VC Data Model 2.0.
	ContentTypeCredentialJWT = "application/vc+jwt"

	// AcceptHeaderStatusListCredential is the Accept header value sent when
	// fetching a W3C status-list credential. It advertises both JSON-LD and
	// JWT formats so issuers with strict content negotiation can respond
	// with either representation.
	AcceptHeaderStatusListCredential = ContentTypeCredentialJson + ", " + ContentTypeCredentialJWT

	// StatusListCacheCleanupMultiplier scales the configured cache expiry to
	// obtain the go-cache janitor cleanup interval. A value of 2 matches the
	// 2×expiry pattern used by the existing caches in common/cache.go and
	// common/caching_document_loader.go.
	StatusListCacheCleanupMultiplier = 2

	// statusListHTTPOKMin and statusListHTTPOKMaxExclusive define the
	// accepted success-status range for a status-list fetch. They are
	// module-private because no caller outside this file needs to inspect
	// the raw HTTP contract.
	statusListHTTPOKMin          = 200
	statusListHTTPOKMaxExclusive = 300
)

// Typed errors returned by the status-list client. Exported so callers can
// match them with errors.Is when the verifier's validation service needs to
// distinguish a network failure from a parse failure.
var (
	// ErrorStatusListHttpFailure is returned when the HTTP request to fetch
	// a status-list credential cannot be executed or returns a non-2xx
	// status code.
	ErrorStatusListHttpFailure = errors.New("status_list_http_failure")
	// ErrorStatusListUnparseable is returned when the fetched response body
	// is not a recognisable Verifiable Credential (neither a JSON-LD object
	// nor a decodable JWT).
	ErrorStatusListUnparseable = errors.New("status_list_unparseable")
	// ErrorStatusListJSONLDProofUnsupported is returned when a status list
	// credential is in JSON-LD format and no LDProofChecker is available to
	// verify the Linked Data Proof. This prevents MITM attacks on
	// status-list resolution.
	ErrorStatusListJSONLDProofUnsupported = errors.New("json_ld_status_list_proof_verification_not_supported")
	// ErrorStatusListJSONLDProofMissing is returned when a JSON-LD status
	// list credential does not contain a proof member, even though an
	// LDProofChecker is available.
	ErrorStatusListJSONLDProofMissing = errors.New("json_ld_status_list_credential_missing_proof")
	// ErrorStatusListJSONLDProofInvalid is returned when the Linked Data
	// Proof on a JSON-LD status list credential fails cryptographic
	// verification.
	ErrorStatusListJSONLDProofInvalid = errors.New("json_ld_status_list_credential_proof_invalid")
	// ErrorStatusListSubjectMismatch is returned when the `sub` claim of a
	// fetched IETF Token Status List JWT does not match the `uri` from the
	// credential's status reference, per draft-ietf-oauth-status-list §8.3
	// step 4a.
	ErrorStatusListSubjectMismatch = errors.New("status_list_subject_mismatch")

	// ErrorStatusListIssuerUnknown is returned when the credential that
	// references a status list carries no issuer at all. The status list can
	// then not be bound to anybody, and the proof on the list itself proves
	// nothing — an attacker who answers the status-list URL picks both its
	// issuer and its signing key. The check fails closed instead.
	ErrorStatusListIssuerUnknown = errors.New("status_list_referencing_issuer_unknown")
	// ErrorStatusListIssuerMismatch is returned when the status-list
	// credential was issued by a different entity than the credential whose
	// credentialStatus referenced it.
	ErrorStatusListIssuerMismatch = errors.New("status_list_issuer_mismatch")
	// ErrorStatusListExpired is returned when the `exp` claim of a fetched
	// IETF Token Status List JWT is in the past, per
	// draft-ietf-oauth-status-list §8.3 step 4c.
	ErrorStatusListExpired = errors.New("status_list_expired")
	// ErrorStatusListInvalidTyp is returned when the JWT `typ` header is
	// not `statuslist+jwt`, per draft-ietf-oauth-status-list §5.1.
	ErrorStatusListInvalidTyp = errors.New("status_list_invalid_typ")
)

const (
	// jwtClaimSub is the standard JWT `sub` (subject) claim key.
	jwtClaimSub = "sub"
	// jwtClaimIss is the standard JWT `iss` (issuer) claim key.
	jwtClaimIss = "iss"
	// jwtClaimExp is the standard JWT `exp` (expiration time) claim key.
	jwtClaimExp = "exp"
	// jwtClaimTTL is the IETF Token Status List `ttl` claim key, specifying
	// the maximum time in seconds the status list should be cached before
	// re-fetching, per draft-ietf-oauth-status-list §5.1.
	jwtClaimTTL = "ttl"
	// jwtHeaderTyp is the JWT header key for the token type.
	jwtHeaderTyp = "typ"
	// statusListJWTTyp is the required value of the `typ` JWT header for
	// IETF Token Status List JWTs, per draft-ietf-oauth-status-list §5.1.
	statusListJWTTyp = "statuslist+jwt"
)

// StatusListCredentialClient fetches and returns W3C Bitstring / StatusList2021
// credentials referenced from a VC's `credentialStatus` entry.
//
// Implementations are expected to be safe for concurrent use so the verifier
// can share a single client across requests.
type StatusListCredentialClient interface {
	// Fetch returns the status-list credential found at the given URL. It is
	// free to serve previously fetched responses from an internal cache.
	//
	// expectedIssuer is the issuer of the credential whose credentialStatus
	// pointed at this URL. Implementations must reject a status list that was
	// issued by anybody else, so that control over the network path to the
	// status list is not enough to clear revocation bits. Passing an empty
	// expectedIssuer skips the check.
	Fetch(url string, expectedIssuer string) (*common.Credential, error)
}

// CachingStatusListClient is the default StatusListCredentialClient
// implementation. It fetches W3C Bitstring Status List credentials in either
// JWT or JSON-LD encoding, uses patrickmn/go-cache to avoid repeated network
// calls for the same URL, and applies a configurable http.Client timeout to
// protect the verifier from slow status-list issuers.
//
// JSON-LD credentials are accepted only when an LDProofChecker is configured
// and the credential carries a valid Linked Data Proof created by its own
// issuer.
type CachingStatusListClient struct {
	httpClient     *http.Client
	cache          common.Cache
	expiry         time.Duration
	jwtVerifier    StatusListJWTVerifier
	ldProofChecker *LDProofChecker
}

// NewCachingStatusListClient constructs a CachingStatusListClient using the
// supplied HTTP timeout, cache TTL, optional JWT verifier, and optional
// LD-proof checker.
//
// Passing nil for jwtVerifier skips JWT signature verification (a warning is
// logged). Passing nil for ldProofChecker causes all JSON-LD status list
// credentials to be rejected (fail-closed).
//
// The cache janitor's cleanup interval is derived from cacheExpiry via
// StatusListCacheCleanupMultiplier so evicted entries are reaped on a cadence
// that matches the rest of the codebase.
func NewCachingStatusListClient(timeout time.Duration, cacheExpiry time.Duration, jwtVerifier StatusListJWTVerifier, ldProofChecker *LDProofChecker) *CachingStatusListClient {
	return &CachingStatusListClient{
		httpClient:     &http.Client{Timeout: timeout},
		cache:          cache.New(cacheExpiry, StatusListCacheCleanupMultiplier*cacheExpiry),
		expiry:         cacheExpiry,
		jwtVerifier:    jwtVerifier,
		ldProofChecker: ldProofChecker,
	}
}

// Fetch retrieves the status-list credential at url. A cached copy is
// returned when available; otherwise the credential is fetched, parsed with
// the existing VC parser, stored in the cache and returned.
//
// The issuer of the returned credential is checked against expectedIssuer —
// the issuer of the credential that referenced this status list. The issuer
// check is applied to cached entries as well, so a status list fetched for
// one issuer can never be reused to answer for another.
//
// The returned error is wrapped with ErrorStatusListHttpFailure for transport
// or non-2xx responses, with ErrorStatusListUnparseable when the body does
// not parse as a Verifiable Credential, and with
// ErrorStatusListIssuerMismatch when the status list belongs to a different
// issuer.
func (c *CachingStatusListClient) Fetch(url string, expectedIssuer string) (*common.Credential, error) {
	if cached, hit := c.cache.Get(url); hit {
		logging.Log().Debugf("Status-list cache hit for %s", url)
		cachedCredential := cached.(*common.Credential)
		if err := assertStatusListIssuer(cachedCredential, expectedIssuer, url); err != nil {
			return nil, err
		}
		return cachedCredential, nil
	}

	logging.Log().Debugf("Fetching W3C status-list credential from %s", url)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logging.Log().Debugf("Failed to create HTTP request for %s: %v", url, err)
		return nil, fmt.Errorf("%w: %v", ErrorStatusListHttpFailure, err)
	}
	req.Header.Set("Accept", AcceptHeaderStatusListCredential)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		logging.Log().Debugf("HTTP request to %s failed: %v", url, err)
		return nil, fmt.Errorf("%w: %v", ErrorStatusListHttpFailure, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < statusListHTTPOKMin || resp.StatusCode >= statusListHTTPOKMaxExclusive {
		logging.Log().Debugf("Unexpected HTTP status %d from %s", resp.StatusCode, url)
		return nil, fmt.Errorf("%w: unexpected status %d", ErrorStatusListHttpFailure, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.Log().Debugf("Failed to read response body from %s: %v", url, err)
		return nil, fmt.Errorf("%w: %v", ErrorStatusListHttpFailure, err)
	}

	logging.Log().Debugf("Received %d bytes from %s, parsing credential", len(body), url)
	cred, err := parseStatusListCredentialBody(body, c.jwtVerifier, c.ldProofChecker)
	if err != nil {
		logging.Log().Debugf("Failed to parse status-list credential from %s: %v", url, err)
		return nil, err
	}

	if err := assertStatusListIssuer(cred, expectedIssuer, url); err != nil {
		return nil, err
	}

	c.cache.Set(url, cred, c.expiry)
	logging.Log().Debugf("Cached status-list credential for %s", url)
	return cred, nil
}

// assertStatusListIssuer requires the status-list credential to have been
// issued by the issuer of the credential that referenced it. Verifying the
// signature on a status list only shows that the signer controls the key it
// names; without this binding an attacker who can answer the status-list URL
// can present a self-signed list with every revocation bit cleared.
//
// An empty expectedIssuer — a referencing credential with no issuer at all —
// is rejected rather than exempted. Skipping the only check that anchors the
// list to a known party would fail open on exactly the credentials that are
// least trustworthy.
func assertStatusListIssuer(cred *common.Credential, expectedIssuer string, url string) error {
	if expectedIssuer == "" {
		logging.Log().Warnf("Referencing credential has no issuer, cannot bind status list %s to an issuer", url)
		return fmt.Errorf("%w: status list %s", ErrorStatusListIssuerUnknown, url)
	}

	actualIssuer := ""
	if issuer := cred.Contents().Issuer; issuer != nil {
		actualIssuer = issuer.ID
	}
	if actualIssuer != expectedIssuer {
		logging.Log().Warnf("Status list %s is issued by %q but the referencing credential is issued by %q",
			url, actualIssuer, expectedIssuer)
		return fmt.Errorf("%w: status list issuer %q, credential issuer %q",
			ErrorStatusListIssuerMismatch, actualIssuer, expectedIssuer)
	}
	return nil
}

// parseStatusListCredentialBody decodes a status-list credential response
// body into a *common.Credential.
//
// Two transport encodings are handled:
//   - JSON-LD: a response body starting with `{` is accepted when an
//     LDProofChecker is provided and the credential carries a Linked Data
//     Proof created by its own issuer. Without a checker or without a proof
//     the credential is rejected (fail-closed). Note that the proof alone
//     only establishes who signed the list — binding it to the credential
//     that referenced it is done separately, in Fetch.
//   - JWT: any other non-empty body is treated as a JWS. When a
//     StatusListJWTVerifier is provided the signature is verified;
//     otherwise a warning is logged but parsing proceeds.
//
// Parse failures are wrapped with ErrorStatusListUnparseable; JSON-LD
// rejections use ErrorStatusListJSONLDProofUnsupported (no checker),
// ErrorStatusListJSONLDProofMissing (no proof member), or
// ErrorStatusListJSONLDProofInvalid (proof verification failed).
// Callers can distinguish failure types with errors.Is.
func parseStatusListCredentialBody(body []byte, jwtVerifier StatusListJWTVerifier, ldProofChecker *LDProofChecker) (*common.Credential, error) {
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) == 0 {
		logging.Log().Debug("Status-list credential response body is empty")
		return nil, fmt.Errorf("%w: empty response body", ErrorStatusListUnparseable)
	}

	if trimmed[0] == '{' {
		return parseJSONLDStatusListCredential([]byte(trimmed), ldProofChecker)
	}

	logging.Log().Debug("Parsing status-list credential as JWT")
	if jwtVerifier != nil {
		if _, err := jwtVerifier.VerifyStatusListJWT([]byte(trimmed)); err != nil {
			logging.Log().Debugf("W3C status-list JWT signature verification failed: %v", err)
			return nil, fmt.Errorf("%w: %v", ErrorStatusListUnparseable, err)
		}
		logging.Log().Debug("W3C status-list JWT signature verified")
	} else {
		logging.Log().Warn("No JWT verifier configured for W3C status list — skipping signature verification")
	}
	cred, err := parseUnsignedJWTCredential(trimmed)
	if err != nil {
		logging.Log().Debugf("JWT credential parse failed: %v", err)
		return nil, fmt.Errorf("%w: %v", ErrorStatusListUnparseable, err)
	}
	return cred, nil
}

// parseJSONLDStatusListCredential parses and verifies a JSON-LD encoded
// status list credential. If ldProofChecker is nil, the credential is rejected
// (fail-closed). If the credential does not carry a proof member, it is also
// rejected. Otherwise the Linked Data Proof is cryptographically verified
// against the credential's own issuer.
func parseJSONLDStatusListCredential(body []byte, ldProofChecker *LDProofChecker) (*common.Credential, error) {
	if ldProofChecker == nil {
		logging.Log().Warn("No LDProofChecker configured — rejecting JSON-LD status list credential")
		return nil, fmt.Errorf("%w: JSON-LD status list credentials cannot be verified without LD-proof support",
			ErrorStatusListJSONLDProofUnsupported)
	}

	// Parse the body as a JSON map to extract the proof and credential fields.
	var docMap map[string]interface{}
	if err := json.Unmarshal(body, &docMap); err != nil {
		logging.Log().Debugf("JSON-LD status list credential is not valid JSON: %v", err)
		return nil, fmt.Errorf("%w: invalid JSON: %v", ErrorStatusListUnparseable, err)
	}

	// Extract and parse the proof member.
	proofRaw, hasProof := docMap[common.VPKeyProof]
	if !hasProof || proofRaw == nil {
		logging.Log().Warn("JSON-LD status list credential has no proof — rejecting")
		return nil, fmt.Errorf("%w: credential does not contain a proof member",
			ErrorStatusListJSONLDProofMissing)
	}

	proofs, err := common.ParseLDProofs(proofRaw)
	if err != nil {
		logging.Log().Debugf("Failed to parse proof on JSON-LD status list credential: %v", err)
		return nil, fmt.Errorf("%w: %v", ErrorStatusListJSONLDProofInvalid, err)
	}
	if len(proofs) == 0 {
		logging.Log().Warn("JSON-LD status list credential proof array is empty — rejecting")
		return nil, fmt.Errorf("%w: credential proof array is empty",
			ErrorStatusListJSONLDProofMissing)
	}

	// Strip the proof from the document for canonicalization.
	delete(docMap, common.VPKeyProof)
	docBytes, err := json.Marshal(docMap)
	if err != nil {
		logging.Log().Debugf("Failed to marshal proof-stripped JSON-LD status list credential: %v", err)
		return nil, fmt.Errorf("%w: %v", ErrorStatusListUnparseable, err)
	}

	// Verify each proof against the issuer the status list itself claims.
	statusListIssuer := extractStatusListIssuer(docMap)
	for i, proof := range proofs {
		if verifyErr := ldProofChecker.VerifyCredential(docBytes, proof, statusListIssuer); verifyErr != nil {
			logging.Log().Debugf("JSON-LD status list credential proof %d verification failed: %v", i, verifyErr)
			return nil, fmt.Errorf("%w: proof %d: %v", ErrorStatusListJSONLDProofInvalid, i, verifyErr)
		}
	}
	logging.Log().Debug("JSON-LD status list credential proof(s) verified successfully")

	// Parse the credential structure. Re-add the proof to the map so
	// parseJSONLDCredential can attach it to the resulting Credential.
	docMap[common.VPKeyProof] = proofRaw
	cred, err := parseJSONLDCredential(docMap)
	if err != nil {
		logging.Log().Debugf("Failed to parse JSON-LD status list credential fields: %v", err)
		return nil, fmt.Errorf("%w: %v", ErrorStatusListUnparseable, err)
	}
	return cred, nil
}

// extractStatusListIssuer reads the `issuer` member of a raw status-list
// credential, accepting both the string and the object (`{"id": ...}`) form
// defined by the VC data model.
func extractStatusListIssuer(docMap map[string]interface{}) string {
	switch issuer := docMap[common.VCKeyIssuer].(type) {
	case string:
		return issuer
	case map[string]interface{}:
		if id, ok := issuer[common.JSONLDKeyID].(string); ok {
			return id
		}
	}
	return ""
}

// Compile-time assertion that CachingStatusListClient satisfies the public
// interface. This protects callers who type against StatusListCredentialClient
// from accidental signature drift.
var _ StatusListCredentialClient = (*CachingStatusListClient)(nil)

// ---------------------------------------------------------------------------
// IETF Token Status List client
// ---------------------------------------------------------------------------

// IETFStatusListClient fetches IETF OAuth 2.0 Token Status List JWTs from
// the URI declared in a credential's `status.status_list.uri` field.
//
// The response is a JWT with Content-Type `application/statuslist+jwt`,
// optionally gzip-compressed (Content-Encoding: gzip). The JWT payload
// contains `status_list.bits` and `status_list.lst` — the latter being a
// base64url-encoded, zlib-compressed bitstring.
type IETFStatusListClient interface {
	// FetchIETF fetches and returns the parsed IETF status list from the
	// given URI. Implementations may cache results internally.
	//
	// expectedIssuer is the issuer of the credential that referenced the
	// list; the `iss` claim of the status-list JWT must match it. Passing an
	// empty expectedIssuer is rejected — see assertIETFStatusListIssuer.
	FetchIETF(uri string, expectedIssuer string) (*common.IETFStatusList, error)

	// InvalidateIETF removes a cached status list entry so the next
	// FetchIETF call retrieves a fresh copy from the origin.
	InvalidateIETF(uri string)
}

// StatusListJWTVerifier verifies the signature of an IETF Token Status List
// JWT and returns the verified payload bytes. Implementations may extract
// the verification key from the JWT header (e.g. x5c certificate chain) or
// resolve it externally (e.g. via DID resolution).
type StatusListJWTVerifier interface {
	// VerifyStatusListJWT verifies the JWT signature and returns the payload.
	VerifyStatusListJWT(jwtBytes []byte) (payload []byte, err error)
}

// StatusListJWTVerifierImpl verifies IETF Token Status List JWTs using two
// strategies, tried in order:
//
//  1. If the JWT payload contains an `iss` claim that is a DID, the public
//     key is resolved from the DID document via the configured DID registry.
//  2. Otherwise, if the JWT header carries an `x5c` certificate chain, the
//     public key is extracted from the leaf certificate.
//
// This two-step approach covers both spec-compliant issuers (iss-based) and
// legacy/transitional deployments that only embed an x5c header.
type StatusListJWTVerifierImpl struct {
	registry *did.Registry
}

// NewStatusListJWTVerifier constructs a StatusListJWTVerifierImpl backed by
// the given DID registry. The registry must support the DID methods used by
// status list issuers (typically did:web and did:key).
func NewStatusListJWTVerifier(registry *did.Registry) *StatusListJWTVerifierImpl {
	return &StatusListJWTVerifierImpl{registry: registry}
}

// VerifyStatusListJWT parses the JWS and verifies the signature. It first
// attempts iss-based DID key resolution; when no iss claim is present it
// falls back to x5c certificate chain verification.
func (v *StatusListJWTVerifierImpl) VerifyStatusListJWT(jwtBytes []byte) ([]byte, error) {
	logging.Log().Debug("Verifying status list JWT signature")
	msg, err := jws.Parse(jwtBytes)
	if err != nil {
		logging.Log().Debugf("JWS parse failed: %v", err)
		return nil, fmt.Errorf("%w: JWS parse failed: %v", ErrorStatusListUnparseable, err)
	}

	sigs := msg.Signatures()
	if len(sigs) == 0 {
		logging.Log().Debug("Status list JWT has no signatures")
		return nil, fmt.Errorf("%w: no signatures in status list JWT", ErrorStatusListUnparseable)
	}

	headers := sigs[0].ProtectedHeaders()
	alg, _ := headers.Algorithm()

	issuerDID := extractIssFromPayload(msg.Payload())
	if issuerDID != "" {
		logging.Log().Debugf("Status list JWT has iss claim %s, verifying via DID resolution", issuerDID)
		return v.verifyWithISS(jwtBytes, msg, alg, issuerDID)
	}

	logging.Log().Debug("Status list JWT has no iss claim, falling back to x5c verification")
	return v.verifyWithX5C(jwtBytes, headers, alg)
}

// verifyWithISS resolves the public key from the iss DID and verifies the
// JWT signature.
func (v *StatusListJWTVerifierImpl) verifyWithISS(jwtBytes []byte, msg *jws.Message, alg jwa.SignatureAlgorithm, issuerDID string) ([]byte, error) {
	kid, _ := msg.Signatures()[0].ProtectedHeaders().KeyID()

	key, err := v.resolveKeyFromDID(issuerDID, kid)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to resolve key for %s: %v", ErrorStatusListUnparseable, issuerDID, err)
	}

	payload, err := jws.Verify(jwtBytes, jws.WithKey(alg, key))
	if err != nil {
		return nil, fmt.Errorf("%w: status list JWT signature verification failed for %s: %v", ErrorStatusListUnparseable, issuerDID, err)
	}

	logging.Log().Debugf("Status list JWT signature verified via iss DID %s", issuerDID)
	return payload, nil
}

// verifyWithX5C extracts the public key from the x5c certificate chain in
// the JWT header and verifies the signature.
func (v *StatusListJWTVerifierImpl) verifyWithX5C(jwtBytes []byte, headers jws.Headers, alg jwa.SignatureAlgorithm) ([]byte, error) {
	chain, hasX5C := headers.X509CertChain()
	if !hasX5C || chain == nil || chain.Len() == 0 {
		return nil, fmt.Errorf("%w: status list JWT has neither iss claim nor x5c header", ErrorStatusListUnparseable)
	}

	leafB64, ok := chain.Get(0)
	if !ok {
		return nil, fmt.Errorf("%w: x5c chain is empty", ErrorStatusListUnparseable)
	}

	leafDER, err := base64.StdEncoding.DecodeString(string(leafB64))
	if err != nil {
		return nil, fmt.Errorf("%w: x5c leaf base64 decode failed: %v", ErrorStatusListUnparseable, err)
	}

	cert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("%w: x5c leaf certificate parse failed: %v", ErrorStatusListUnparseable, err)
	}

	pubKey, err := jwk.Import(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: x5c public key import failed: %v", ErrorStatusListUnparseable, err)
	}

	payload, err := jws.Verify(jwtBytes, jws.WithKey(alg, pubKey))
	if err != nil {
		return nil, fmt.Errorf("%w: status list JWT x5c signature verification failed: %v", ErrorStatusListUnparseable, err)
	}

	logging.Log().Debug("Status list JWT signature verified via x5c certificate chain")
	return payload, nil
}

// resolveKeyFromDID resolves the DID document and finds the verification
// method matching the given kid. When kid is empty, the first verification
// method with a JWK key is returned.
func (v *StatusListJWTVerifierImpl) resolveKeyFromDID(issuerDID, kid string) (interface{}, error) {
	docRes, err := v.registry.Resolve(issuerDID)
	if err != nil {
		logging.Log().Warnf("Failed to resolve DID %s for status list verification: %v", issuerDID, err)
		return nil, err
	}

	for _, vm := range docRes.DIDDocument.VerificationMethod {
		if kid != "" && !compareVerificationMethod(kid, vm.ID) {
			logging.Log().Debugf("Skipping verification method %s (does not match kid %s)", vm.ID, kid)
			continue
		}
		key := vm.JSONWebKey()
		if key != nil {
			logging.Log().Debugf("Resolved verification key from DID %s (method=%s)", issuerDID, vm.ID)
			return key, nil
		}
	}

	logging.Log().Warnf("No matching verification method for status list issuer %s (kid=%s)", issuerDID, kid)
	return nil, ErrorNoVerificationKey
}

// Compile-time assertion.
var _ StatusListJWTVerifier = (*StatusListJWTVerifierImpl)(nil)

// CachingIETFStatusListClient is the default IETFStatusListClient
// implementation with in-memory caching and JWT signature verification.
type CachingIETFStatusListClient struct {
	httpClient  *http.Client
	cache       common.Cache
	expiry      time.Duration
	jwtVerifier StatusListJWTVerifier
	clock       common.Clock
}

// NewCachingIETFStatusListClient constructs a CachingIETFStatusListClient.
// The jwtVerifier is used to verify the signature of fetched status list
// JWTs. When nil, JWT signatures are not verified (not recommended for
// production). The clock is used to check the `exp` claim; pass nil to use
// the real system clock.
func NewCachingIETFStatusListClient(timeout time.Duration, cacheExpiry time.Duration, jwtVerifier StatusListJWTVerifier, clock common.Clock) *CachingIETFStatusListClient {
	if clock == nil {
		clock = common.RealClock{}
	}
	return &CachingIETFStatusListClient{
		httpClient:  &http.Client{Timeout: timeout},
		cache:       cache.New(cacheExpiry, StatusListCacheCleanupMultiplier*cacheExpiry),
		expiry:      cacheExpiry,
		jwtVerifier: jwtVerifier,
		clock:       clock,
	}
}

// FetchIETF retrieves the IETF Token Status List JWT from the given URI.
// The JWT signature is verified using the configured StatusListJWTVerifier,
// then the `status_list` payload is extracted and cached.
//
// The `iss` claim of the status-list JWT is checked against expectedIssuer,
// the issuer of the credential that referenced the list. Verifying the JWT
// signature alone only shows that the signer controls the key the token
// names — the attacker picks both when they control the status-list URL. The
// binding is applied to cached entries as well, so a list fetched for one
// issuer can never answer for another.
func (c *CachingIETFStatusListClient) FetchIETF(uri string, expectedIssuer string) (*common.IETFStatusList, error) {
	if cached, hit := c.cache.Get(uri); hit {
		logging.Log().Debugf("IETF status-list cache hit for %s", uri)
		cachedEntry := cached.(*cachedIETFStatusList)
		if err := assertIETFStatusListIssuer(cachedEntry.issuer, expectedIssuer, uri); err != nil {
			return nil, err
		}
		return cachedEntry.statusList, nil
	}

	logging.Log().Debugf("Fetching IETF status list JWT from %s", uri)
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		logging.Log().Debugf("Failed to create HTTP request for %s: %v", uri, err)
		return nil, fmt.Errorf("%w: %v", ErrorStatusListHttpFailure, err)
	}
	req.Header.Set("Accept", common.ContentTypeStatusListJWT)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		logging.Log().Debugf("HTTP request to %s failed: %v", uri, err)
		return nil, fmt.Errorf("%w: %v", ErrorStatusListHttpFailure, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < statusListHTTPOKMin || resp.StatusCode >= statusListHTTPOKMaxExclusive {
		logging.Log().Debugf("Unexpected HTTP status %d from %s", resp.StatusCode, uri)
		return nil, fmt.Errorf("%w: unexpected status %d from %s", ErrorStatusListHttpFailure, resp.StatusCode, uri)
	}

	var bodyReader io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		logging.Log().Debugf("Response from %s is gzip-encoded, decompressing", uri)
		gzReader, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			logging.Log().Debugf("Gzip decode failed for %s: %v", uri, gzErr)
			return nil, fmt.Errorf("%w: gzip decode failed: %v", ErrorStatusListUnparseable, gzErr)
		}
		defer func() { _ = gzReader.Close() }()
		bodyReader = gzReader
	}

	body, err := io.ReadAll(bodyReader)
	if err != nil {
		logging.Log().Debugf("Failed to read response body from %s: %v", uri, err)
		return nil, fmt.Errorf("%w: %v", ErrorStatusListHttpFailure, err)
	}

	logging.Log().Debugf("Received %d bytes from %s, verifying JWT", len(body), uri)
	payload, err := c.verifyAndExtractPayload(body)
	if err != nil {
		logging.Log().Debugf("JWT verification failed for %s: %v", uri, err)
		return nil, err
	}

	result, err := parseIETFStatusListPayload(payload, uri, c.clock)
	if err != nil {
		logging.Log().Debugf("Failed to parse IETF status list payload from %s: %v", uri, err)
		return nil, err
	}

	if err := assertIETFStatusListIssuer(result.issuer, expectedIssuer, uri); err != nil {
		return nil, err
	}

	cacheExpiry := c.expiry
	if result.ttl != nil && *result.ttl < cacheExpiry {
		cacheExpiry = *result.ttl
		logging.Log().Debugf("Using issuer ttl %v (shorter than configured %v) for %s", cacheExpiry, c.expiry, uri)
	}

	c.cache.Set(uri, &cachedIETFStatusList{statusList: result.statusList, issuer: result.issuer}, cacheExpiry)
	logging.Log().Debugf("Cached IETF status-list for %s (expiry=%v)", uri, cacheExpiry)
	return result.statusList, nil
}

// cachedIETFStatusList is the cache entry for an IETF status list. The issuer
// is retained alongside the list so the issuer binding can be re-checked on a
// cache hit instead of being established only on the fetch path.
type cachedIETFStatusList struct {
	statusList *common.IETFStatusList
	issuer     string
}

// assertIETFStatusListIssuer requires the `iss` claim of a status-list JWT to
// match the issuer of the credential that referenced it.
//
// As with the W3C status lists, an empty expectedIssuer is rejected rather
// than exempted: a referencing credential with no issuer cannot be bound to
// any list, and skipping the check would fail open.
func assertIETFStatusListIssuer(actualIssuer string, expectedIssuer string, uri string) error {
	if expectedIssuer == "" {
		logging.Log().Warnf("Referencing credential has no issuer, cannot bind IETF status list %s to an issuer", uri)
		return fmt.Errorf("%w: status list %s", ErrorStatusListIssuerUnknown, uri)
	}
	if actualIssuer != expectedIssuer {
		logging.Log().Warnf("IETF status list %s is issued by %q but the referencing credential is issued by %q",
			uri, actualIssuer, expectedIssuer)
		return fmt.Errorf("%w: status list issuer %q, credential issuer %q",
			ErrorStatusListIssuerMismatch, actualIssuer, expectedIssuer)
	}
	return nil
}

// InvalidateIETF removes the cached status list for the given URI so the
// next FetchIETF call fetches a fresh copy from the origin server.
func (c *CachingIETFStatusListClient) InvalidateIETF(uri string) {
	c.cache.Delete(uri)
}

// verifyAndExtractPayload validates the JWT `typ` header, verifies the
// signature (when a verifier is configured), and returns the payload bytes.
// Falls back to unverified base64 decoding when no verifier is set.
func (c *CachingIETFStatusListClient) verifyAndExtractPayload(jwtBytes []byte) ([]byte, error) {
	if err := validateStatusListJWTTyp(jwtBytes); err != nil {
		logging.Log().Debugf("Status list JWT typ validation failed: %v", err)
		return nil, err
	}
	logging.Log().Debug("Status list JWT typ header is valid")

	if c.jwtVerifier != nil {
		return c.jwtVerifier.VerifyStatusListJWT(jwtBytes)
	}

	logging.Log().Warn("No JWT verifier configured for IETF status list — skipping signature verification")
	return decodeJWTPayloadUnverified(jwtBytes)
}

// validateStatusListJWTTyp decodes the JWT header (first dot-separated
// segment) and rejects the token when the `typ` field is not
// `statuslist+jwt`, as required by draft-ietf-oauth-status-list §5.1.
func validateStatusListJWTTyp(jwtBytes []byte) error {
	dot := bytes.IndexByte(jwtBytes, '.')
	if dot < 0 {
		logging.Log().Debug("JWT has no dot separator, cannot extract header")
		return fmt.Errorf("%w: JWT has no header segment", ErrorStatusListUnparseable)
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(string(jwtBytes[:dot]))
	if err != nil {
		logging.Log().Debugf("JWT header base64 decode failed: %v", err)
		return fmt.Errorf("%w: JWT header base64 decode failed: %v", ErrorStatusListUnparseable, err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		logging.Log().Debugf("JWT header JSON unmarshal failed: %v", err)
		return fmt.Errorf("%w: JWT header JSON unmarshal failed: %v", ErrorStatusListUnparseable, err)
	}

	typ, _ := header[jwtHeaderTyp].(string)
	if !strings.EqualFold(typ, statusListJWTTyp) {
		logging.Log().Debugf("Status list JWT typ header is %q, expected %q", typ, statusListJWTTyp)
		return fmt.Errorf("%w: expected %q, got %q", ErrorStatusListInvalidTyp, statusListJWTTyp, typ)
	}

	return nil
}

// decodeJWTPayloadUnverified extracts the payload from a JWT without
// verifying the signature. Used only as a fallback when no verifier is
// configured.
func decodeJWTPayloadUnverified(jwtBytes []byte) ([]byte, error) {
	parts := strings.Split(strings.TrimSpace(string(jwtBytes)), ".")
	if len(parts) != 3 {
		logging.Log().Debugf("JWT has %d parts instead of 3, cannot decode payload", len(parts))
		return nil, fmt.Errorf("%w: expected 3 JWT parts, got %d", ErrorStatusListUnparseable, len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		logging.Log().Debugf("JWT payload raw base64url decode failed, trying padded: %v", err)
		padded, padErr := base64.URLEncoding.DecodeString(parts[1])
		if padErr != nil {
			logging.Log().Debugf("JWT payload padded base64url decode also failed: %v", padErr)
			return nil, fmt.Errorf("%w: JWT payload base64 decode failed: %v", ErrorStatusListUnparseable, err)
		}
		payload = padded
	}
	logging.Log().Debug("Decoded JWT payload without signature verification")
	return payload, nil
}

// ietfStatusListResult bundles the parsed status list with optional
// caching metadata extracted from the JWT payload.
type ietfStatusListResult struct {
	statusList *common.IETFStatusList
	// issuer is the `iss` claim of the status-list JWT. It is retained so
	// the list can be bound to the credential that referenced it.
	issuer string
	// ttl is the issuer-requested cache duration from the `ttl` JWT claim
	// (draft-ietf-oauth-status-list §5.1 / §8.3 step 4d). Nil when the
	// claim is absent.
	ttl *time.Duration
}

// parseIETFStatusListPayload extracts the `status_list` fields from a
// verified JWT payload. It enforces draft-ietf-oauth-status-list §8.3:
//   - step 4a: the JWT's `sub` claim must equal expectedURI
//   - step 4c: if `exp` is present it must not be in the past
//   - step 4d: if `ttl` is present it is returned for cache control
//
// The `iss` claim is returned as-is; binding it to the referencing credential
// is the caller's job (see assertIETFStatusListIssuer).
func parseIETFStatusListPayload(payload []byte, expectedURI string, clock common.Clock) (*ietfStatusListResult, error) {
	logging.Log().Debugf("Parsing IETF status list payload for %s", expectedURI)
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		logging.Log().Debugf("JWT payload JSON unmarshal failed: %v", err)
		return nil, fmt.Errorf("%w: JWT payload JSON unmarshal failed: %v", ErrorStatusListUnparseable, err)
	}

	sub, _ := claims[jwtClaimSub].(string)
	if sub != expectedURI {
		logging.Log().Warnf("Status list JWT sub claim %q does not match expected URI %q", sub, expectedURI)
		return nil, fmt.Errorf("%w: sub=%q, expected=%q", ErrorStatusListSubjectMismatch, sub, expectedURI)
	}
	logging.Log().Debugf("Status list JWT sub claim matches expected URI %s", expectedURI)

	if err := checkExpClaim(claims, clock); err != nil {
		return nil, err
	}

	statusListRaw, ok := claims[common.IETFStatusListKey]
	if !ok || statusListRaw == nil {
		logging.Log().Debug("No top-level status_list key, treating entire payload as status list")
		statusListRaw = claims
	}

	statusListMap, ok := statusListRaw.(map[string]interface{})
	if !ok {
		logging.Log().Debugf("status_list is %T, expected JSON object", statusListRaw)
		return nil, fmt.Errorf("%w: status_list is not a JSON object", ErrorStatusListUnparseable)
	}

	lst, ok := statusListMap[common.IETFStatusListLst].(string)
	if !ok || lst == "" {
		logging.Log().Debug("status_list.lst is missing or empty")
		return nil, fmt.Errorf("%w: status_list.lst is missing or empty", ErrorStatusListUnparseable)
	}

	bits, err := parseIETFBits(statusListMap[common.IETFStatusListBits])
	if err != nil {
		logging.Log().Debugf("Invalid bits value: %v", err)
		return nil, fmt.Errorf("%w: %v", ErrorStatusListUnparseable, err)
	}
	logging.Log().Debugf("Parsed IETF status list: bits=%d, lst length=%d", bits, len(lst))

	issuer, _ := claims[jwtClaimIss].(string)
	result := &ietfStatusListResult{
		statusList: &common.IETFStatusList{Bits: bits, Lst: lst},
		issuer:     issuer,
	}

	if ttlRaw, hasTTL := claims[jwtClaimTTL]; hasTTL {
		ttl, ttlErr := parsePositiveSeconds(ttlRaw)
		if ttlErr != nil {
			logging.Log().Debugf("Invalid ttl value: %v", ttlErr)
			return nil, fmt.Errorf("%w: %v", ErrorStatusListUnparseable, ttlErr)
		}
		result.ttl = &ttl
		logging.Log().Debugf("Status list JWT declares ttl=%v", ttl)
	}

	return result, nil
}

// parsePositiveSeconds converts a JSON numeric value to a positive
// time.Duration in seconds.
func parsePositiveSeconds(raw interface{}) (time.Duration, error) {
	var secs int64
	switch v := raw.(type) {
	case float64:
		secs = int64(v)
	case int:
		secs = int64(v)
	case int64:
		secs = v
	default:
		return 0, fmt.Errorf("ttl has unexpected type %T", raw)
	}
	if secs <= 0 {
		return 0, fmt.Errorf("ttl must be positive, got %d", secs)
	}
	return time.Duration(secs) * time.Second, nil
}

// checkExpClaim verifies the `exp` claim if present. Per
// draft-ietf-oauth-status-list §8.3 step 4c the token is rejected when `exp`
// is defined and the current time is past it. When `exp` is absent the check
// is a no-op.
func checkExpClaim(claims map[string]interface{}, clock common.Clock) error {
	expRaw, ok := claims[jwtClaimExp]
	if !ok {
		logging.Log().Debug("Status list JWT has no exp claim, skipping expiration check")
		return nil
	}

	expFloat, ok := expRaw.(float64)
	if !ok {
		logging.Log().Debugf("exp claim has unexpected type %T", expRaw)
		return fmt.Errorf("%w: exp claim has unexpected type %T", ErrorStatusListUnparseable, expRaw)
	}

	expTime := time.Unix(int64(expFloat), 0)
	if clock.Now().After(expTime) {
		logging.Log().Warnf("Status list JWT expired at %v", expTime)
		return fmt.Errorf("%w: token expired at %v", ErrorStatusListExpired, expTime)
	}

	logging.Log().Debugf("Status list JWT exp check passed (expires %v)", expTime)
	return nil
}

// validIETFBitsValues is the set of allowed values for the `bits` field in
// an IETF Token Status List, per draft-ietf-oauth-status-list §4.1.
var validIETFBitsValues = map[int]bool{1: true, 2: true, 4: true, 8: true}

// parseIETFBits converts the `bits` value from a status list JWT payload to
// an int and validates it against the allowed set {1, 2, 4, 8} defined in
// draft-ietf-oauth-status-list §4.1. The `bits` claim is REQUIRED per §4.2;
// a nil value is rejected. JSON numbers arrive as float64.
func parseIETFBits(raw interface{}) (int, error) {
	var bits int
	switch v := raw.(type) {
	case float64:
		bits = int(v)
	case int:
		bits = v
	case int64:
		bits = int(v)
	case nil:
		return 0, fmt.Errorf("bits claim is required but missing")
	default:
		return 0, fmt.Errorf("bits has unexpected type %T", raw)
	}

	if !validIETFBitsValues[bits] {
		return 0, fmt.Errorf("bits must be one of {1, 2, 4, 8}, got %d", bits)
	}

	return bits, nil
}

// Compile-time assertion.
var _ IETFStatusListClient = (*CachingIETFStatusListClient)(nil)
