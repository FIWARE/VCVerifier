package verifier

import (
	"errors"
	"fmt"

	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// ErrorUnsupportedSignatureAlgorithm indicates that the `alg` header of a JWS
// names an algorithm the verifier does not accept — `none`, a symmetric (HMAC)
// algorithm, or anything outside allowedSignatureAlgorithms.
var ErrorUnsupportedSignatureAlgorithm = errors.New("unsupported_signature_algorithm")

// ErrorAlgorithmKeyMismatch indicates that the `alg` header of a JWS does not
// match the algorithm the verification key itself declares.
var ErrorAlgorithmKeyMismatch = errors.New("signature_algorithm_key_mismatch")

// ErrorNoUsableVerificationKey indicates that none of the resolved candidate
// keys verified the signature.
var ErrorNoUsableVerificationKey = errors.New("no_usable_verification_key")

// allowedSignatureAlgorithms is the set of JWS algorithms accepted for
// credential and presentation signatures. It is an allowlist rather than a
// denylist: the `alg` header comes from the token, so anything not listed here
// — `none` above all, and the symmetric HS* family, where a public key doubles
// as the shared secret — must never reach the verification step.
var allowedSignatureAlgorithms = map[string]bool{
	jwa.RS256().String(): true,
	jwa.RS384().String(): true,
	jwa.RS512().String(): true,
	jwa.PS256().String(): true,
	jwa.PS384().String(): true,
	jwa.PS512().String(): true,
	jwa.ES256().String(): true,
	jwa.ES384().String(): true,
	jwa.ES512().String(): true,
	jwa.EdDSA().String(): true,
}

// verifyJWSWithCandidateKeys verifies a JWS against the given candidate keys and
// returns the payload together with the key that verified it.
//
// The algorithm is taken from the protected header but pinned twice before use:
// it has to be in allowedSignatureAlgorithms, and it has to match the `alg` of
// the key when the key declares one — a JWKS entry published for PS256 is not
// usable for an RS256 signature just because the token says so.
//
// Trying every candidate is what makes a kid-less JWS verifiable against a
// multi-key JWKS: only the key that actually signed produces a valid signature,
// so iterating is safe and does not weaken the check.
func verifyJWSWithCandidateKeys(token []byte, headers jws.Headers, keys []jwk.Key) ([]byte, jwk.Key, error) {
	headerAlg, err := allowedHeaderAlgorithm(headers)
	if err != nil {
		return nil, nil, err
	}

	if len(keys) == 0 {
		return nil, nil, ErrorNoUsableVerificationKey
	}

	var lastErr error
	for _, key := range keys {
		if err := assertKeyAllowsAlgorithm(key, headerAlg); err != nil {
			logging.Log().Debugf("Skipping candidate key: %v", err)
			lastErr = err
			continue
		}
		payload, err := jws.Verify(token, jws.WithKey(headerAlg, key))
		if err == nil {
			return payload, key, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		lastErr = ErrorNoUsableVerificationKey
	}
	return nil, nil, fmt.Errorf("%w: %v", ErrorNoUsableVerificationKey, lastErr)
}

// allowedHeaderAlgorithm extracts the `alg` of a protected header and checks it
// against allowedSignatureAlgorithms.
func allowedHeaderAlgorithm(headers jws.Headers) (jwa.SignatureAlgorithm, error) {
	alg, ok := headers.Algorithm()
	if !ok {
		return alg, fmt.Errorf("%w: the JWS header declares no algorithm", ErrorUnsupportedSignatureAlgorithm)
	}
	if err := assertAllowedAlgorithm(alg); err != nil {
		return alg, err
	}
	return alg, nil
}

// assertAllowedAlgorithm checks a signature algorithm against the allowlist.
func assertAllowedAlgorithm(alg jwa.SignatureAlgorithm) error {
	if !allowedSignatureAlgorithms[alg.String()] {
		logging.Log().Warnf("Rejecting JWS signed with unsupported algorithm %q", alg.String())
		return fmt.Errorf("%w: %s", ErrorUnsupportedSignatureAlgorithm, alg.String())
	}
	return nil
}

// assertKeyAllowsAlgorithm requires the key's own `alg`, when it declares one,
// to be the algorithm the JWS header names.
func assertKeyAllowsAlgorithm(key jwk.Key, alg jwa.SignatureAlgorithm) error {
	keyAlg, ok := key.Algorithm()
	if !ok || keyAlg == nil || keyAlg.String() == "" {
		return nil
	}
	if keyAlg.String() != alg.String() {
		return fmt.Errorf("%w: key declares %s but the JWS is signed with %s", ErrorAlgorithmKeyMismatch, keyAlg.String(), alg.String())
	}
	return nil
}
