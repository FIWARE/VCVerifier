package verifier

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

const (
	PKCEPlain = "plain"
	PKCES256  = "S256"
)

var (
	ErrorInvalidPKCEChallenge = errors.New("invalid_pkce_code_challenge")
	ErrorInvalidPKCEMethod    = errors.New("unsupported_pkce_code_challenge_method")
	ErrorInvalidPKCEVerifier  = errors.New("invalid_pkce_code_verifier")

	pkceValuePattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
)

// PKCEChallenge carries the challenge bound to an authorization code.
type PKCEChallenge struct {
	Value        string
	Method       string
	ChallengeSet bool
	MethodSet    bool
}

type pkceMethod interface {
	validateChallenge(string) error
	verify(challenge, verifier string) bool
}

type plainPKCEMethod struct{}

func (plainPKCEMethod) validateChallenge(challenge string) error {
	if !pkceValuePattern.MatchString(challenge) {
		return ErrorInvalidPKCEChallenge
	}
	return nil
}

func (plainPKCEMethod) verify(challenge, verifier string) bool {
	return subtle.ConstantTimeCompare([]byte(challenge), []byte(verifier)) == 1
}

type s256PKCEMethod struct{}

func (s256PKCEMethod) validateChallenge(challenge string) error {
	if len(challenge) != 43 || !pkceValuePattern.MatchString(challenge) {
		return ErrorInvalidPKCEChallenge
	}
	return nil
}

func (s256PKCEMethod) verify(challenge, verifier string) bool {
	digest := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(challenge), []byte(expected)) == 1
}

// pkceMethods is the single registry for supported transformations. Adding a
// method requires implementing pkceMethod and registering its name here.
var pkceMethods = map[string]pkceMethod{
	PKCEPlain: plainPKCEMethod{},
	PKCES256:  s256PKCEMethod{},
}

func canonicalPKCEMethod(name string) (string, bool) {
	for supported := range pkceMethods {
		if strings.EqualFold(name, supported) {
			return supported, true
		}
	}
	return "", false
}

func isPKCEMethodAllowed(method string, allowedMethods []string) bool {
	for _, allowed := range allowedMethods {
		if strings.EqualFold(method, allowed) {
			return true
		}
	}
	return false
}

func validatePKCEConfiguration(methods []string) ([]string, error) {
	if len(methods) == 0 {
		methods = []string{PKCES256}
	}

	normalized := make([]string, 0, len(methods))
	for _, method := range methods {
		canonical, supported := canonicalPKCEMethod(method)
		if !supported {
			return nil, fmt.Errorf("%w: %q", ErrorInvalidPKCEMethod, method)
		}
		if slices.Contains(normalized, canonical) {
			continue
		}
		normalized = append(normalized, canonical)
	}
	return normalized, nil
}

func validatePKCEChallenge(challenge PKCEChallenge, allowedMethods []string) (PKCEChallenge, error) {
	if challenge.Value == "" {
		if challenge.ChallengeSet || challenge.MethodSet || challenge.Method != "" {
			return challenge, ErrorInvalidPKCEChallenge
		}
		return challenge, nil
	}
	if challenge.MethodSet && challenge.Method == "" {
		return challenge, ErrorInvalidPKCEMethod
	}

	// RFC 7636 defines plain as the default when the method is omitted.
	if challenge.Method == "" {
		challenge.Method = PKCEPlain
	} else {
		canonical, supported := canonicalPKCEMethod(challenge.Method)
		if !supported {
			return challenge, fmt.Errorf("%w: %q", ErrorInvalidPKCEMethod, challenge.Method)
		}
		challenge.Method = canonical
	}
	method, supported := pkceMethods[challenge.Method]
	if !supported || !isPKCEMethodAllowed(challenge.Method, allowedMethods) {
		return challenge, fmt.Errorf("%w: %q", ErrorInvalidPKCEMethod, challenge.Method)
	}
	if err := method.validateChallenge(challenge.Value); err != nil {
		return challenge, err
	}
	return challenge, nil
}

func verifyPKCE(challenge PKCEChallenge, codeVerifier string) error {
	if challenge.Value == "" {
		// A verifier for a code issued without a challenge is a downgrade: the challenge was
		// stripped from the authorization request, so the verifier proves nothing (RFC 9700 §2.1.1).
		if codeVerifier != "" {
			return ErrorInvalidPKCEVerifier
		}
		return nil
	}
	if !pkceValuePattern.MatchString(codeVerifier) {
		return ErrorInvalidPKCEVerifier
	}
	method, supported := pkceMethods[challenge.Method]
	if !supported || !method.verify(challenge.Value, codeVerifier) {
		return ErrorInvalidPKCEVerifier
	}
	return nil
}
