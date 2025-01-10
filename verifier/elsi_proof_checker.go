package verifier

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/fiware/VCVerifier/jades"
	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/vc-go/proof/checker"
)

const DidElsiPrefix = "did:elsi:"
const DidPartsSeparator = ":"

var ErrorInvalidJAdESSignature = errors.New("invalid_jades_signature")
var ErrorNoCertInHeader = errors.New("no_certificate_found_in_jwt_header")
var ErrorCertHeaderEmpty = errors.New("cert_header_is_empty")
var ErrorPemDecodeFailed = errors.New("failed_to_decode_pem_from_header")
var ErrorIssuerValidationFailed = errors.New("isser_validation_failed")

// ProofChecker implementation supporting the did:elsi method -> https://alastria.github.io/did-method-elsi/
type ElsiProofChecker struct {
	defaultChecker *checker.ProofChecker
	jAdESValidator jades.JAdESValidator
}

func (epc ElsiProofChecker) CheckJWTProof(headers jose.Headers, expectedProofIssuer string, msg, signature []byte) error {
	// handle did elsi
	if isDidElsiMethod(expectedProofIssuer) {
		return epc.checkElsiProof(headers, expectedProofIssuer, msg, signature)
		// or refer to the default proof check
	} else {
		return epc.defaultChecker.CheckJWTProof(headers, expectedProofIssuer, msg, signature)
	}
}

func isDidElsiMethod(did string) bool {
	parts := strings.Split(did, DidPartsSeparator)
	return len(parts) == 3 && strings.HasPrefix(did, DidElsiPrefix)
}

// checks the proof for did:elsi
// 1. check that the issuer is the one mentioned in the certificate
// 2. check that the signature is a valid JAdES signature
func (epc ElsiProofChecker) checkElsiProof(headers jose.Headers, expectedProofIssuer string, msg, signature []byte) (err error) {

	// start with issuer validation, no external calls required if it fails
	certificate, err := retrieveClientCertificate(headers)
	if err != nil {
		return err
	}
	err = validateIssuer(certificate, expectedProofIssuer)
	if err != nil {
		logging.Log().Debugf("%v is not the valid issuer.", expectedProofIssuer)
		return err
	}

	logging.Log().Warnf("Decoded message %s", string(msg))
	encodedMessage, _ := decodeBase64BytesToString(msg)
	logging.Log().Warnf("Encoded message %s", encodedMessage)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	originalJwt := encodedMessage + "." + encodedSignature
	base64Jwt := base64.RawURLEncoding.EncodeToString([]byte(originalJwt))
	isValid, err := epc.jAdESValidator.ValidateSignature(base64Jwt)
	if err != nil {
		logging.Log().Warnf("Was not able to validate JAdES signature. Err: %v", err)
		return err
	}
	if !isValid {
		logging.Log().Infof("JAdES signature was invalid.")
		return ErrorInvalidJAdESSignature
	}
	logging.Log().Debugf("Valid did:elsi credential.")
	return err
}

func decodeBase64BytesToString(base64Bytes []byte) (string, error) {
	base64Str := base64.RawURLEncoding.EncodeToString(base64Bytes)
	decodedBytes, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return "", err
	}

	return string(decodedBytes[:]), nil
}

func retrieveClientCertificate(headers jose.Headers) (*x509.Certificate, error) {
	raw, ok := headers[jose.HeaderX509CertificateChain]
	if !ok {
		return nil, ErrorNoCertInHeader
	}

	rawArray := raw.([]interface{})

	if len(rawArray) != 0 {
		cert := rawArray[0].(string)
		return parseCertificate(cert)
	} else {
		return nil, ErrorCertHeaderEmpty
	}
}

func parseCertificate(certBase64 string) (*x509.Certificate, error) {
	certDER, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		logging.Log().Warnf("Failed to decode the certificate header. Error: %v", err)
		return nil, ErrorPemDecodeFailed
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		logging.Log().Warnf("Failed to parse the certificate header. Error: %v", err)
		return nil, err
	}
	return cert, nil
}

func validateIssuer(certificate *x509.Certificate, issuerDid string) error {
	var oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	organizationIdentifier := ""

	for _, name := range certificate.Subject.Names {
		if name.Type.Equal(oidOrganizationIdentifier) {
			organizationIdentifier = name.Value.(string)
			break
		}
	}
	// checks that the organization identifier in the certificate is equal to the id-part of the did:elsi:<ID>
	if organizationIdentifier != "" && strings.HasSuffix(issuerDid, DidPartsSeparator+organizationIdentifier) {
		return nil
	} else {
		return ErrorIssuerValidationFailed
	}
}

// non-elsi proof check methods - will be handled by the default checkers

func (epc *ElsiProofChecker) CheckLDProof(proof *proof.Proof, expectedProofIssuer string, msg, signature []byte) error {
	return epc.defaultChecker.CheckLDProof(proof, expectedProofIssuer, msg, signature)
}

func (epc ElsiProofChecker) GetLDPCanonicalDocument(proof *proof.Proof, doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	return epc.defaultChecker.GetLDPCanonicalDocument(proof, doc, opts...)
}

func (epc ElsiProofChecker) GetLDPDigest(proof *proof.Proof, doc []byte) ([]byte, error) {
	return epc.defaultChecker.GetLDPDigest(proof, doc)
}
