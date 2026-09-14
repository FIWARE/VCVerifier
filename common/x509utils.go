package common

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

// ParseBase64Certificate decodes a base64-encoded DER X.509 certificate and
// parses it into an *x509.Certificate. Whitespace (spaces, newlines, tabs,
// carriage returns) in the base64 data is stripped before decoding, which is
// necessary for sources such as ETSI trust list XML that commonly format
// certificate data with line breaks.
func ParseBase64Certificate(b64Data string) (*x509.Certificate, error) {
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, b64Data)

	derBytes, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER certificate: %w", err)
	}

	return cert, nil
}
