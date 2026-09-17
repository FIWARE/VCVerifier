package eidas

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// --- Qualified certificate statements (ETSI EN 319 412-5) ---
//
// A certificate declares that it is a qualified certificate through the
// qcStatements extension (RFC 3739 §3.2.6, profiled by ETSI EN 319 412-5).
// Being issued by a CA that is listed under a qualified service type in a
// trust list is not the same thing: such a CA may also issue non-qualified
// certificates, so the statement has to be read from the certificate itself.

var (
	// oidQCStatements is id-pe-qcStatements, the certificate extension holding
	// the qualified certificate statements (RFC 3739 §3.2.6).
	oidQCStatements = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}

	// oidQcCompliance is id-etsi-qcs-QcCompliance: the certificate is a
	// qualified certificate as defined in Regulation (EU) No 910/2014.
	oidQcCompliance = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1}

	// oidQcSSCD is id-etsi-qcs-QcSSCD: the private key resides in a qualified
	// signature/seal creation device.
	oidQcSSCD = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 4}

	// oidQcType is id-etsi-qcs-QcType: the type(s) of the qualified certificate.
	oidQcType = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6}

	// QcTypeESign is id-etsi-qct-esign: a qualified certificate for electronic
	// signatures, issued to a natural person.
	QcTypeESign = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 1}

	// QcTypeESeal is id-etsi-qct-eseal: a qualified certificate for electronic
	// seals, issued to a legal person.
	QcTypeESeal = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 2}

	// QcTypeWeb is id-etsi-qct-web: a qualified certificate for website
	// authentication.
	QcTypeWeb = asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 3}
)

// ErrorNoQCStatements is returned when a certificate carries no qcStatements
// extension at all, so it makes no qualified-certificate claim.
var ErrorNoQCStatements = errors.New("certificate_has_no_qc_statements")

// ErrorMalformedQCStatements is returned when the qcStatements extension is
// present but cannot be parsed.
var ErrorMalformedQCStatements = errors.New("malformed_qc_statements")

// QCStatements holds the qualified certificate statements read from a
// certificate's qcStatements extension.
type QCStatements struct {
	// Compliant reports whether the certificate declares QcCompliance, i.e.
	// that it is a qualified certificate under Regulation (EU) No 910/2014.
	Compliant bool
	// SSCD reports whether the certificate declares that its private key
	// resides in a qualified signature/seal creation device.
	SSCD bool
	// Types holds the declared QcType identifiers (esign, eseal, web). It is
	// empty when the certificate declares no QcType statement.
	Types []asn1.ObjectIdentifier
}

// HasType reports whether the certificate declares the given QcType.
func (q QCStatements) HasType(qcType asn1.ObjectIdentifier) bool {
	for _, t := range q.Types {
		if t.Equal(qcType) {
			return true
		}
	}
	return false
}

// qcStatement is one entry of the qcStatements SEQUENCE. StatementInfo is
// statement-specific and optional (RFC 3739 §3.2.6).
type qcStatement struct {
	StatementID   asn1.ObjectIdentifier
	StatementInfo asn1.RawValue `asn1:"optional"`
}

// ParseQCStatements reads the qcStatements extension from a certificate.
//
// It returns ErrorNoQCStatements when the extension is absent — the
// certificate then makes no qualified-certificate claim — and
// ErrorMalformedQCStatements when it is present but cannot be decoded.
func ParseQCStatements(certificate *x509.Certificate) (QCStatements, error) {
	if certificate == nil {
		return QCStatements{}, ErrorNoQCStatements
	}

	var raw []byte
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oidQCStatements) {
			raw = extension.Value
			break
		}
	}
	if raw == nil {
		return QCStatements{}, ErrorNoQCStatements
	}

	var statements []qcStatement
	rest, err := asn1.Unmarshal(raw, &statements)
	if err != nil {
		return QCStatements{}, fmt.Errorf("%w: %v", ErrorMalformedQCStatements, err)
	}
	if len(rest) != 0 {
		return QCStatements{}, fmt.Errorf("%w: %d trailing bytes", ErrorMalformedQCStatements, len(rest))
	}

	parsed := QCStatements{}
	for _, statement := range statements {
		switch {
		case statement.StatementID.Equal(oidQcCompliance):
			parsed.Compliant = true
		case statement.StatementID.Equal(oidQcSSCD):
			parsed.SSCD = true
		case statement.StatementID.Equal(oidQcType):
			types, err := parseQcTypes(statement.StatementInfo)
			if err != nil {
				return QCStatements{}, err
			}
			parsed.Types = types
		}
	}

	return parsed, nil
}

// IsQualifiedCertificate reports whether the certificate declares itself a
// qualified certificate through a QcCompliance statement. A certificate
// without the qcStatements extension, or with an unreadable one, is not
// qualified; the error explains which of the two it was.
func IsQualifiedCertificate(certificate *x509.Certificate) (bool, error) {
	statements, err := ParseQCStatements(certificate)
	if err != nil {
		return false, err
	}
	return statements.Compliant, nil
}

// parseQcTypes decodes the statementInfo of a QcType statement, which is a
// SEQUENCE OF OBJECT IDENTIFIER (ETSI EN 319 412-5 §4.2.3).
func parseQcTypes(statementInfo asn1.RawValue) ([]asn1.ObjectIdentifier, error) {
	if len(statementInfo.FullBytes) == 0 {
		return nil, fmt.Errorf("%w: QcType statement carries no statementInfo", ErrorMalformedQCStatements)
	}

	var types []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(statementInfo.FullBytes, &types); err != nil {
		return nil, fmt.Errorf("%w: QcType: %v", ErrorMalformedQCStatements, err)
	}
	return types, nil
}
