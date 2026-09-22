package eidas

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// qcStatementFixture describes one statement to encode into a test
// certificate's qcStatements extension.
type qcStatementFixture struct {
	id    asn1.ObjectIdentifier
	types []asn1.ObjectIdentifier
}

// makeQCStatementsExtension encodes the given statements into a qcStatements
// extension value.
func makeQCStatementsExtension(t *testing.T, statements []qcStatementFixture) pkix.Extension {
	t.Helper()

	type plainStatement struct {
		StatementID asn1.ObjectIdentifier
	}
	type typedStatement struct {
		StatementID   asn1.ObjectIdentifier
		StatementInfo []asn1.ObjectIdentifier
	}

	var encoded []interface{}
	for _, statement := range statements {
		if len(statement.types) > 0 {
			encoded = append(encoded, typedStatement{StatementID: statement.id, StatementInfo: statement.types})
			continue
		}
		encoded = append(encoded, plainStatement{StatementID: statement.id})
	}

	value, err := asn1.Marshal(encoded)
	require.NoError(t, err)

	return pkix.Extension{Id: oidQCStatements, Value: value}
}

// makeCertificateWithExtensions creates a self-signed certificate carrying the
// given extra extensions.
func makeCertificateWithExtensions(t *testing.T, extensions []pkix.Extension) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "QC Statement Test"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: extensions,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// TestParseQCStatements verifies that the qualified certificate statements are
// read from the qcStatements extension, and that a certificate without a usable
// extension is not treated as qualified.
func TestParseQCStatements(t *testing.T) {
	tests := []struct {
		name              string
		statements        []qcStatementFixture
		omitExtension     bool
		malformedValue    []byte
		expectedError     error
		expectedCompliant bool
		expectedSSCD      bool
		expectedTypes     []asn1.ObjectIdentifier
	}{
		{
			name:              "qc compliance only",
			statements:        []qcStatementFixture{{id: oidQcCompliance}},
			expectedCompliant: true,
		},
		{
			name: "compliance, sscd and esign type",
			statements: []qcStatementFixture{
				{id: oidQcCompliance},
				{id: oidQcSSCD},
				{id: oidQcType, types: []asn1.ObjectIdentifier{QcTypeESign}},
			},
			expectedCompliant: true,
			expectedSSCD:      true,
			expectedTypes:     []asn1.ObjectIdentifier{QcTypeESign},
		},
		{
			name: "eseal type without compliance",
			statements: []qcStatementFixture{
				{id: oidQcType, types: []asn1.ObjectIdentifier{QcTypeESeal}},
			},
			expectedCompliant: false,
			expectedTypes:     []asn1.ObjectIdentifier{QcTypeESeal},
		},
		{
			name: "unknown statements are ignored",
			statements: []qcStatementFixture{
				{id: asn1.ObjectIdentifier{1, 2, 3, 4}},
				{id: oidQcCompliance},
			},
			expectedCompliant: true,
		},
		{
			name:          "no extension at all",
			omitExtension: true,
			expectedError: ErrorNoQCStatements,
		},
		{
			name:           "unparseable extension",
			malformedValue: []byte{0x30, 0x03, 0x02, 0x01},
			expectedError:  ErrorMalformedQCStatements,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var extensions []pkix.Extension
			switch {
			case tc.omitExtension:
				extensions = nil
			case tc.malformedValue != nil:
				extensions = []pkix.Extension{{Id: oidQCStatements, Value: tc.malformedValue}}
			default:
				extensions = []pkix.Extension{makeQCStatementsExtension(t, tc.statements)}
			}

			cert := makeCertificateWithExtensions(t, extensions)

			statements, err := ParseQCStatements(cert)
			if tc.expectedError != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.expectedError)

				qualified, err := IsQualifiedCertificate(cert)
				assert.False(t, qualified)
				assert.ErrorIs(t, err, tc.expectedError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expectedCompliant, statements.Compliant)
			assert.Equal(t, tc.expectedSSCD, statements.SSCD)
			assert.Equal(t, tc.expectedTypes, statements.Types)

			for _, expectedType := range tc.expectedTypes {
				assert.True(t, statements.HasType(expectedType))
			}
			assert.False(t, statements.HasType(asn1.ObjectIdentifier{9, 9, 9}))

			qualified, err := IsQualifiedCertificate(cert)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedCompliant, qualified)
		})
	}
}

// TestParseQCStatements_NilCertificate verifies the nil guard.
func TestParseQCStatements_NilCertificate(t *testing.T) {
	_, err := ParseQCStatements(nil)
	assert.ErrorIs(t, err, ErrorNoQCStatements)
}
