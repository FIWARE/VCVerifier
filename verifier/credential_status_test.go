package verifier

// credential_status_test.go exercises CredentialStatusValidationService via
// table-driven cases that mirror the patterns used in compliance_test.go and
// trustedissuer_test.go. The tests deliberately avoid real network I/O: a
// mockStatusListClient serves fixture status-list credentials from an
// in-memory map so every code branch can be reached deterministically.

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/did"
	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func boolPtr(v bool) *bool { return &v }

// Named constants used throughout the test file. Pulling them out of the
// table rows keeps the intent of each row obvious and removes magic values.
// The "statusValidation" prefix avoids collisions with the already-declared
// testStatus* constants in credentialsConfig_test.go and
// credential_status_client_test.go.
const (
	// statusValidationTestType is the credential `type` used by fixtures
	// that need the status-list check to be active. Matches the keys used
	// in the PerType config maps of the same tests.
	statusValidationTestType = "TestCredential"
	// statusValidationUnconfiguredType is a credential `type` that no test
	// config opts in; credentials declaring this type must never trigger a
	// fetch.
	statusValidationUnconfiguredType = "UnconfiguredCredential"
	// statusValidationTestURL is the primary status-list credential URL
	// used by most fixtures. Tests that need a second entry use
	// statusValidationTestURLAlt.
	statusValidationTestURL = "https://example.org/status/1"
	// statusValidationTestURLAlt is used by the two-entry fixture that
	// combines a suspension and a revocation list pointing at different
	// URLs.
	statusValidationTestURLAlt = "https://example.org/status/2"
	// statusValidationTestIndex is the bit index the fixture entries
	// reference. A small non-zero value keeps the fixture bitstring tiny
	// while still exercising the "set-bit-somewhere-other-than-byte-
	// boundary" path.
	statusValidationTestIndex uint64 = 3
)

// statusValidationRevokedByte is a single-byte bitstring with the bit at
// statusValidationTestIndex set (MSB-first). 0x10 = 0b00010000 -> bit 3
// from the MSB is set.
var statusValidationRevokedByte = []byte{0x10}

// statusValidationClearByte is a single-byte bitstring with no bits set.
var statusValidationClearByte = []byte{0x00}

// mockStatusListClient is a StatusListCredentialClient test double that
// serves pre-built responses from an in-memory map. It records every URL
// it is asked to fetch so tests can assert that opt-out paths skipped the
// network call entirely.
type mockStatusListClient struct {
	credentials map[string]*common.Credential
	err         error
	calls       []string
	// issuers records the expected issuer each Fetch was called with, so
	// tests can assert the status list is bound to the referencing
	// credential's issuer.
	issuers []string
}

// Fetch implements StatusListCredentialClient. When err is non-nil it is
// returned verbatim so tests can inject transport/parse failures. On the
// happy path the URL is looked up in `credentials` and a missing entry
// yields a distinct error that would fail any subsequent assertion — this
// guards against silent "revoked" false-positives caused by typos in the
// table rows.
func (m *mockStatusListClient) Fetch(url string, expectedIssuer string) (*common.Credential, error) {
	m.calls = append(m.calls, url)
	m.issuers = append(m.issuers, expectedIssuer)
	if m.err != nil {
		return nil, m.err
	}
	cred, ok := m.credentials[url]
	if !ok {
		return nil, fmt.Errorf("mockStatusListClient: no fixture for %q", url)
	}
	return cred, nil
}

// encodeTestBitstring returns base64url(gzip(bits)), the encoding the W3C
// Bitstring Status List spec requires on `credentialSubject.encodedList`.
func encodeTestBitstring(t *testing.T, bits []byte) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(bits); err != nil {
		t.Fatalf("gzip write failed: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close failed: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

// newStatusListCredential builds a status-list credential whose raw JSON
// representation carries the supplied encoded bitstring and purpose on its
// `credentialSubject`. SetRawJSON is used so the resulting credential
// round-trips through ToRawJSON() exactly as a fetched VC would.
func newStatusListCredential(t *testing.T, encodedList, purpose string) *common.Credential {
	t.Helper()
	raw := common.JSONObject{
		common.JSONLDKeyID:   statusValidationTestURL,
		common.JSONLDKeyType: []string{common.TypeVerifiableCredential, common.TypeBitstringStatusListCredential},
		common.VCKeyCredentialSubject: common.JSONObject{
			common.StatusListKeyEncodedList:   encodedList,
			common.StatusListKeyStatusPurpose: purpose,
		},
	}
	cred, err := common.CreateCredential(common.CredentialContents{
		Types: []string{common.TypeVerifiableCredential, common.TypeBitstringStatusListCredential},
	}, common.CustomFields{})
	if err != nil {
		t.Fatalf("CreateCredential failed: %v", err)
	}
	cred.SetRawJSON(raw)
	return cred
}

// newStatusListCredentialWithTypes builds a status-list credential with
// custom types, allowing tests to verify type-checking logic by passing
// types that do not include a recognised status-list credential type.
func newStatusListCredentialWithTypes(t *testing.T, encodedList, purpose string, types []string) *common.Credential {
	t.Helper()
	raw := common.JSONObject{
		common.JSONLDKeyID:   statusValidationTestURL,
		common.JSONLDKeyType: types,
		common.VCKeyCredentialSubject: common.JSONObject{
			common.StatusListKeyEncodedList:   encodedList,
			common.StatusListKeyStatusPurpose: purpose,
		},
	}
	cred, err := common.CreateCredential(common.CredentialContents{
		Types: types,
	}, common.CustomFields{})
	if err != nil {
		t.Fatalf("CreateCredential failed: %v", err)
	}
	cred.SetRawJSON(raw)
	return cred
}

// newCredentialWithStatus builds a verifier-input credential carrying the
// supplied `credentialStatus` raw value plus the declared credential type.
// When rawStatus is nil the credential exposes no status field — this is
// the shape expected by the "no credentialStatus entry" table rows.
func newCredentialWithStatus(t *testing.T, credentialType string, rawStatus interface{}) *common.Credential {
	t.Helper()
	fields := common.CustomFields{}
	if rawStatus != nil {
		fields[common.VCKeyCredentialStatus] = rawStatus
	}
	cred, err := common.CreateCredential(common.CredentialContents{
		Types: []string{credentialType},
	}, fields)
	if err != nil {
		t.Fatalf("CreateCredential failed: %v", err)
	}
	return cred
}

// bitstringStatusEntry returns a raw credentialStatus JSON object for a
// BitstringStatusListEntry referencing the supplied URL, purpose and index.
func bitstringStatusEntry(url, purpose string, index uint64) common.JSONObject {
	return common.JSONObject{
		common.StatusListEntryKeyType:                 common.TypeBitstringStatusListEntry,
		common.StatusListEntryKeyStatusPurpose:        purpose,
		common.StatusListEntryKeyStatusListCredential: url,
		common.StatusListEntryKeyStatusListIndex:      fmt.Sprintf("%d", index),
	}
}

// TestCredentialStatusValidationService_ValidateVC walks every observable
// branch of ValidateVC. Each row builds an input credential, a per-type
// config map and an optional set of fixtures served by the mock client,
// then asserts the returned (bool, error) pair and — where relevant — that
// no fetch occurred.
func TestCredentialStatusValidationService_ValidateVC(t *testing.T) {
	type test struct {
		testName        string
		credential      *common.Credential
		perType         map[string]configModel.CredentialStatus
		fixtures        map[string]*common.Credential
		fetchErr        error
		expectedResult  bool
		expectedError   error
		expectedNoFetch bool
	}

	revokedList := newStatusListCredential(t, encodeTestBitstring(t, statusValidationRevokedByte), configModel.StatusPurposeRevocation)
	clearList := newStatusListCredential(t, encodeTestBitstring(t, statusValidationClearByte), configModel.StatusPurposeRevocation)
	suspensionClearList := newStatusListCredential(t, encodeTestBitstring(t, statusValidationClearByte), configModel.StatusPurposeSuspension)
	malformedList := newStatusListCredential(t, "not*valid*base64!", configModel.StatusPurposeRevocation)

	// A credential with an encodedList but no recognised status-list type.
	wrongTypeList := newStatusListCredentialWithTypes(t,
		encodeTestBitstring(t, statusValidationClearByte),
		configModel.StatusPurposeRevocation,
		[]string{common.TypeVerifiableCredential},
	)

	// Two-entry fixture credentials for the suspension + revocation case.
	// The suspension list's URL differs from the revocation list's URL so
	// the mock client returns the correct fixture for each lookup.
	altRevokedList := newStatusListCredential(t, encodeTestBitstring(t, statusValidationRevokedByte), configModel.StatusPurposeRevocation)

	tests := []test{
		{
			testName:        "Type not present in PerType is a no-op",
			credential:      newCredentialWithStatus(t, statusValidationUnconfiguredType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeRevocation, statusValidationTestIndex)),
			perType:         map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: boolPtr(true)}},
			expectedResult:  true,
			expectedError:   nil,
			expectedNoFetch: true,
		},
		{
			testName:        "Type present but Enabled=false is a no-op",
			credential:      newCredentialWithStatus(t, statusValidationTestType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeRevocation, statusValidationTestIndex)),
			perType:         map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: boolPtr(false)}},
			expectedResult:  true,
			expectedError:   nil,
			expectedNoFetch: true,
		},
		{
			testName:        "Enabled, no credentialStatus, RequireStatus=false -> valid",
			credential:      newCredentialWithStatus(t, statusValidationTestType, nil),
			perType:         map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: boolPtr(true)}},
			expectedResult:  true,
			expectedError:   nil,
			expectedNoFetch: true,
		},
		{
			testName:        "Enabled, no credentialStatus, RequireStatus=true -> ErrorStatusMissing",
			credential:      newCredentialWithStatus(t, statusValidationTestType, nil),
			perType:         map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: boolPtr(true), RequireStatus: true}},
			expectedResult:  false,
			expectedError:   ErrorStatusMissing,
			expectedNoFetch: true,
		},
		{
			testName:       "Revoked bit set -> ErrorCredentialRevoked",
			credential:     newCredentialWithStatus(t, statusValidationTestType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeRevocation, statusValidationTestIndex)),
			perType:        map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: boolPtr(true)}},
			fixtures:       map[string]*common.Credential{statusValidationTestURL: revokedList},
			expectedResult: false,
			expectedError:  ErrorCredentialRevoked,
		},
		{
			testName:       "Revoked bit clear -> valid",
			credential:     newCredentialWithStatus(t, statusValidationTestType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeRevocation, statusValidationTestIndex)),
			perType:        map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: boolPtr(true)}},
			fixtures:       map[string]*common.Credential{statusValidationTestURL: clearList},
			expectedResult: true,
			expectedError:  nil,
		},
		{
			testName:   "Status purpose not in AcceptedPurposes is skipped",
			credential: newCredentialWithStatus(t, statusValidationTestType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeSuspension, statusValidationTestIndex)),
			perType: map[string]configModel.CredentialStatus{
				statusValidationTestType: {Enabled: boolPtr(true), AcceptedPurposes: []string{configModel.StatusPurposeRevocation}},
			},
			expectedResult:  true,
			expectedError:   nil,
			expectedNoFetch: true,
		},
		{
			testName:       "Fetch failure is propagated",
			credential:     newCredentialWithStatus(t, statusValidationTestType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeRevocation, statusValidationTestIndex)),
			perType:        map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: boolPtr(true)}},
			fetchErr:       ErrorStatusListHttpFailure,
			expectedResult: false,
			expectedError:  ErrorStatusListHttpFailure,
		},
		{
			testName:       "Malformed bitstring -> ErrorStatusListUnparseable",
			credential:     newCredentialWithStatus(t, statusValidationTestType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeRevocation, statusValidationTestIndex)),
			perType:        map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: boolPtr(true)}},
			fixtures:       map[string]*common.Credential{statusValidationTestURL: malformedList},
			expectedResult: false,
			expectedError:  ErrorStatusListUnparseable,
		},
		{
			testName:       "Fetched credential without status list type -> ErrorStatusListUnparseable",
			credential:     newCredentialWithStatus(t, statusValidationTestType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeRevocation, statusValidationTestIndex)),
			perType:        map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: boolPtr(true)}},
			fixtures:       map[string]*common.Credential{statusValidationTestURL: wrongTypeList},
			expectedResult: false,
			expectedError:  ErrorStatusListUnparseable,
		},
		{
			testName: "Two entries (suspension clear + revocation set) -> ErrorCredentialRevoked",
			credential: newCredentialWithStatus(t, statusValidationTestType, []interface{}{
				bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeSuspension, statusValidationTestIndex),
				bitstringStatusEntry(statusValidationTestURLAlt, configModel.StatusPurposeRevocation, statusValidationTestIndex),
			}),
			perType: map[string]configModel.CredentialStatus{
				statusValidationTestType: {
					Enabled:          boolPtr(true),
					AcceptedPurposes: []string{configModel.StatusPurposeRevocation, configModel.StatusPurposeSuspension},
				},
			},
			fixtures: map[string]*common.Credential{
				statusValidationTestURL:    suspensionClearList,
				statusValidationTestURLAlt: altRevokedList,
			},
			expectedResult: false,
			expectedError:  ErrorCredentialRevoked,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			mock := &mockStatusListClient{credentials: tc.fixtures, err: tc.fetchErr}
			service := NewCredentialStatusValidationService(mock, nil, nil)

			result, err := service.ValidateVC(tc.credential, CredentialStatusValidationContext{PerType: tc.perType})

			if result != tc.expectedResult {
				t.Errorf("expected result %v, got %v", tc.expectedResult, result)
			}
			if tc.expectedError == nil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else if !errors.Is(err, tc.expectedError) {
				t.Errorf("expected error %v, got %v", tc.expectedError, err)
			}
			if tc.expectedNoFetch && len(mock.calls) != 0 {
				t.Errorf("expected no fetches, got %d (URLs=%v)", len(mock.calls), mock.calls)
			}
		})
	}
}

// TestCredentialStatusValidationService_ContextMismatch asserts that passing
// a validation context of the wrong concrete type yields
// ErrorCannotConverContext rather than panicking. The recover-guard in the
// service relies on this shape to interoperate with the single
// ValidateVC(cred, ValidationContext) signature shared across services.
func TestCredentialStatusValidationService_ContextMismatch(t *testing.T) {
	mock := &mockStatusListClient{}
	service := NewCredentialStatusValidationService(mock, nil, nil)

	cred := newCredentialWithStatus(t, statusValidationTestType, nil)

	// A context value of a different concrete type must be rejected.
	result, err := service.ValidateVC(cred, TrustRegistriesValidationContext{})

	if result {
		t.Errorf("expected result=false on context mismatch, got true")
	}
	if !errors.Is(err, ErrorCannotConverContext) {
		t.Errorf("expected ErrorCannotConverContext, got %v", err)
	}
	if len(mock.calls) != 0 {
		t.Errorf("expected no fetches on context mismatch, got %d", len(mock.calls))
	}
}

// ---------------------------------------------------------------------------
// IETF Token Status List tests
// ---------------------------------------------------------------------------

// mockIETFStatusListClient is a test double for IETFStatusListClient.
type mockIETFStatusListClient struct {
	statusList *common.IETFStatusList
	err        error
	calls      []string
	// refreshedStatusList is returned after InvalidateIETF is called,
	// simulating a fresh fetch with an updated list.
	refreshedStatusList *common.IETFStatusList
	invalidated         bool
}

func (m *mockIETFStatusListClient) FetchIETF(uri string) (*common.IETFStatusList, error) {
	m.calls = append(m.calls, uri)
	if m.invalidated && m.refreshedStatusList != nil {
		return m.refreshedStatusList, m.err
	}
	return m.statusList, m.err
}

func (m *mockIETFStatusListClient) InvalidateIETF(uri string) {
	m.invalidated = true
}

// encodeIETFTestBitstring returns base64url(zlib(bits)), the encoding the
// IETF Token Status List spec requires on the `lst` field.
func encodeIETFTestBitstring(t *testing.T, bits []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(bits); err != nil {
		t.Fatalf("zlib write failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zlib close failed: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

// newCredentialWithIETFStatus builds a credential whose credentialSubject
// contains the IETF-format status reference.
func newCredentialWithIETFStatus(t *testing.T, credentialType string, idx uint64, uri string) *common.Credential {
	t.Helper()
	subject := common.Subject{
		CustomFields: common.CustomFields{
			common.IETFStatusClaimKey: map[string]interface{}{
				common.IETFStatusListKey: map[string]interface{}{
					common.IETFStatusListIdx: float64(idx),
					common.IETFStatusListURI: uri,
				},
			},
		},
	}
	cred, err := common.CreateCredential(common.CredentialContents{
		Types:   []string{credentialType},
		Subject: []common.Subject{subject},
	}, common.CustomFields{})
	if err != nil {
		t.Fatalf("CreateCredential failed: %v", err)
	}
	return cred
}

func TestCredentialStatusValidationService_IETF(t *testing.T) {
	const testURI = "https://example.org/statuslists/test-list"

	type test struct {
		testName       string
		credential     *common.Credential
		perType        map[string]configModel.CredentialStatus
		ietfList       *common.IETFStatusList
		ietfErr        error
		expectedResult bool
		expectedError  error
	}

	// A list where index 0 is clear (valid).
	clearBits := encodeIETFTestBitstring(t, []byte{0b00000000})
	// A list where index 1 is set (invalid), with 1 bit per status, LSB-first.
	revokedBits := encodeIETFTestBitstring(t, []byte{0b00000010})

	tests := []test{
		{
			testName:       "IETF: clear bit -> valid",
			credential:     newCredentialWithIETFStatus(t, statusValidationTestType, 0, testURI),
			perType:        map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: boolPtr(true)}},
			ietfList:       &common.IETFStatusList{Bits: 1, Lst: clearBits},
			expectedResult: true,
			expectedError:  nil,
		},
		{
			testName:       "IETF: set bit -> ErrorCredentialRevoked",
			credential:     newCredentialWithIETFStatus(t, statusValidationTestType, 1, testURI),
			perType:        map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: boolPtr(true)}},
			ietfList:       &common.IETFStatusList{Bits: 1, Lst: revokedBits},
			expectedResult: false,
			expectedError:  ErrorCredentialRevoked,
		},
		{
			testName:       "IETF: fetch error is propagated",
			credential:     newCredentialWithIETFStatus(t, statusValidationTestType, 0, testURI),
			perType:        map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: boolPtr(true)}},
			ietfErr:        ErrorStatusListHttpFailure,
			expectedResult: false,
			expectedError:  ErrorStatusListHttpFailure,
		},
		{
			testName:       "IETF: disabled config is a no-op",
			credential:     newCredentialWithIETFStatus(t, statusValidationTestType, 0, testURI),
			perType:        map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: boolPtr(false)}},
			expectedResult: true,
			expectedError:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			w3cMock := &mockStatusListClient{}
			ietfMock := &mockIETFStatusListClient{statusList: tc.ietfList, err: tc.ietfErr}
			service := NewCredentialStatusValidationService(w3cMock, ietfMock, nil)

			result, err := service.ValidateVC(tc.credential, CredentialStatusValidationContext{PerType: tc.perType})

			if result != tc.expectedResult {
				t.Errorf("expected result %v, got %v", tc.expectedResult, result)
			}
			if tc.expectedError == nil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else if !errors.Is(err, tc.expectedError) {
				t.Errorf("expected error %v, got %v", tc.expectedError, err)
			}
		})
	}
}

func TestCredentialStatusValidationService_IETF_RetryOnOutOfRange(t *testing.T) {
	testURI := "https://example.org/statuslists/test-list"

	// The cached list has 1 byte (8 bits), so index 10 is out of range.
	smallBits := encodeIETFTestBitstring(t, []byte{0b00000000})
	// After a fresh fetch the list has 2 bytes (16 bits), covering index 10.
	grownBits := encodeIETFTestBitstring(t, []byte{0b00000000, 0b00000000})

	tests := []struct {
		testName       string
		index          uint64
		initial        *common.IETFStatusList
		refreshed      *common.IETFStatusList
		expectedResult bool
		expectedError  error
		expectedCalls  int
	}{
		{
			testName:       "retry succeeds after cache eviction",
			index:          10,
			initial:        &common.IETFStatusList{Bits: 1, Lst: smallBits},
			refreshed:      &common.IETFStatusList{Bits: 1, Lst: grownBits},
			expectedResult: true,
			expectedError:  nil,
			expectedCalls:  2,
		},
		{
			testName:       "retry still out of range after fresh fetch",
			index:          20,
			initial:        &common.IETFStatusList{Bits: 1, Lst: smallBits},
			refreshed:      &common.IETFStatusList{Bits: 1, Lst: grownBits},
			expectedResult: false,
			expectedError:  common.ErrorStatusListIndexOutOfRange,
			expectedCalls:  2,
		},
		{
			testName:       "no retry needed when index is in range",
			index:          3,
			initial:        &common.IETFStatusList{Bits: 1, Lst: smallBits},
			refreshed:      nil,
			expectedResult: true,
			expectedError:  nil,
			expectedCalls:  1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			ietfMock := &mockIETFStatusListClient{
				statusList:          tc.initial,
				refreshedStatusList: tc.refreshed,
			}
			service := NewCredentialStatusValidationService(nil, ietfMock, nil)
			cred := newCredentialWithIETFStatus(t, statusValidationTestType, tc.index, testURI)
			perType := map[string]configModel.CredentialStatus{
				statusValidationTestType: {Enabled: boolPtr(true)},
			}

			result, err := service.ValidateVC(cred, CredentialStatusValidationContext{PerType: perType})

			if result != tc.expectedResult {
				t.Errorf("expected result %v, got %v", tc.expectedResult, result)
			}
			if tc.expectedError == nil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else if !errors.Is(err, tc.expectedError) {
				t.Errorf("expected error %v, got %v", tc.expectedError, err)
			}
			if len(ietfMock.calls) != tc.expectedCalls {
				t.Errorf("expected %d FetchIETF calls, got %d", tc.expectedCalls, len(ietfMock.calls))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// StatusListJWTVerifierImpl tests
// ---------------------------------------------------------------------------

// generateTestKeyAndDID creates an ECDSA P-256 key pair and returns the
// private key along with its did:jwk DID string. The did:jwk DID is
// constructed by base64url-encoding the public JWK, making it trivially
// resolvable by did.NewJWKVDR().
func generateTestKeyAndDID(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubJWK, err := jwk.Import(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("import public key to JWK: %v", err)
	}
	pubJSON, err := json.Marshal(pubJWK)
	if err != nil {
		t.Fatalf("marshal public JWK: %v", err)
	}
	didJWK := "did:jwk:" + base64.RawURLEncoding.EncodeToString(pubJSON)
	return privateKey, didJWK
}

// generateTestKey creates an ECDSA P-256 key pair without a DID.
func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// generateSelfSignedCert creates a self-signed X.509 certificate from the
// given key for x5c testing.
func generateSelfSignedCert(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return certDER
}

// buildStatusListJWTWithISS creates a signed JWT with the `iss` claim set
// to the given DID so that the verifier resolves the key via DID resolution.
func buildStatusListJWTWithISS(t *testing.T, payload map[string]interface{}, privateKey *ecdsa.PrivateKey, issuerDID string) []byte {
	t.Helper()
	payload["iss"] = issuerDID

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		t.Fatalf("import private key: %v", err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set("typ", "statuslist+jwt")

	signed, err := jws.Sign(payloadBytes, jws.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

// buildStatusListJWTWithX5C creates a signed JWT with an x5c header (no iss
// claim) so that the verifier falls back to x5c certificate chain verification.
func buildStatusListJWTWithX5C(t *testing.T, payload map[string]interface{}, privateKey *ecdsa.PrivateKey, certDER []byte) []byte {
	t.Helper()

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		t.Fatalf("import private key: %v", err)
	}

	var chain cert.Chain
	certB64 := base64.StdEncoding.EncodeToString(certDER)
	if err := chain.AddString(certB64); err != nil {
		t.Fatalf("add cert to chain: %v", err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set("typ", "statuslist+jwt")
	_ = hdrs.Set("x5c", &chain)

	signed, err := jws.Sign(payloadBytes, jws.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

// newTestStatusListJWTVerifier creates a StatusListJWTVerifierImpl backed by
// a registry that supports did:jwk resolution.
func newTestStatusListJWTVerifier() *StatusListJWTVerifierImpl {
	registry := did.NewRegistry(did.WithVDR(did.NewJWKVDR()))
	return NewStatusListJWTVerifier(registry)
}

// --- ISS-based (DID resolution) tests ---

func TestStatusListJWTVerifier_ISS_ValidSignature(t *testing.T) {
	privateKey, issuerDID := generateTestKeyAndDID(t)
	payload := map[string]interface{}{
		"status_list": map[string]interface{}{
			"bits": 1,
			"lst":  "eNpjAAAAAQAB",
		},
		"sub": "https://example.org/statuslists/1",
	}

	jwtBytes := buildStatusListJWTWithISS(t, payload, privateKey, issuerDID)

	verifier := newTestStatusListJWTVerifier()
	verified, err := verifier.VerifyStatusListJWT(jwtBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(verified, &claims); err != nil {
		t.Fatalf("unmarshal verified payload: %v", err)
	}
	if claims["sub"] != "https://example.org/statuslists/1" {
		t.Errorf("unexpected sub claim: %v", claims["sub"])
	}
}

func TestStatusListJWTVerifier_ISS_TamperedPayload(t *testing.T) {
	privateKey, issuerDID := generateTestKeyAndDID(t)
	payload := map[string]interface{}{"sub": "original"}

	jwtBytes := buildStatusListJWTWithISS(t, payload, privateKey, issuerDID)

	parts := bytes.SplitN(jwtBytes, []byte("."), 3)
	tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"tampered","iss":"` + issuerDID + `"}`))
	tampered := append(parts[0], '.')
	tampered = append(tampered, []byte(tamperedPayload)...)
	tampered = append(tampered, '.')
	tampered = append(tampered, parts[2]...)

	verifier := newTestStatusListJWTVerifier()
	_, err := verifier.VerifyStatusListJWT(tampered)
	if err == nil {
		t.Fatal("expected error for tampered payload, got nil")
	}
	if !errors.Is(err, ErrorStatusListUnparseable) {
		t.Errorf("expected ErrorStatusListUnparseable, got %v", err)
	}
}

func TestStatusListJWTVerifier_ISS_WrongKey(t *testing.T) {
	signingKey, _ := generateTestKeyAndDID(t)
	_, wrongDID := generateTestKeyAndDID(t)

	payload := map[string]interface{}{"sub": "test"}
	jwtBytes := buildStatusListJWTWithISS(t, payload, signingKey, wrongDID)

	verifier := newTestStatusListJWTVerifier()
	_, err := verifier.VerifyStatusListJWT(jwtBytes)
	if err == nil {
		t.Fatal("expected error when iss DID does not match signing key, got nil")
	}
	if !errors.Is(err, ErrorStatusListUnparseable) {
		t.Errorf("expected ErrorStatusListUnparseable, got %v", err)
	}
}

// --- X5C fallback tests (no iss claim) ---

func TestStatusListJWTVerifier_X5C_ValidSignature(t *testing.T) {
	privateKey := generateTestKey(t)
	certDER := generateSelfSignedCert(t, privateKey)
	payload := map[string]interface{}{
		"status_list": map[string]interface{}{
			"bits": 1,
			"lst":  "eNpjAAAAAQAB",
		},
		"sub": "https://example.org/statuslists/1",
	}

	jwtBytes := buildStatusListJWTWithX5C(t, payload, privateKey, certDER)

	verifier := newTestStatusListJWTVerifier()
	verified, err := verifier.VerifyStatusListJWT(jwtBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(verified, &claims); err != nil {
		t.Fatalf("unmarshal verified payload: %v", err)
	}
	if claims["sub"] != "https://example.org/statuslists/1" {
		t.Errorf("unexpected sub claim: %v", claims["sub"])
	}
}

func TestStatusListJWTVerifier_X5C_TamperedPayload(t *testing.T) {
	privateKey := generateTestKey(t)
	certDER := generateSelfSignedCert(t, privateKey)
	payload := map[string]interface{}{"sub": "original"}

	jwtBytes := buildStatusListJWTWithX5C(t, payload, privateKey, certDER)

	parts := bytes.SplitN(jwtBytes, []byte("."), 3)
	tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"tampered"}`))
	tampered := append(parts[0], '.')
	tampered = append(tampered, []byte(tamperedPayload)...)
	tampered = append(tampered, '.')
	tampered = append(tampered, parts[2]...)

	verifier := newTestStatusListJWTVerifier()
	_, err := verifier.VerifyStatusListJWT(tampered)
	if err == nil {
		t.Fatal("expected error for tampered payload, got nil")
	}
	if !errors.Is(err, ErrorStatusListUnparseable) {
		t.Errorf("expected ErrorStatusListUnparseable, got %v", err)
	}
}

func TestStatusListJWTVerifier_X5C_WrongKey(t *testing.T) {
	signingKey := generateTestKey(t)
	wrongKey := generateTestKey(t)
	wrongCertDER := generateSelfSignedCert(t, wrongKey)

	payload := map[string]interface{}{"sub": "test"}
	jwtBytes := buildStatusListJWTWithX5C(t, payload, signingKey, wrongCertDER)

	verifier := newTestStatusListJWTVerifier()
	_, err := verifier.VerifyStatusListJWT(jwtBytes)
	if err == nil {
		t.Fatal("expected error when x5c cert does not match signing key, got nil")
	}
	if !errors.Is(err, ErrorStatusListUnparseable) {
		t.Errorf("expected ErrorStatusListUnparseable, got %v", err)
	}
}

func TestStatusListJWTVerifier_NoISSNoX5C(t *testing.T) {
	privateKey := generateTestKey(t)
	payloadBytes := []byte(`{"sub":"test"}`)

	key, err := jwk.Import(privateKey)
	if err != nil {
		t.Fatalf("import key: %v", err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set("typ", "statuslist+jwt")

	signed, err := jws.Sign(payloadBytes, jws.WithKey(jwa.ES256(), key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	verifier := newTestStatusListJWTVerifier()
	_, err = verifier.VerifyStatusListJWT(signed)
	if err == nil {
		t.Fatal("expected error when neither iss nor x5c is present, got nil")
	}
	if !errors.Is(err, ErrorStatusListUnparseable) {
		t.Errorf("expected ErrorStatusListUnparseable, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// parseIETFStatusListPayload claim verification tests
// ---------------------------------------------------------------------------

// fixedTimeClock is a Clock that always returns a fixed time, allowing
// tests to control the "now" value for exp-claim verification.
type fixedTimeClock struct {
	now time.Time
}

func (c fixedTimeClock) Now() time.Time { return c.now }

func TestParseIETFStatusListPayload_ClaimVerification(t *testing.T) {
	const expectedURI = "https://example.org/statuslists/1"

	// A reference "now" for exp tests.
	referenceNow := time.Unix(1700000000, 0)
	// exp in the future relative to referenceNow.
	expFuture := float64(referenceNow.Unix() + 3600)
	// exp in the past relative to referenceNow.
	expPast := float64(referenceNow.Unix() - 3600)

	type test struct {
		testName      string
		payload       map[string]interface{}
		expectedURI   string
		clock         common.Clock
		expectedError error
		expectedTTL   *time.Duration
	}

	validStatusList := map[string]interface{}{
		"bits": 1,
		"lst":  "eNpjAAAAAQAB",
	}

	ttl60s := 60 * time.Second
	ttl300s := 300 * time.Second

	tests := []test{
		// --- sub claim ---
		{
			testName: "sub matches URI",
			payload: map[string]interface{}{
				"sub":         expectedURI,
				"status_list": validStatusList,
			},
			expectedURI:   expectedURI,
			clock:         fixedTimeClock{now: referenceNow},
			expectedError: nil,
		},
		{
			testName: "sub does not match URI",
			payload: map[string]interface{}{
				"sub":         "https://wrong.example.org/statuslists/99",
				"status_list": validStatusList,
			},
			expectedURI:   expectedURI,
			clock:         fixedTimeClock{now: referenceNow},
			expectedError: ErrorStatusListSubjectMismatch,
		},
		{
			testName: "sub claim missing",
			payload: map[string]interface{}{
				"status_list": validStatusList,
			},
			expectedURI:   expectedURI,
			clock:         fixedTimeClock{now: referenceNow},
			expectedError: ErrorStatusListSubjectMismatch,
		},
		{
			testName: "sub is empty string",
			payload: map[string]interface{}{
				"sub":         "",
				"status_list": validStatusList,
			},
			expectedURI:   expectedURI,
			clock:         fixedTimeClock{now: referenceNow},
			expectedError: ErrorStatusListSubjectMismatch,
		},
		// --- exp claim ---
		{
			testName: "exp in the future is accepted",
			payload: map[string]interface{}{
				"sub":         expectedURI,
				"exp":         expFuture,
				"status_list": validStatusList,
			},
			expectedURI:   expectedURI,
			clock:         fixedTimeClock{now: referenceNow},
			expectedError: nil,
		},
		{
			testName: "exp in the past is rejected",
			payload: map[string]interface{}{
				"sub":         expectedURI,
				"exp":         expPast,
				"status_list": validStatusList,
			},
			expectedURI:   expectedURI,
			clock:         fixedTimeClock{now: referenceNow},
			expectedError: ErrorStatusListExpired,
		},
		{
			testName: "exp absent is accepted",
			payload: map[string]interface{}{
				"sub":         expectedURI,
				"status_list": validStatusList,
			},
			expectedURI:   expectedURI,
			clock:         fixedTimeClock{now: referenceNow},
			expectedError: nil,
		},
		// --- ttl claim ---
		{
			testName: "ttl is extracted when present",
			payload: map[string]interface{}{
				"sub":         expectedURI,
				"ttl":         float64(60),
				"status_list": validStatusList,
			},
			expectedURI: expectedURI,
			clock:       fixedTimeClock{now: referenceNow},
			expectedTTL: &ttl60s,
		},
		{
			testName: "ttl with larger value",
			payload: map[string]interface{}{
				"sub":         expectedURI,
				"ttl":         float64(300),
				"status_list": validStatusList,
			},
			expectedURI: expectedURI,
			clock:       fixedTimeClock{now: referenceNow},
			expectedTTL: &ttl300s,
		},
		{
			testName: "ttl absent leaves result.ttl nil",
			payload: map[string]interface{}{
				"sub":         expectedURI,
				"status_list": validStatusList,
			},
			expectedURI: expectedURI,
			clock:       fixedTimeClock{now: referenceNow},
			expectedTTL: nil,
		},
		{
			testName: "ttl zero is rejected",
			payload: map[string]interface{}{
				"sub":         expectedURI,
				"ttl":         float64(0),
				"status_list": validStatusList,
			},
			expectedURI:   expectedURI,
			clock:         fixedTimeClock{now: referenceNow},
			expectedError: ErrorStatusListUnparseable,
		},
		{
			testName: "ttl negative is rejected",
			payload: map[string]interface{}{
				"sub":         expectedURI,
				"ttl":         float64(-10),
				"status_list": validStatusList,
			},
			expectedURI:   expectedURI,
			clock:         fixedTimeClock{now: referenceNow},
			expectedError: ErrorStatusListUnparseable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			payloadBytes, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}

			result, err := parseIETFStatusListPayload(payloadBytes, tc.expectedURI, tc.clock)

			if tc.expectedError == nil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if result == nil {
					t.Fatal("expected non-nil result")
				}
				if tc.expectedTTL == nil {
					if result.ttl != nil {
						t.Errorf("expected nil ttl, got %v", *result.ttl)
					}
				} else {
					if result.ttl == nil {
						t.Fatalf("expected ttl=%v, got nil", *tc.expectedTTL)
					}
					if *result.ttl != *tc.expectedTTL {
						t.Errorf("expected ttl=%v, got %v", *tc.expectedTTL, *result.ttl)
					}
				}
			} else {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.expectedError)
				}
				if !errors.Is(err, tc.expectedError) {
					t.Errorf("expected error %v, got %v", tc.expectedError, err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateStatusListJWTTyp tests
// ---------------------------------------------------------------------------

// buildRawJWT assembles a JWT from a header map, payload map and a dummy
// signature. No cryptographic signing is performed — this is only for
// testing header validation.
func buildRawJWT(t *testing.T, header, payload map[string]interface{}) []byte {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	p, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return []byte(
		base64.RawURLEncoding.EncodeToString(h) + "." +
			base64.RawURLEncoding.EncodeToString(p) + "." +
			base64.RawURLEncoding.EncodeToString([]byte("signature")),
	)
}

func TestValidateStatusListJWTTyp(t *testing.T) {
	type test struct {
		testName      string
		jwt           []byte
		expectedError error
	}

	tests := []test{
		{
			testName: "correct typ header",
			jwt: buildRawJWT(t,
				map[string]interface{}{"alg": "ES256", "typ": "statuslist+jwt"},
				map[string]interface{}{"sub": "x"},
			),
			expectedError: nil,
		},
		{
			testName: "wrong typ header",
			jwt: buildRawJWT(t,
				map[string]interface{}{"alg": "ES256", "typ": "JWT"},
				map[string]interface{}{"sub": "x"},
			),
			expectedError: ErrorStatusListInvalidTyp,
		},
		{
			testName: "typ header missing",
			jwt: buildRawJWT(t,
				map[string]interface{}{"alg": "ES256"},
				map[string]interface{}{"sub": "x"},
			),
			expectedError: ErrorStatusListInvalidTyp,
		},
		{
			testName:      "no dot separator",
			jwt:           []byte("nodots"),
			expectedError: ErrorStatusListUnparseable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			err := validateStatusListJWTTyp(tc.jwt)

			if tc.expectedError == nil {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.expectedError)
				}
				if !errors.Is(err, tc.expectedError) {
					t.Errorf("expected error %v, got %v", tc.expectedError, err)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseIETFBits tests
// ---------------------------------------------------------------------------

func TestParseIETFBits(t *testing.T) {
	type test struct {
		testName      string
		input         interface{}
		expectedBits  int
		expectedError bool
	}

	tests := []test{
		{testName: "bits=1 (float64)", input: float64(1), expectedBits: 1},
		{testName: "bits=2 (float64)", input: float64(2), expectedBits: 2},
		{testName: "bits=4 (float64)", input: float64(4), expectedBits: 4},
		{testName: "bits=8 (float64)", input: float64(8), expectedBits: 8},
		{testName: "bits=1 (int)", input: 1, expectedBits: 1},
		{testName: "bits=8 (int64)", input: int64(8), expectedBits: 8},
		{testName: "bits=3 is invalid", input: float64(3), expectedError: true},
		{testName: "bits=16 is invalid", input: float64(16), expectedError: true},
		{testName: "bits=0 is invalid", input: float64(0), expectedError: true},
		{testName: "bits=-1 is invalid", input: float64(-1), expectedError: true},
		{testName: "bits=nil is required", input: nil, expectedError: true},
		{testName: "bits=string is invalid type", input: "1", expectedError: true},
	}

	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			bits, err := parseIETFBits(tc.input)

			if tc.expectedError {
				if err == nil {
					t.Fatalf("expected error, got bits=%d", bits)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if bits != tc.expectedBits {
					t.Errorf("expected bits=%d, got %d", tc.expectedBits, bits)
				}
			}
		})
	}
}
