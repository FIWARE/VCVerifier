package verifier

// credential_status_test.go exercises CredentialStatusValidationService via
// table-driven cases that mirror the patterns used in compliance_test.go and
// trustedissuer_test.go. The tests deliberately avoid real network I/O: a
// mockStatusListClient serves fixture status-list credentials from an
// in-memory map so every code branch can be reached deterministically.

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
)

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
}

// Fetch implements StatusListCredentialClient. When err is non-nil it is
// returned verbatim so tests can inject transport/parse failures. On the
// happy path the URL is looked up in `credentials` and a missing entry
// yields a distinct error that would fail any subsequent assertion — this
// guards against silent "revoked" false-positives caused by typos in the
// table rows.
func (m *mockStatusListClient) Fetch(url string) (*common.Credential, error) {
	m.calls = append(m.calls, url)
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
	cred, err := common.CreateCredential(common.CredentialContents{}, common.CustomFields{})
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

	// Two-entry fixture credentials for the suspension + revocation case.
	// The suspension list's URL differs from the revocation list's URL so
	// the mock client returns the correct fixture for each lookup.
	altRevokedList := newStatusListCredential(t, encodeTestBitstring(t, statusValidationRevokedByte), configModel.StatusPurposeRevocation)

	tests := []test{
		{
			testName:        "Type not present in PerType is a no-op",
			credential:      newCredentialWithStatus(t, statusValidationUnconfiguredType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeRevocation, statusValidationTestIndex)),
			perType:         map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: true}},
			expectedResult:  true,
			expectedError:   nil,
			expectedNoFetch: true,
		},
		{
			testName:        "Type present but Enabled=false is a no-op",
			credential:      newCredentialWithStatus(t, statusValidationTestType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeRevocation, statusValidationTestIndex)),
			perType:         map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: false}},
			expectedResult:  true,
			expectedError:   nil,
			expectedNoFetch: true,
		},
		{
			testName:        "Enabled, no credentialStatus, RequireStatus=false -> valid",
			credential:      newCredentialWithStatus(t, statusValidationTestType, nil),
			perType:         map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: true}},
			expectedResult:  true,
			expectedError:   nil,
			expectedNoFetch: true,
		},
		{
			testName:        "Enabled, no credentialStatus, RequireStatus=true -> ErrorStatusMissing",
			credential:      newCredentialWithStatus(t, statusValidationTestType, nil),
			perType:         map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: true, RequireStatus: true}},
			expectedResult:  false,
			expectedError:   ErrorStatusMissing,
			expectedNoFetch: true,
		},
		{
			testName:       "Revoked bit set -> ErrorCredentialRevoked",
			credential:     newCredentialWithStatus(t, statusValidationTestType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeRevocation, statusValidationTestIndex)),
			perType:        map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: true}},
			fixtures:       map[string]*common.Credential{statusValidationTestURL: revokedList},
			expectedResult: false,
			expectedError:  ErrorCredentialRevoked,
		},
		{
			testName:       "Revoked bit clear -> valid",
			credential:     newCredentialWithStatus(t, statusValidationTestType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeRevocation, statusValidationTestIndex)),
			perType:        map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: true}},
			fixtures:       map[string]*common.Credential{statusValidationTestURL: clearList},
			expectedResult: true,
			expectedError:  nil,
		},
		{
			testName:   "Status purpose not in AcceptedPurposes is skipped",
			credential: newCredentialWithStatus(t, statusValidationTestType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeSuspension, statusValidationTestIndex)),
			perType: map[string]configModel.CredentialStatus{
				statusValidationTestType: {Enabled: true, AcceptedPurposes: []string{configModel.StatusPurposeRevocation}},
			},
			expectedResult:  true,
			expectedError:   nil,
			expectedNoFetch: true,
		},
		{
			testName:       "Fetch failure is propagated",
			credential:     newCredentialWithStatus(t, statusValidationTestType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeRevocation, statusValidationTestIndex)),
			perType:        map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: true}},
			fetchErr:       ErrorStatusListHttpFailure,
			expectedResult: false,
			expectedError:  ErrorStatusListHttpFailure,
		},
		{
			testName:       "Malformed bitstring -> ErrorStatusListUnparseable",
			credential:     newCredentialWithStatus(t, statusValidationTestType, bitstringStatusEntry(statusValidationTestURL, configModel.StatusPurposeRevocation, statusValidationTestIndex)),
			perType:        map[string]configModel.CredentialStatus{statusValidationTestType: {Enabled: true}},
			fixtures:       map[string]*common.Credential{statusValidationTestURL: malformedList},
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
					Enabled:          true,
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
			service := NewCredentialStatusValidationService(mock, nil)

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
	service := NewCredentialStatusValidationService(mock, nil)

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
