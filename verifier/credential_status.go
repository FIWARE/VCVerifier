package verifier

// credential_status.go implements the ValidationService that enforces the
// per-credential W3C Bitstring Status List / StatusList2021 revocation check.
//
// The service is wired into the verifier's validation chain by
// verifier.InitVerifier and is always appended; per-credential opt-in is
// expressed via the CredentialStatusValidationContext it receives at
// dispatch time. When no credential type has opted in, ValidateVC is a
// no-op and performs no network I/O.

import (
	"errors"
	"fmt"

	"github.com/fiware/VCVerifier/common"
	configModel "github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
)

// Typed errors returned by the CredentialStatusValidationService. They are
// exported so callers can match them with errors.Is when they need to
// distinguish a revoked credential from, for example, a missing
// credentialStatus entry.
var (
	// ErrorCredentialRevoked is returned when the bit referenced by a
	// credential's status-list entry is set, indicating that the issuer has
	// revoked (or, depending on purpose, suspended) the credential.
	ErrorCredentialRevoked = errors.New("credential_revoked")
	// ErrorStatusMissing is returned when a credential is required (via
	// config.CredentialStatus.RequireStatus) to carry a `credentialStatus`
	// entry but does not.
	ErrorStatusMissing = errors.New("credential_status_missing")
	// ErrorStatusListPurposeMismatch is returned when a fetched status-list
	// credential declares a `statusPurpose` that does not match the purpose
	// declared on the referencing credential's status-list entry.
	ErrorStatusListPurposeMismatch = errors.New("status_list_purpose_mismatch")
)

// CredentialStatusValidationContext carries the resolved per-credential-type
// configuration for the revocation-list check. The map key is the credential
// `type` value as it appears in the presented VC (for example
// "VerifiableCredential" or a custom type). The shape mirrors
// TrustRegistriesValidationContext.trustedIssuersLists so callers can build
// the context the same way for both services.
type CredentialStatusValidationContext struct {
	// PerType maps a credential type to its status-list configuration. A
	// credential with no matching entry — or only entries with
	// Enabled == false — is accepted without any network call.
	PerType map[string]configModel.CredentialStatus
}

// CredentialStatusValidationService is the ValidationService responsible for
// enforcing credential revocation via W3C Bitstring Status List /
// StatusList2021 credentials.
//
// The service is safe for concurrent use as long as the configured client is.
type CredentialStatusValidationService struct {
	client StatusListCredentialClient
	clock  common.Clock
}

// NewCredentialStatusValidationService constructs a ready-to-use validation
// service backed by the supplied status-list credential client and clock.
// The clock is retained for future use (for example to enforce the
// `validFrom`/`validUntil` window on a fetched status-list credential) and
// defaults to common.RealClock when nil.
func NewCredentialStatusValidationService(client StatusListCredentialClient, clock common.Clock) *CredentialStatusValidationService {
	if clock == nil {
		clock = common.RealClock{}
	}
	return &CredentialStatusValidationService{client: client, clock: clock}
}

// ValidateVC enforces the per-credential-type revocation-list check against
// the supplied credential.
//
// The method:
//   - casts the validation context to CredentialStatusValidationContext;
//     returns ErrorCannotConverContext on any other type;
//   - is a no-op (returns true, nil) when none of the credential's declared
//     types opts in via config.CredentialStatus.Enabled == true;
//   - extracts the `credentialStatus` field from the credential's raw JSON
//     and parses it with common.ParseStatusListEntries;
//   - returns ErrorStatusMissing when the credential must carry a status
//     entry but does not (merged RequireStatus across matching configs);
//   - for every recognised status-list entry whose purpose is accepted,
//     fetches the referenced status-list credential, decodes the bitstring
//     and inspects the bit at the entry's index;
//   - returns ErrorCredentialRevoked as soon as a bit is found set;
//   - logs and skips entries whose type is not recognised so the
//     verifier remains forward-compatible with future status-list flavours.
func (s *CredentialStatusValidationService) ValidateVC(verifiableCredential *common.Credential, validationContext ValidationContext) (result bool, err error) {
	logging.Log().Debugf("Validate credentialStatus for %s", logging.PrettyPrintObject(verifiableCredential))
	defer func() {
		if recErr := recover(); recErr != nil {
			logging.Log().Warnf("CredentialStatusValidationService: Was not able to convert context. Err: %v", recErr)
			err = ErrorCannotConverContext
		}
	}()

	statusContext, ok := validationContext.(CredentialStatusValidationContext)
	if !ok {
		logging.Log().Warnf("CredentialStatusValidationService: Was not able to convert context of type %T", validationContext)
		return false, ErrorCannotConverContext
	}

	matchingConfigs := collectMatchingStatusConfigs(verifiableCredential.Contents().Types, statusContext.PerType)
	if len(matchingConfigs) == 0 {
		// Feature off for every declared type → nothing to check.
		return true, nil
	}

	acceptedPurposes := mergeAcceptedPurposes(matchingConfigs)
	requireStatus := mergeRequireStatus(matchingConfigs)

	raw := verifiableCredential.ToRawJSON()
	rawStatus := raw[common.VCKeyCredentialStatus]

	entries, err := common.ParseStatusListEntries(rawStatus)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrorStatusListUnparseable, err)
	}

	if len(entries) == 0 {
		if requireStatus {
			logging.Log().Warnf("Credential %s has no credentialStatus but RequireStatus is true", verifiableCredential.Contents().ID)
			return false, ErrorStatusMissing
		}
		return true, nil
	}

	for _, entry := range entries {
		if !isRecognisedStatusEntryType(entry.Type) {
			logging.Log().Debugf("Skipping unrecognised credentialStatus entry type %q", entry.Type)
			continue
		}
		if !isPurposeAccepted(entry.StatusPurpose, acceptedPurposes) {
			logging.Log().Debugf("Skipping credentialStatus entry with purpose %q (not in acceptedPurposes %v)", entry.StatusPurpose, acceptedPurposes)
			continue
		}

		statusCred, fetchErr := s.client.Fetch(entry.StatusListCredential)
		if fetchErr != nil {
			return false, fetchErr
		}

		encodedList, purpose, extractErr := extractStatusListFields(statusCred)
		if extractErr != nil {
			return false, fmt.Errorf("%w: %v", ErrorStatusListUnparseable, extractErr)
		}

		if purpose != "" && entry.StatusPurpose != "" && purpose != entry.StatusPurpose {
			logging.Log().Warnf("Status-list credential purpose %q does not match entry purpose %q", purpose, entry.StatusPurpose)
			return false, ErrorStatusListPurposeMismatch
		}

		bitstring, decodeErr := common.DecodeBitstring(encodedList)
		if decodeErr != nil {
			return false, fmt.Errorf("%w: %v", ErrorStatusListUnparseable, decodeErr)
		}

		set, idxErr := common.IsStatusSet(bitstring, entry.StatusListIndex, entry.StatusSize)
		if idxErr != nil {
			return false, fmt.Errorf("%w: %v", ErrorStatusListUnparseable, idxErr)
		}
		if set {
			logging.Log().Infof("Credential %s is revoked (purpose=%s, index=%d)", verifiableCredential.Contents().ID, entry.StatusPurpose, entry.StatusListIndex)
			return false, ErrorCredentialRevoked
		}
	}

	return true, nil
}

// collectMatchingStatusConfigs returns the subset of `perType` entries whose
// key matches one of the credential's declared types AND whose `Enabled`
// flag is true. The returned slice preserves the type order declared on the
// credential so merge ordering is deterministic for callers.
func collectMatchingStatusConfigs(credentialTypes []string, perType map[string]configModel.CredentialStatus) []configModel.CredentialStatus {
	matching := make([]configModel.CredentialStatus, 0, len(credentialTypes))
	for _, credentialType := range credentialTypes {
		cfg, found := perType[credentialType]
		if !found {
			continue
		}
		if !cfg.Enabled {
			continue
		}
		matching = append(matching, cfg)
	}
	return matching
}

// mergeAcceptedPurposes returns the union of `AcceptedPurposes` declared on
// every matching config. An empty result defaults to
// configModel.DefaultAcceptedStatusPurposes() so the behaviour matches the
// documented "defaults to [revocation]" semantic.
func mergeAcceptedPurposes(matchingConfigs []configModel.CredentialStatus) []string {
	seen := map[string]bool{}
	merged := []string{}
	for _, cfg := range matchingConfigs {
		for _, purpose := range cfg.AcceptedPurposes {
			if seen[purpose] {
				continue
			}
			seen[purpose] = true
			merged = append(merged, purpose)
		}
	}
	if len(merged) == 0 {
		return configModel.DefaultAcceptedStatusPurposes()
	}
	return merged
}

// mergeRequireStatus returns true when ANY matching config demands a
// `credentialStatus` entry. The semantics follow the "most restrictive
// wins" rule used throughout the verifier for per-type merges.
func mergeRequireStatus(matchingConfigs []configModel.CredentialStatus) bool {
	for _, cfg := range matchingConfigs {
		if cfg.RequireStatus {
			return true
		}
	}
	return false
}

// isRecognisedStatusEntryType reports whether the given `type` value on a
// credentialStatus entry is one of the status-list entry types this
// verifier knows how to evaluate. Unknown types are skipped with a debug
// log so future list formats do not cause a hard failure.
func isRecognisedStatusEntryType(entryType string) bool {
	switch entryType {
	case common.TypeBitstringStatusListEntry, common.TypeStatusList2021Entry:
		return true
	default:
		return false
	}
}

// isPurposeAccepted reports whether `purpose` appears in `acceptedPurposes`.
// An empty `purpose` is accepted unconditionally because older status-list
// entries may omit the field; the referencing credential's configured
// purposes are still enforced through the fetched status-list credential.
func isPurposeAccepted(purpose string, acceptedPurposes []string) bool {
	if purpose == "" {
		return true
	}
	for _, accepted := range acceptedPurposes {
		if accepted == purpose {
			return true
		}
	}
	return false
}

// extractStatusListFields pulls the `encodedList` and `statusPurpose` fields
// out of a fetched status-list credential's `credentialSubject`. The
// credential subject can be either a single object or an array; both shapes
// are supported here so issuers can follow either VC Data Model flavour.
//
// A non-nil error is returned when the credential does not expose an
// `encodedList` string on at least one subject.
func extractStatusListFields(statusCred *common.Credential) (encodedList string, statusPurpose string, err error) {
	if statusCred == nil {
		return "", "", fmt.Errorf("status-list credential is nil")
	}
	raw := statusCred.ToRawJSON()
	subjectRaw, ok := raw[common.VCKeyCredentialSubject]
	if !ok || subjectRaw == nil {
		return "", "", fmt.Errorf("status-list credential has no %q", common.VCKeyCredentialSubject)
	}

	switch subject := subjectRaw.(type) {
	case map[string]interface{}:
		return readEncodedListFromSubject(subject)
	case []interface{}:
		for _, item := range subject {
			obj, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			list, purpose, readErr := readEncodedListFromSubject(obj)
			if readErr == nil {
				return list, purpose, nil
			}
		}
		return "", "", fmt.Errorf("no subject in status-list credential exposes %q", common.StatusListKeyEncodedList)
	default:
		return "", "", fmt.Errorf("status-list credential %q has unexpected type %T", common.VCKeyCredentialSubject, subjectRaw)
	}
}

// readEncodedListFromSubject extracts the encoded bitstring and optional
// purpose from a single credentialSubject object. The `statusPurpose` is
// returned as an empty string when absent so callers can treat that as
// "purpose not declared" rather than an error.
func readEncodedListFromSubject(subject map[string]interface{}) (string, string, error) {
	encoded, ok := subject[common.StatusListKeyEncodedList].(string)
	if !ok || encoded == "" {
		return "", "", fmt.Errorf("status-list subject missing %q", common.StatusListKeyEncodedList)
	}
	purpose, _ := subject[common.StatusListKeyStatusPurpose].(string)
	return encoded, purpose, nil
}

// Compile-time assertion that CredentialStatusValidationService satisfies
// the ValidationService interface. This protects callers who register the
// service through the interface from accidental signature drift.
var _ ValidationService = (*CredentialStatusValidationService)(nil)
