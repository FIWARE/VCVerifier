package common

import (
	"encoding/json"
	"time"
)

// ParseCredentialDates extracts validFrom/validUntil (VC Data Model 2.0) from a raw VC
// JSON object, falling back to their VC Data Model 1.0/1.1 equivalents issuanceDate/
// expirationDate when the 2.0 properties are absent.
func ParseCredentialDates(raw JSONObject) (validFrom, validUntil *time.Time) {
	if vf, ok := raw[VCKeyValidFrom].(string); ok {
		if t, err := time.Parse(time.RFC3339, vf); err == nil {
			validFrom = &t
		}
	} else if vf, ok := raw[VCKeyIssuanceDate].(string); ok {
		if t, err := time.Parse(time.RFC3339, vf); err == nil {
			validFrom = &t
		}
	}

	if vu, ok := raw[VCKeyValidUntil].(string); ok {
		if t, err := time.Parse(time.RFC3339, vu); err == nil {
			validUntil = &t
		}
	} else if vu, ok := raw[VCKeyExpirationDate].(string); ok {
		if t, err := time.Parse(time.RFC3339, vu); err == nil {
			validUntil = &t
		}
	}

	return validFrom, validUntil
}

// ParseCredentialStatus extracts the first credentialStatus entry of a raw
// credential as a *TypedID.
//
// VCDM 2.0 allows credentialStatus to be either a single object or an array of
// them; the full value stays reachable through the credential's raw JSON for
// callers that need every entry.
//
// This is the one place the mapping lives. It used to be duplicated per parser
// and simply missing from ParseCredentialJSON, whose standardKeys set listed
// credentialStatus - so the field was neither copied into contents.Status nor
// kept as a custom field. Nothing errored; revocation checking just silently
// had nothing to check.
func ParseCredentialStatus(raw interface{}) *TypedID {
	switch v := raw.(type) {
	case map[string]interface{}:
		return typedIDFromMap(v)
	case []interface{}:
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				return typedIDFromMap(m)
			}
		}
	}
	return nil
}

// typedIDFromMap reads the id and type members of a JSON object, treating a
// missing or non-string member as empty.
func typedIDFromMap(m map[string]interface{}) *TypedID {
	id, _ := m[JSONLDKeyID].(string)
	typ, _ := m[JSONLDKeyType].(string)
	return &TypedID{ID: id, Type: typ}
}

// ParseCredentialJSON parses a Verifiable Credential from its JSON representation.
func ParseCredentialJSON(data []byte) (*Credential, error) {
	var raw JSONObject
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	contents := CredentialContents{}

	if ctx, ok := raw[JSONLDKeyContext]; ok {
		contents.Context = ToStringSlice(ctx)
	}
	if id, ok := raw[JSONLDKeyID].(string); ok {
		contents.ID = id
	}
	if t, ok := raw[JSONLDKeyType]; ok {
		contents.Types = ToStringSlice(t)
	}

	// issuer can be a string or an object with "id" field
	if iss, ok := raw[VCKeyIssuer]; ok {
		switch v := iss.(type) {
		case string:
			contents.Issuer = &Issuer{ID: v}
		case map[string]interface{}:
			if id, ok := v[JSONLDKeyID].(string); ok {
				contents.Issuer = &Issuer{ID: id}
			}
		}
	}

	contents.ValidFrom, contents.ValidUntil = ParseCredentialDates(raw)

	if cs, ok := raw[VCKeyCredentialSubject]; ok {
		contents.Subject = parseSubjects(cs)
	}

	contents.Status = ParseCredentialStatus(raw[VCKeyCredentialStatus])

	// Collect non-standard fields as custom fields
	standardKeys := map[string]bool{
		JSONLDKeyContext: true, JSONLDKeyID: true, JSONLDKeyType: true,
		VCKeyIssuer: true, VCKeyCredentialSubject: true,
		VCKeyValidFrom: true, VCKeyValidUntil: true,
		VCKeyIssuanceDate: true, VCKeyExpirationDate: true, VCKeyIssued: true,
		VCKeyCredentialStatus: true, VCKeyCredentialSchema: true,
		VCKeyEvidence: true, VCKeyTermsOfUse: true, VCKeyRefreshService: true,
		VPKeyProof: true,
	}
	customFields := CustomFields{}
	for k, v := range raw {
		if !standardKeys[k] {
			customFields[k] = v
		}
	}

	cred, err := CreateCredential(contents, customFields)
	if err != nil {
		return nil, err
	}
	cred.SetRawJSON(raw)
	return cred, nil
}

func parseSubjects(cs interface{}) []Subject {
	switch v := cs.(type) {
	case map[string]interface{}:
		return []Subject{parseOneSubject(v)}
	case []interface{}:
		subjects := make([]Subject, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				subjects = append(subjects, parseOneSubject(m))
			}
		}
		return subjects
	}
	return nil
}

func parseOneSubject(m map[string]interface{}) Subject {
	s := Subject{CustomFields: map[string]interface{}{}}
	if id, ok := m[JSONLDKeyID].(string); ok {
		s.ID = id
	}
	for k, v := range m {
		if k != JSONLDKeyID {
			s.CustomFields[k] = v
		}
	}
	return s
}

// ToStringSlice normalizes a JSON-decoded value that may hold either a single
// string or an array of strings into a []string. JSON-LD allows both spellings
// for keys such as `@context` and `type`, so every parser reading those keys must
// accept a plain string as well as an array. Values that are neither yield nil,
// and non-string array entries are skipped.
func ToStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case string:
		return []string{val}
	case []string:
		return val
	}
	return nil
}
