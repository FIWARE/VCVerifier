package common

import (
	"encoding/json"
	"time"
)

// ParseCredentialJSON parses a Verifiable Credential from its JSON representation.
func ParseCredentialJSON(data []byte) (*Credential, error) {
	var raw JSONObject
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	contents := CredentialContents{}

	if ctx, ok := raw[JSONLDKeyContext]; ok {
		contents.Context = toStringSlice(ctx)
	}
	if id, ok := raw[JSONLDKeyID].(string); ok {
		contents.ID = id
	}
	if t, ok := raw[JSONLDKeyType]; ok {
		contents.Types = toStringSlice(t)
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

	// validFrom (VC v2) or issuanceDate (VC v1)
	if vf, ok := raw[VCKeyValidFrom].(string); ok {
		if t, err := time.Parse(time.RFC3339, vf); err == nil {
			contents.ValidFrom = &t
		}
	} else if vf, ok := raw[VCKeyIssuanceDate].(string); ok {
		if t, err := time.Parse(time.RFC3339, vf); err == nil {
			contents.ValidFrom = &t
		}
	}

	// validUntil (VC v2) or expirationDate (VC v1)
	if vu, ok := raw[VCKeyValidUntil].(string); ok {
		if t, err := time.Parse(time.RFC3339, vu); err == nil {
			contents.ValidUntil = &t
		}
	} else if vu, ok := raw[VCKeyExpirationDate].(string); ok {
		if t, err := time.Parse(time.RFC3339, vu); err == nil {
			contents.ValidUntil = &t
		}
	}

	if cs, ok := raw[VCKeyCredentialSubject]; ok {
		contents.Subject = parseSubjects(cs)
	}

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

func toStringSlice(v interface{}) []string {
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
