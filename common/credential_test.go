package common

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCreateCredential(t *testing.T) {
	validFrom := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	contents := CredentialContents{
		Context: []string{ContextCredentialsV2},
		ID:      "vc-1",
		Types:   []string{TypeVerifiableCredential, "MyType"},
		Issuer:  &Issuer{ID: "did:web:issuer.example.com"},
		Subject: []Subject{
			{ID: "did:web:subject.example.com", CustomFields: map[string]interface{}{"name": "Alice"}},
		},
		ValidFrom: &validFrom,
	}
	cred, err := CreateCredential(contents, CustomFields{"extra": "field"})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if cred == nil {
		t.Fatal("Expected credential, got nil")
	}

	c := cred.Contents()
	if c.ID != "vc-1" {
		t.Errorf("Expected ID vc-1, got %s", c.ID)
	}
	if len(c.Context) != 1 || c.Context[0] != ContextCredentialsV2 {
		t.Errorf("Expected context [%s], got %v", ContextCredentialsV2, c.Context)
	}
	if len(c.Types) != 2 || c.Types[0] != TypeVerifiableCredential {
		t.Errorf("Expected types [%s MyType], got %v", TypeVerifiableCredential, c.Types)
	}
	if c.Issuer.ID != "did:web:issuer.example.com" {
		t.Errorf("Expected issuer did:web:issuer.example.com, got %s", c.Issuer.ID)
	}
	if len(c.Subject) != 1 || c.Subject[0].ID != "did:web:subject.example.com" {
		t.Errorf("Unexpected subject: %v", c.Subject)
	}
	if c.Subject[0].CustomFields["name"] != "Alice" {
		t.Errorf("Expected name=Alice, got %v", c.Subject[0].CustomFields["name"])
	}
	if c.ValidFrom == nil || !c.ValidFrom.Equal(validFrom) {
		t.Errorf("Expected ValidFrom %v, got %v", validFrom, c.ValidFrom)
	}
}

func TestCredential_ToRawJSON(t *testing.T) {
	validFrom := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	cred, _ := CreateCredential(CredentialContents{
		Context:   []string{ContextCredentialsV2},
		ID:        "vc-1",
		Types:     []string{TypeVerifiableCredential},
		Issuer:    &Issuer{ID: "did:web:issuer.example.com"},
		Subject:   []Subject{{CustomFields: map[string]interface{}{"name": "Alice", "age": 30}}},
		ValidFrom: &validFrom,
		Status:    &TypedID{ID: "https://example.com/status/1", Type: "StatusList2021Entry"},
	}, CustomFields{})

	raw, err := cred.ToRawJSON()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if raw[JSONLDKeyID] != "vc-1" {
		t.Errorf("Expected id=vc-1, got %v", raw[JSONLDKeyID])
	}
	if raw[VCKeyIssuer] != "did:web:issuer.example.com" {
		t.Errorf("Expected issuer DID, got %v", raw[VCKeyIssuer])
	}
	if raw[VCKeyValidFrom] != "2024-01-01T00:00:00Z" {
		t.Errorf("Expected validFrom, got %v", raw[VCKeyValidFrom])
	}

	subj, ok := raw[VCKeyCredentialSubject].(JSONObject)
	if !ok {
		t.Fatalf("Expected single credentialSubject map, got %T", raw[VCKeyCredentialSubject])
	}
	if subj["name"] != "Alice" {
		t.Errorf("Expected name=Alice, got %v", subj["name"])
	}

	status, ok := raw[VCKeyCredentialStatus].(JSONObject)
	if !ok {
		t.Fatalf("Expected credentialStatus map, got %T", raw[VCKeyCredentialStatus])
	}
	if status[JSONLDKeyID] != "https://example.com/status/1" {
		t.Errorf("Expected status ID, got %v", status[JSONLDKeyID])
	}
}

func TestCredential_ToRawJSON_MultipleSubjects(t *testing.T) {
	cred, _ := CreateCredential(CredentialContents{
		Subject: []Subject{
			{ID: "s1", CustomFields: map[string]interface{}{"a": 1}},
			{ID: "s2", CustomFields: map[string]interface{}{"b": 2}},
		},
	}, CustomFields{})

	raw, err := cred.ToRawJSON()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	subjects, ok := raw[VCKeyCredentialSubject].([]JSONObject)
	if !ok {
		t.Fatalf("Expected []JSONObject for multiple subjects, got %T", raw[VCKeyCredentialSubject])
	}
	if len(subjects) != 2 {
		t.Errorf("Expected 2 subjects, got %d", len(subjects))
	}
}

func TestCredential_ToRawJSON_CustomFields(t *testing.T) {
	cred, _ := CreateCredential(CredentialContents{
		ID: "vc-1",
	}, CustomFields{JSONLDKeyContext: []string{ContextCredentialsV1}, "extra": "value"})

	raw, err := cred.ToRawJSON()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if raw[JSONLDKeyID] != "vc-1" {
		t.Errorf("Expected id=vc-1, got %v", raw[JSONLDKeyID])
	}
	if raw["extra"] != "value" {
		t.Errorf("Expected extra=value, got %v", raw["extra"])
	}
}

func TestCredential_ToRawJSON_SchemasAndEvidence(t *testing.T) {
	cred, _ := CreateCredential(CredentialContents{
		Schemas:  []TypedID{{ID: "https://example.com/schema", Type: "JsonSchema"}},
		Evidence: []interface{}{map[string]interface{}{"type": "DocumentVerification"}},
	}, CustomFields{})

	raw, err := cred.ToRawJSON()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	schemas, ok := raw[VCKeyCredentialSchema].([]JSONObject)
	if !ok || len(schemas) != 1 {
		t.Fatalf("Expected 1 schema, got %v", raw[VCKeyCredentialSchema])
	}
	if schemas[0][JSONLDKeyType] != "JsonSchema" {
		t.Errorf("Expected schema type JsonSchema, got %v", schemas[0][JSONLDKeyType])
	}
	evidence, ok := raw[VCKeyEvidence].([]interface{})
	if !ok || len(evidence) != 1 {
		t.Fatalf("Expected 1 evidence, got %v", raw[VCKeyEvidence])
	}
}

func TestCredential_MarshalJSON(t *testing.T) {
	cred, _ := CreateCredential(CredentialContents{
		ID:     "vc-1",
		Types:  []string{TypeVerifiableCredential},
		Issuer: &Issuer{ID: "did:web:issuer.example.com"},
	}, CustomFields{})

	data, err := cred.MarshalJSON()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if parsed[JSONLDKeyID] != "vc-1" {
		t.Errorf("Expected id=vc-1 in JSON, got %v", parsed[JSONLDKeyID])
	}
}

func TestNewPresentation(t *testing.T) {
	p, err := NewPresentation()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if p == nil {
		t.Fatal("Expected presentation, got nil")
	}
	if len(p.Credentials()) != 0 {
		t.Errorf("Expected empty credentials, got %d", len(p.Credentials()))
	}
}

func TestNewPresentation_WithCredentials(t *testing.T) {
	c1, _ := CreateCredential(CredentialContents{ID: "vc-1"}, CustomFields{})
	c2, _ := CreateCredential(CredentialContents{ID: "vc-2"}, CustomFields{})

	p, err := NewPresentation(WithCredentials(c1, c2))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(p.Credentials()) != 2 {
		t.Errorf("Expected 2 credentials, got %d", len(p.Credentials()))
	}
}

func TestPresentation_AddCredentials(t *testing.T) {
	p, _ := NewPresentation()
	c1, _ := CreateCredential(CredentialContents{ID: "vc-1"}, CustomFields{})

	p.AddCredentials(c1)
	if len(p.Credentials()) != 1 {
		t.Fatalf("Expected 1 credential, got %d", len(p.Credentials()))
	}
	if p.Credentials()[0].Contents().ID != "vc-1" {
		t.Errorf("Expected vc-1, got %s", p.Credentials()[0].Contents().ID)
	}
}

func TestPresentation_HolderAndID(t *testing.T) {
	p, _ := NewPresentation()
	p.Holder = "did:web:holder.example.com"
	p.ID = "vp-1"

	if p.Holder != "did:web:holder.example.com" {
		t.Errorf("Expected holder, got %s", p.Holder)
	}
	if p.ID != "vp-1" {
		t.Errorf("Expected ID vp-1, got %s", p.ID)
	}
}

func TestPresentation_MarshalJSON(t *testing.T) {
	c1, _ := CreateCredential(CredentialContents{
		ID:     "vc-1",
		Types:  []string{TypeVerifiableCredential},
		Issuer: &Issuer{ID: "did:web:issuer.example.com"},
	}, CustomFields{})

	p, _ := NewPresentation(WithCredentials(c1))
	p.Holder = "did:web:holder.example.com"
	p.ID = "vp-1"

	data, err := p.MarshalJSON()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
	if parsed[VPKeyHolder] != "did:web:holder.example.com" {
		t.Errorf("Expected holder in JSON, got %v", parsed[VPKeyHolder])
	}
	if parsed[JSONLDKeyID] != "vp-1" {
		t.Errorf("Expected id=vp-1 in JSON, got %v", parsed[JSONLDKeyID])
	}
	if parsed[JSONLDKeyType].([]interface{})[0] != TypeVerifiablePresentation {
		t.Errorf("Expected type=%s, got %v", TypeVerifiablePresentation, parsed[JSONLDKeyType])
	}

	vcs, ok := parsed[VPKeyVerifiableCredential].([]interface{})
	if !ok || len(vcs) != 1 {
		t.Fatalf("Expected 1 verifiableCredential, got %v", parsed[VPKeyVerifiableCredential])
	}
}

func TestPresentation_MarshalJSON_Empty(t *testing.T) {
	p, _ := NewPresentation()
	data, err := p.MarshalJSON()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)
	if _, ok := parsed[VPKeyVerifiableCredential]; ok {
		t.Error("Expected no verifiableCredential key for empty presentation")
	}
	if _, ok := parsed[VPKeyHolder]; ok {
		t.Error("Expected no holder key for empty presentation")
	}
}

func TestPresentation_MarshalJSON_CustomContext(t *testing.T) {
	p, _ := NewPresentation()
	p.Context = []string{ContextCredentialsV2, "https://example.com/custom/v1"}
	p.Type = []string{TypeVerifiablePresentation, "CustomPresentation"}

	data, err := p.MarshalJSON()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)
	ctx := parsed[JSONLDKeyContext].([]interface{})
	if len(ctx) != 2 || ctx[0] != ContextCredentialsV2 {
		t.Errorf("Expected custom context, got %v", ctx)
	}
	types := parsed[JSONLDKeyType].([]interface{})
	if len(types) != 2 || types[1] != "CustomPresentation" {
		t.Errorf("Expected custom types, got %v", types)
	}
}

func TestConstants(t *testing.T) {
	if ContextCredentialsV1 != "https://www.w3.org/2018/credentials/v1" {
		t.Error("ContextCredentialsV1 mismatch")
	}
	if ContextCredentialsV2 != "https://www.w3.org/ns/credentials/v2" {
		t.Error("ContextCredentialsV2 mismatch")
	}
	if TypeVerifiableCredential != "VerifiableCredential" {
		t.Error("TypeVerifiableCredential mismatch")
	}
	if TypeVerifiablePresentation != "VerifiablePresentation" {
		t.Error("TypeVerifiablePresentation mismatch")
	}
}
