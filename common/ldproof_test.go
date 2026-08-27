package common

import (
	"testing"
)

func TestParseLDProof_JsonWebSignature2020(t *testing.T) {
	proofMap := map[string]interface{}{
		LDProofKeyType:               "JsonWebSignature2020",
		LDProofKeyCreated:            "2024-01-01T00:00:00Z",
		LDProofKeyVerificationMethod: "did:web:example.com#key-1",
		LDProofKeyJWS:                "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..signature",
		LDProofKeyProofPurpose:       "assertionMethod",
	}

	proof, err := ParseLDProof(proofMap)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if proof.Type != "JsonWebSignature2020" {
		t.Errorf("Expected type JsonWebSignature2020, got %s", proof.Type)
	}
	if proof.Created != "2024-01-01T00:00:00Z" {
		t.Errorf("Expected created 2024-01-01T00:00:00Z, got %s", proof.Created)
	}
	if proof.VerificationMethod != "did:web:example.com#key-1" {
		t.Errorf("Expected verificationMethod did:web:example.com#key-1, got %s", proof.VerificationMethod)
	}
	if proof.JWS != "eyJhbGciOiJQUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..signature" {
		t.Errorf("Unexpected JWS value: %s", proof.JWS)
	}
	if proof.ProofPurpose != "assertionMethod" {
		t.Errorf("Expected proofPurpose assertionMethod, got %s", proof.ProofPurpose)
	}
	if proof.ProofValue != "" {
		t.Errorf("Expected empty proofValue, got %s", proof.ProofValue)
	}
}

func TestParseLDProof_DataIntegrityWithProofValue(t *testing.T) {
	proofMap := map[string]interface{}{
		LDProofKeyType:               "DataIntegrityProof",
		LDProofKeyCreated:            "2024-06-15T12:00:00Z",
		LDProofKeyVerificationMethod: "did:key:z6Mktest#z6Mktest",
		LDProofKeyProofValue:         "z3FXQjecWufY46...base58btc-encoded",
		LDProofKeyCryptosuite:        "eddsa-rdfc-2022",
		LDProofKeyProofPurpose:       "authentication",
		LDProofKeyChallenge:          "nonce-abc123",
		LDProofKeyDomain:             "https://verifier.example.com",
	}

	proof, err := ParseLDProof(proofMap)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if proof.Type != "DataIntegrityProof" {
		t.Errorf("Expected type DataIntegrityProof, got %s", proof.Type)
	}
	if proof.ProofValue != "z3FXQjecWufY46...base58btc-encoded" {
		t.Errorf("Unexpected proofValue: %s", proof.ProofValue)
	}
	if proof.Cryptosuite != "eddsa-rdfc-2022" {
		t.Errorf("Expected cryptosuite eddsa-rdfc-2022, got %s", proof.Cryptosuite)
	}
	if proof.Challenge != "nonce-abc123" {
		t.Errorf("Expected challenge nonce-abc123, got %s", proof.Challenge)
	}
	if proof.Domain != "https://verifier.example.com" {
		t.Errorf("Expected domain https://verifier.example.com, got %s", proof.Domain)
	}
	if proof.ProofPurpose != "authentication" {
		t.Errorf("Expected proofPurpose authentication, got %s", proof.ProofPurpose)
	}
	if proof.JWS != "" {
		t.Errorf("Expected empty JWS, got %s", proof.JWS)
	}
}

func TestParseLDProof_MissingType(t *testing.T) {
	proofMap := map[string]interface{}{
		LDProofKeyCreated: "2024-01-01T00:00:00Z",
		LDProofKeyJWS:     "eyJ..sig",
	}

	_, err := ParseLDProof(proofMap)
	if err != ErrorLDProofMissingType {
		t.Errorf("Expected ErrorLDProofMissingType, got %v", err)
	}
}

func TestParseLDProof_EmptyType(t *testing.T) {
	proofMap := map[string]interface{}{
		LDProofKeyType: "",
		LDProofKeyJWS:  "eyJ..sig",
	}

	_, err := ParseLDProof(proofMap)
	if err != ErrorLDProofMissingType {
		t.Errorf("Expected ErrorLDProofMissingType, got %v", err)
	}
}

func TestParseLDProof_NoSignature(t *testing.T) {
	proofMap := map[string]interface{}{
		LDProofKeyType:               "JsonWebSignature2020",
		LDProofKeyCreated:            "2024-01-01T00:00:00Z",
		LDProofKeyVerificationMethod: "did:web:example.com#key-1",
	}

	_, err := ParseLDProof(proofMap)
	if err != ErrorLDProofNoSignature {
		t.Errorf("Expected ErrorLDProofNoSignature, got %v", err)
	}
}

func TestParseLDProof_OptionalFieldsAbsent(t *testing.T) {
	// Minimal valid proof with only required fields + JWS.
	proofMap := map[string]interface{}{
		LDProofKeyType: "JsonWebSignature2020",
		LDProofKeyJWS:  "eyJ..sig",
	}

	proof, err := ParseLDProof(proofMap)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if proof.Created != "" {
		t.Errorf("Expected empty created, got %s", proof.Created)
	}
	if proof.VerificationMethod != "" {
		t.Errorf("Expected empty verificationMethod, got %s", proof.VerificationMethod)
	}
	if proof.ProofPurpose != "" {
		t.Errorf("Expected empty proofPurpose, got %s", proof.ProofPurpose)
	}
	if proof.Challenge != "" {
		t.Errorf("Expected empty challenge, got %s", proof.Challenge)
	}
	if proof.Domain != "" {
		t.Errorf("Expected empty domain, got %s", proof.Domain)
	}
}

// Table-driven tests for ParseLDProofs.
func TestParseLDProofs(t *testing.T) {
	tests := []struct {
		name      string
		input     interface{}
		wantCount int
		wantErr   error
	}{
		{
			name:      "nil input",
			input:     nil,
			wantCount: 0,
			wantErr:   nil,
		},
		{
			name: "single proof map",
			input: map[string]interface{}{
				LDProofKeyType: "JsonWebSignature2020",
				LDProofKeyJWS:  "eyJ..sig",
			},
			wantCount: 1,
			wantErr:   nil,
		},
		{
			name: "array with two proofs",
			input: []interface{}{
				map[string]interface{}{
					LDProofKeyType: "JsonWebSignature2020",
					LDProofKeyJWS:  "eyJ..sig1",
				},
				map[string]interface{}{
					LDProofKeyType:      "DataIntegrityProof",
					LDProofKeyProofValue: "z3FXQ...",
				},
			},
			wantCount: 2,
			wantErr:   nil,
		},
		{
			name:      "invalid type (string)",
			input:     "not-a-proof",
			wantCount: 0,
			wantErr:   ErrorLDProofInvalidFormat,
		},
		{
			name: "array with non-map element",
			input: []interface{}{
				"not-a-map",
			},
			wantCount: 0,
			wantErr:   ErrorLDProofInvalidFormat,
		},
		{
			name:      "empty array",
			input:     []interface{}{},
			wantCount: 0,
			wantErr:   nil,
		},
		{
			name: "single proof map missing type",
			input: map[string]interface{}{
				LDProofKeyJWS: "eyJ..sig",
			},
			wantCount: 0,
			wantErr:   ErrorLDProofMissingType,
		},
		{
			name: "array with invalid proof (no signature)",
			input: []interface{}{
				map[string]interface{}{
					LDProofKeyType: "JsonWebSignature2020",
					// no jws or proofValue
				},
			},
			wantCount: 0,
			wantErr:   ErrorLDProofNoSignature,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proofs, err := ParseLDProofs(tc.input)
			if err != tc.wantErr {
				t.Errorf("Expected error %v, got %v", tc.wantErr, err)
			}
			if len(proofs) != tc.wantCount {
				t.Errorf("Expected %d proofs, got %d", tc.wantCount, len(proofs))
			}
		})
	}
}

func TestParseLDProofs_SingleProofFields(t *testing.T) {
	input := map[string]interface{}{
		LDProofKeyType:               "JsonWebSignature2020",
		LDProofKeyCreated:            "2024-01-01T00:00:00Z",
		LDProofKeyVerificationMethod: "did:web:example.com#key-1",
		LDProofKeyJWS:                "eyJ..sig",
		LDProofKeyProofPurpose:       "assertionMethod",
	}

	proofs, err := ParseLDProofs(input)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(proofs) != 1 {
		t.Fatalf("Expected 1 proof, got %d", len(proofs))
	}
	p := proofs[0]
	if p.Type != "JsonWebSignature2020" {
		t.Errorf("Expected type JsonWebSignature2020, got %s", p.Type)
	}
	if p.VerificationMethod != "did:web:example.com#key-1" {
		t.Errorf("Expected verificationMethod, got %s", p.VerificationMethod)
	}
}

func TestParseLDProofs_MultipleProofFields(t *testing.T) {
	input := []interface{}{
		map[string]interface{}{
			LDProofKeyType:          "JsonWebSignature2020",
			LDProofKeyJWS:           "eyJ..sig1",
			LDProofKeyProofPurpose:  "assertionMethod",
		},
		map[string]interface{}{
			LDProofKeyType:          "DataIntegrityProof",
			LDProofKeyProofValue:    "zProofValue2",
			LDProofKeyCryptosuite:   "ecdsa-rdfc-2019",
			LDProofKeyChallenge:     "challenge-xyz",
			LDProofKeyDomain:        "https://example.com",
		},
	}

	proofs, err := ParseLDProofs(input)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(proofs) != 2 {
		t.Fatalf("Expected 2 proofs, got %d", len(proofs))
	}

	if proofs[0].JWS != "eyJ..sig1" {
		t.Errorf("First proof JWS mismatch: %s", proofs[0].JWS)
	}
	if proofs[0].ProofPurpose != "assertionMethod" {
		t.Errorf("First proof proofPurpose mismatch: %s", proofs[0].ProofPurpose)
	}

	if proofs[1].ProofValue != "zProofValue2" {
		t.Errorf("Second proof proofValue mismatch: %s", proofs[1].ProofValue)
	}
	if proofs[1].Cryptosuite != "ecdsa-rdfc-2019" {
		t.Errorf("Second proof cryptosuite mismatch: %s", proofs[1].Cryptosuite)
	}
	if proofs[1].Challenge != "challenge-xyz" {
		t.Errorf("Second proof challenge mismatch: %s", proofs[1].Challenge)
	}
	if proofs[1].Domain != "https://example.com" {
		t.Errorf("Second proof domain mismatch: %s", proofs[1].Domain)
	}
}
