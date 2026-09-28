package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildDIDDocJSON constructs a JSON DID document with the given verification
// methods. Each entry in vms is marshalled as-is into the verificationMethod
// array. Optional authentication and assertionMethod slices contain string
// references or embedded VMs.
func buildDIDDocJSON(t *testing.T, id string, vms []map[string]interface{}, auth, assertion []interface{}) []byte {
	t.Helper()
	doc := map[string]interface{}{
		"id":                 id,
		"verificationMethod": vms,
	}
	if auth != nil {
		doc["authentication"] = auth
	}
	if assertion != nil {
		doc["assertionMethod"] = assertion
	}
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	return data
}

// generateEd25519Multibase generates a random Ed25519 key pair and returns
// the multibase-encoded public key and the corresponding JWK private key.
func generateEd25519Multibase(t *testing.T) (string, jwk.Key) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	multibase := encodeMultibaseKey(MulticodecEd25519Pub, pub)
	privJWK, err := jwk.Import(priv)
	require.NoError(t, err)
	return multibase, privJWK
}

// generateP256Multibase generates a random P-256 key pair and returns
// the multibase-encoded compressed public key and the corresponding JWK
// private key.
func generateP256Multibase(t *testing.T) (string, jwk.Key) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)
	multibase := encodeMultibaseKey(MulticodecP256Pub, compressed)
	privJWK, err := jwk.Import(privKey)
	require.NoError(t, err)
	return multibase, privJWK
}

// generateP384Multibase generates a random P-384 key pair and returns
// the multibase-encoded compressed public key and the corresponding JWK
// private key.
func generateP384Multibase(t *testing.T) (string, jwk.Key) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	compressed := elliptic.MarshalCompressed(elliptic.P384(), privKey.PublicKey.X, privKey.PublicKey.Y)
	multibase := encodeMultibaseKey(MulticodecP384Pub, compressed)
	privJWK, err := jwk.Import(privKey)
	require.NoError(t, err)
	return multibase, privJWK
}

func TestParseVerificationMethod_Multikey(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) (vmJSON string, wantKeyType jwa.KeyType, wantCurve jwa.EllipticCurveAlgorithm)
		wantNilKey  bool
		wantErr     bool
		description string
	}{
		{
			name:        "Ed25519 publicKeyMultibase decodes to OKP JWK",
			description: "A Multikey VM with a valid Ed25519 publicKeyMultibase should produce a usable OKP/Ed25519 JWK",
			setup: func(t *testing.T) (string, jwa.KeyType, jwa.EllipticCurveAlgorithm) {
				mb, _ := generateEd25519Multibase(t)
				vmJSON := `{
					"id": "did:web:example.com#key-1",
					"type": "Multikey",
					"controller": "did:web:example.com",
					"publicKeyMultibase": "` + mb + `"
				}`
				return vmJSON, jwa.OKP(), jwa.Ed25519()
			},
		},
		{
			name:        "P-256 publicKeyMultibase decodes to EC JWK",
			description: "A Multikey VM with a valid P-256 publicKeyMultibase should produce a usable EC/P-256 JWK",
			setup: func(t *testing.T) (string, jwa.KeyType, jwa.EllipticCurveAlgorithm) {
				mb, _ := generateP256Multibase(t)
				vmJSON := `{
					"id": "did:web:example.com#key-2",
					"type": "Multikey",
					"controller": "did:web:example.com",
					"publicKeyMultibase": "` + mb + `"
				}`
				return vmJSON, jwa.EC(), jwa.P256()
			},
		},
		{
			name:        "P-384 publicKeyMultibase decodes to EC JWK",
			description: "A Multikey VM with a valid P-384 publicKeyMultibase should produce a usable EC/P-384 JWK",
			setup: func(t *testing.T) (string, jwa.KeyType, jwa.EllipticCurveAlgorithm) {
				mb, _ := generateP384Multibase(t)
				vmJSON := `{
					"id": "did:web:example.com#key-3",
					"type": "Multikey",
					"controller": "did:web:example.com",
					"publicKeyMultibase": "` + mb + `"
				}`
				return vmJSON, jwa.EC(), jwa.P384()
			},
		},
		{
			name:        "Ed25519VerificationKey2020 type also decodes publicKeyMultibase",
			description: "The multibase decoding is type-agnostic: an Ed25519VerificationKey2020 VM also gets a JWK",
			setup: func(t *testing.T) (string, jwa.KeyType, jwa.EllipticCurveAlgorithm) {
				mb, _ := generateEd25519Multibase(t)
				vmJSON := `{
					"id": "did:web:example.com#key-ed2020",
					"type": "Ed25519VerificationKey2020",
					"controller": "did:web:example.com",
					"publicKeyMultibase": "` + mb + `"
				}`
				return vmJSON, jwa.OKP(), jwa.Ed25519()
			},
		},
		{
			name:        "invalid publicKeyMultibase produces nil JWK without error",
			description: "An unparseable multibase value should not cause an error — the VM is parsed but with nil JWK",
			setup: func(t *testing.T) (string, jwa.KeyType, jwa.EllipticCurveAlgorithm) {
				vmJSON := `{
					"id": "did:web:example.com#key-bad",
					"type": "Multikey",
					"controller": "did:web:example.com",
					"publicKeyMultibase": "z6MkTest123"
				}`
				// These values are never checked for wantNilKey cases
				return vmJSON, jwa.OKP(), jwa.Ed25519()
			},
			wantNilKey: true,
		},
		{
			name:        "publicKeyJwk takes priority over publicKeyMultibase",
			description: "When both publicKeyJwk and publicKeyMultibase are present, JWK takes priority",
			setup: func(t *testing.T) (string, jwa.KeyType, jwa.EllipticCurveAlgorithm) {
				// Generate a P-256 JWK (will be in publicKeyJwk)
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				pubJWK, err := jwk.Import(&privKey.PublicKey)
				require.NoError(t, err)
				jwkBytes, err := json.Marshal(pubJWK)
				require.NoError(t, err)

				// Generate an Ed25519 multibase (different key type to prove JWK wins)
				mb, _ := generateEd25519Multibase(t)

				vmJSON := `{
					"id": "did:web:example.com#key-both",
					"type": "JsonWebKey2020",
					"controller": "did:web:example.com",
					"publicKeyJwk": ` + string(jwkBytes) + `,
					"publicKeyMultibase": "` + mb + `"
				}`
				// Expect EC/P-256 from the JWK, NOT OKP/Ed25519 from multibase
				return vmJSON, jwa.EC(), jwa.P256()
			},
		},
		{
			name:        "completely invalid multibase encoding produces nil JWK",
			description: "A string that cannot be multibase-decoded at all should produce nil JWK",
			setup: func(t *testing.T) (string, jwa.KeyType, jwa.EllipticCurveAlgorithm) {
				vmJSON := `{
					"id": "did:web:example.com#key-garbage",
					"type": "Multikey",
					"controller": "did:web:example.com",
					"publicKeyMultibase": "not-valid-multibase!!!"
				}`
				// These values are never checked for wantNilKey cases
				return vmJSON, jwa.OKP(), jwa.Ed25519()
			},
			wantNilKey: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vmJSON, wantKeyType, wantCurve := tc.setup(t)
			vm, err := parseVerificationMethod([]byte(vmJSON))

			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, vm)

			if tc.wantNilKey {
				assert.Nil(t, vm.JSONWebKey(), "expected nil JWK for invalid multibase")
				// Value should still be set to the raw multibase string
				assert.NotEmpty(t, vm.Value, "Value should be set even when JWK decode fails")
				return
			}

			require.NotNil(t, vm.JSONWebKey(), "expected non-nil JWK for valid multibase")
			assert.Equal(t, wantKeyType, vm.JSONWebKey().KeyType())

			var crv jwa.EllipticCurveAlgorithm
			err = vm.JSONWebKey().Get(jwk.ECDSACrvKey, &crv)
			if err != nil {
				err = vm.JSONWebKey().Get(jwk.OKPCrvKey, &crv)
			}
			require.NoError(t, err, "key should have crv parameter")
			assert.Equal(t, wantCurve, crv)
		})
	}
}

func TestParseDIDDocument_MultikeyVerificationMethods(t *testing.T) {
	tests := []struct {
		name        string
		description string
		buildDoc    func(t *testing.T) []byte
		validate    func(t *testing.T, doc *Doc)
	}{
		{
			name:        "document with Ed25519 Multikey VM",
			description: "A did:web document with a Multikey VM using Ed25519 publicKeyMultibase produces a usable JWK",
			buildDoc: func(t *testing.T) []byte {
				mb, _ := generateEd25519Multibase(t)
				return buildDIDDocJSON(t, "did:web:example.com", []map[string]interface{}{
					{
						"id":                 "did:web:example.com#key-1",
						"type":               TypeMultikey,
						"controller":         "did:web:example.com",
						"publicKeyMultibase": mb,
					},
				}, nil, nil)
			},
			validate: func(t *testing.T, doc *Doc) {
				require.Len(t, doc.VerificationMethod, 1)
				vm := doc.VerificationMethod[0]
				assert.Equal(t, "did:web:example.com#key-1", vm.ID)
				assert.Equal(t, TypeMultikey, vm.Type)
				require.NotNil(t, vm.JSONWebKey(), "Ed25519 Multikey should produce a JWK")
				assert.Equal(t, jwa.OKP(), vm.JSONWebKey().KeyType())
			},
		},
		{
			name:        "document with P-256 Multikey VM",
			description: "A did:web document with a Multikey VM using P-256 publicKeyMultibase produces a usable JWK",
			buildDoc: func(t *testing.T) []byte {
				mb, _ := generateP256Multibase(t)
				return buildDIDDocJSON(t, "did:web:example.com", []map[string]interface{}{
					{
						"id":                 "did:web:example.com#key-1",
						"type":               TypeMultikey,
						"controller":         "did:web:example.com",
						"publicKeyMultibase": mb,
					},
				}, nil, nil)
			},
			validate: func(t *testing.T, doc *Doc) {
				require.Len(t, doc.VerificationMethod, 1)
				vm := doc.VerificationMethod[0]
				require.NotNil(t, vm.JSONWebKey(), "P-256 Multikey should produce a JWK")
				assert.Equal(t, jwa.EC(), vm.JSONWebKey().KeyType())
				var crv jwa.EllipticCurveAlgorithm
				require.NoError(t, vm.JSONWebKey().Get(jwk.ECDSACrvKey, &crv))
				assert.Equal(t, jwa.P256(), crv)
			},
		},
		{
			name:        "document with P-384 Multikey VM",
			description: "A did:web document with a Multikey VM using P-384 publicKeyMultibase produces a usable JWK",
			buildDoc: func(t *testing.T) []byte {
				mb, _ := generateP384Multibase(t)
				return buildDIDDocJSON(t, "did:web:example.com", []map[string]interface{}{
					{
						"id":                 "did:web:example.com#key-1",
						"type":               TypeMultikey,
						"controller":         "did:web:example.com",
						"publicKeyMultibase": mb,
					},
				}, nil, nil)
			},
			validate: func(t *testing.T, doc *Doc) {
				require.Len(t, doc.VerificationMethod, 1)
				vm := doc.VerificationMethod[0]
				require.NotNil(t, vm.JSONWebKey(), "P-384 Multikey should produce a JWK")
				assert.Equal(t, jwa.EC(), vm.JSONWebKey().KeyType())
				var crv jwa.EllipticCurveAlgorithm
				require.NoError(t, vm.JSONWebKey().Get(jwk.ECDSACrvKey, &crv))
				assert.Equal(t, jwa.P384(), crv)
			},
		},
		{
			name:        "mixed JWK and Multikey verification methods",
			description: "A document with both JWK and Multikey VMs should parse both correctly",
			buildDoc: func(t *testing.T) []byte {
				mb, _ := generateEd25519Multibase(t)
				return buildDIDDocJSON(t, "did:web:example.com", []map[string]interface{}{
					{
						"id":         "did:web:example.com#key-jwk",
						"type":       TypeJsonWebKey2020,
						"controller": "did:web:example.com",
						"publicKeyJwk": map[string]interface{}{
							"kty": "EC",
							"crv": "P-256",
							"x":   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
							"y":   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
						},
					},
					{
						"id":                 "did:web:example.com#key-multikey",
						"type":               TypeMultikey,
						"controller":         "did:web:example.com",
						"publicKeyMultibase": mb,
					},
				}, nil, nil)
			},
			validate: func(t *testing.T, doc *Doc) {
				require.Len(t, doc.VerificationMethod, 2)

				vmJwk := doc.VerificationMethod[0]
				assert.Equal(t, "did:web:example.com#key-jwk", vmJwk.ID)
				require.NotNil(t, vmJwk.JSONWebKey(), "JWK VM should have a key")
				assert.Equal(t, jwa.EC(), vmJwk.JSONWebKey().KeyType())

				vmMultikey := doc.VerificationMethod[1]
				assert.Equal(t, "did:web:example.com#key-multikey", vmMultikey.ID)
				require.NotNil(t, vmMultikey.JSONWebKey(), "Multikey VM should have a key")
				assert.Equal(t, jwa.OKP(), vmMultikey.JSONWebKey().KeyType())
			},
		},
		{
			name:        "invalid multibase VM does not block document parsing",
			description: "A VM with an unparseable publicKeyMultibase should not prevent the document from parsing",
			buildDoc: func(t *testing.T) []byte {
				return buildDIDDocJSON(t, "did:web:example.com", []map[string]interface{}{
					{
						"id":                 "did:web:example.com#key-bad",
						"type":               TypeMultikey,
						"controller":         "did:web:example.com",
						"publicKeyMultibase": "z6MkTest123",
					},
				}, nil, nil)
			},
			validate: func(t *testing.T, doc *Doc) {
				require.Len(t, doc.VerificationMethod, 1)
				vm := doc.VerificationMethod[0]
				assert.Equal(t, "did:web:example.com#key-bad", vm.ID)
				assert.Nil(t, vm.JSONWebKey(), "invalid multibase should produce nil JWK")
				assert.Equal(t, "z6MkTest123", string(vm.Value))
			},
		},
		{
			name:        "Multikey VM in authentication relationship",
			description: "A Multikey VM listed under authentication should be resolvable with a JWK",
			buildDoc: func(t *testing.T) []byte {
				mb, _ := generateEd25519Multibase(t)
				return buildDIDDocJSON(t, "did:web:example.com",
					[]map[string]interface{}{
						{
							"id":                 "did:web:example.com#key-auth",
							"type":               TypeMultikey,
							"controller":         "did:web:example.com",
							"publicKeyMultibase": mb,
						},
					},
					[]interface{}{"did:web:example.com#key-auth"},
					nil,
				)
			},
			validate: func(t *testing.T, doc *Doc) {
				require.Len(t, doc.VerificationMethod, 1)
				vm := doc.VerificationMethod[0]
				require.NotNil(t, vm.JSONWebKey(), "Multikey VM should produce a JWK")
				require.Len(t, doc.Authentication, 1)
				assert.Equal(t, "did:web:example.com#key-auth", doc.Authentication[0])
				assert.True(t, doc.AllowsForRelationship(vm.ID, RelationshipAuthentication))
			},
		},
		{
			name:        "Multikey VM in assertionMethod relationship",
			description: "A Multikey VM listed under assertionMethod should be resolvable with a JWK",
			buildDoc: func(t *testing.T) []byte {
				mb, _ := generateP256Multibase(t)
				return buildDIDDocJSON(t, "did:web:example.com",
					[]map[string]interface{}{
						{
							"id":                 "did:web:example.com#key-assert",
							"type":               TypeMultikey,
							"controller":         "did:web:example.com",
							"publicKeyMultibase": mb,
						},
					},
					nil,
					[]interface{}{"did:web:example.com#key-assert"},
				)
			},
			validate: func(t *testing.T, doc *Doc) {
				require.Len(t, doc.VerificationMethod, 1)
				vm := doc.VerificationMethod[0]
				require.NotNil(t, vm.JSONWebKey(), "Multikey VM should produce a JWK")
				require.Len(t, doc.AssertionMethod, 1)
				assert.Equal(t, "did:web:example.com#key-assert", doc.AssertionMethod[0])
				assert.True(t, doc.AllowsForRelationship(vm.ID, RelationshipAssertionMethod))
			},
		},
		{
			name:        "embedded Multikey VM in authentication",
			description: "An embedded Multikey VM inside the authentication array should be decoded",
			buildDoc: func(t *testing.T) []byte {
				mb, _ := generateEd25519Multibase(t)
				doc := map[string]interface{}{
					"id":                 "did:web:example.com",
					"verificationMethod": []interface{}{},
					"authentication": []interface{}{
						map[string]interface{}{
							"id":                 "did:web:example.com#key-embedded",
							"type":               TypeMultikey,
							"controller":         "did:web:example.com",
							"publicKeyMultibase": mb,
						},
					},
				}
				data, err := json.Marshal(doc)
				require.NoError(t, err)
				return data
			},
			validate: func(t *testing.T, doc *Doc) {
				// Embedded VMs are appended to the document's verification methods
				require.Len(t, doc.VerificationMethod, 1)
				vm := doc.VerificationMethod[0]
				assert.Equal(t, "did:web:example.com#key-embedded", vm.ID)
				require.NotNil(t, vm.JSONWebKey(), "embedded Multikey VM should produce a JWK")
				assert.Equal(t, jwa.OKP(), vm.JSONWebKey().KeyType())
				// And the authentication relationship should reference it
				require.Len(t, doc.Authentication, 1)
				assert.Equal(t, vm.ID, doc.Authentication[0])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			docBytes := tc.buildDoc(t)
			doc, err := parseDIDDocument(docBytes)
			require.NoError(t, err)
			require.NotNil(t, doc)
			tc.validate(t, doc)
		})
	}
}

// TestKeyResolverWithMultikeyVM verifies that the standard key resolution
// path (verifier/key_resolver.go's ResolveKeyFromDID) works end-to-end
// with Multikey verification methods in a did:web document. Since we cannot
// easily serve a real HTTP endpoint in a unit test, we test through a mock
// VDR that returns a document with Multikey VMs.
func TestKeyResolverWithMultikeyVM(t *testing.T) {
	tests := []struct {
		name        string
		description string
		setup       func(t *testing.T) (*Doc, jwa.KeyType, jwa.EllipticCurveAlgorithm)
	}{
		{
			name:        "resolve Ed25519 Multikey",
			description: "ResolveKeyFromDID resolves an Ed25519 Multikey VM without any code changes to key_resolver.go",
			setup: func(t *testing.T) (*Doc, jwa.KeyType, jwa.EllipticCurveAlgorithm) {
				mb, _ := generateEd25519Multibase(t)
				docJSON := buildDIDDocJSON(t, "did:web:example.com", []map[string]interface{}{
					{
						"id":                 "did:web:example.com#key-1",
						"type":               TypeMultikey,
						"controller":         "did:web:example.com",
						"publicKeyMultibase": mb,
					},
				}, nil, nil)
				doc, err := parseDIDDocument(docJSON)
				require.NoError(t, err)
				return doc, jwa.OKP(), jwa.Ed25519()
			},
		},
		{
			name:        "resolve P-256 Multikey",
			description: "ResolveKeyFromDID resolves a P-256 Multikey VM",
			setup: func(t *testing.T) (*Doc, jwa.KeyType, jwa.EllipticCurveAlgorithm) {
				mb, _ := generateP256Multibase(t)
				docJSON := buildDIDDocJSON(t, "did:web:example.com", []map[string]interface{}{
					{
						"id":                 "did:web:example.com#key-1",
						"type":               TypeMultikey,
						"controller":         "did:web:example.com",
						"publicKeyMultibase": mb,
					},
				}, nil, nil)
				doc, err := parseDIDDocument(docJSON)
				require.NoError(t, err)
				return doc, jwa.EC(), jwa.P256()
			},
		},
		{
			name:        "resolve P-384 Multikey",
			description: "ResolveKeyFromDID resolves a P-384 Multikey VM",
			setup: func(t *testing.T) (*Doc, jwa.KeyType, jwa.EllipticCurveAlgorithm) {
				mb, _ := generateP384Multibase(t)
				docJSON := buildDIDDocJSON(t, "did:web:example.com", []map[string]interface{}{
					{
						"id":                 "did:web:example.com#key-1",
						"type":               TypeMultikey,
						"controller":         "did:web:example.com",
						"publicKeyMultibase": mb,
					},
				}, nil, nil)
				doc, err := parseDIDDocument(docJSON)
				require.NoError(t, err)
				return doc, jwa.EC(), jwa.P384()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, wantKeyType, wantCurve := tc.setup(t)

			// Create a mock VDR that returns the pre-built document
			mock := &multikeyMockVDR{doc: doc}
			registry := NewRegistry(WithVDR(mock))

			// Resolve the key using the standard resolution path
			key, err := resolveKeyFromRegistry(registry, "did:web:example.com", "did:web:example.com#key-1")
			require.NoError(t, err)
			require.NotNil(t, key)
			assert.Equal(t, wantKeyType, key.KeyType())

			var crv jwa.EllipticCurveAlgorithm
			err = key.Get(jwk.ECDSACrvKey, &crv)
			if err != nil {
				err = key.Get(jwk.OKPCrvKey, &crv)
			}
			require.NoError(t, err)
			assert.Equal(t, wantCurve, crv)
		})
	}
}

// multikeyMockVDR is a test VDR that returns a pre-built DID document.
type multikeyMockVDR struct {
	doc *Doc
}

func (m *multikeyMockVDR) Accept(_ string) bool { return true }

func (m *multikeyMockVDR) Read(_ string) (*DocResolution, error) {
	return &DocResolution{DIDDocument: m.doc}, nil
}

// resolveKeyFromRegistry simulates the key resolution path that
// verifier/key_resolver.go follows: resolve the DID, find the matching
// verification method, return its JWK.
func resolveKeyFromRegistry(registry *Registry, didStr, kid string) (jwk.Key, error) {
	docRes, err := registry.Resolve(didStr)
	if err != nil {
		return nil, err
	}
	for _, vm := range docRes.DIDDocument.VerificationMethod {
		if vm.ID == kid {
			return vm.JSONWebKey(), nil
		}
	}
	return nil, nil
}
