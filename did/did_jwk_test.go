package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestJWKVDR_Accept(t *testing.T) {
	vdr := NewJWKVDR()
	if !vdr.Accept("jwk") {
		t.Error("Expected Accept(jwk) = true")
	}
	if vdr.Accept("key") {
		t.Error("Expected Accept(key) = false")
	}
}

func TestJWKVDR_Read(t *testing.T) {
	tests := []struct {
		name      string
		createKey func(t *testing.T) jwk.Key
	}{
		{
			name: "P-256",
			createKey: func(t *testing.T) jwk.Key {
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("Failed to generate P-256 key: %v", err)
				}
				key, err := jwk.Import(&privKey.PublicKey)
				if err != nil {
					t.Fatalf("Failed to import P-256 key: %v", err)
				}
				return key
			},
		},
		{
			name: "P-384",
			createKey: func(t *testing.T) jwk.Key {
				privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatalf("Failed to generate P-384 key: %v", err)
				}
				key, err := jwk.Import(&privKey.PublicKey)
				if err != nil {
					t.Fatalf("Failed to import P-384 key: %v", err)
				}
				return key
			},
		},
		{
			name: "Ed25519",
			createKey: func(t *testing.T) jwk.Key {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("Failed to generate Ed25519 key: %v", err)
				}
				key, err := jwk.Import(pub)
				if err != nil {
					t.Fatalf("Failed to import Ed25519 key: %v", err)
				}
				return key
			},
		},
		{
			name: "RSA-2048",
			createKey: func(t *testing.T) jwk.Key {
				privKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("Failed to generate RSA key: %v", err)
				}
				key, err := jwk.Import(&privKey.PublicKey)
				if err != nil {
					t.Fatalf("Failed to import RSA key: %v", err)
				}
				return key
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jwkKey := tc.createKey(t)

			jwkBytes, err := json.Marshal(jwkKey)
			if err != nil {
				t.Fatalf("Failed to marshal JWK: %v", err)
			}

			encoded := base64.RawURLEncoding.EncodeToString(jwkBytes)
			didStr := "did:jwk:" + encoded

			vdr := NewJWKVDR()
			res, err := vdr.Read(didStr)
			if err != nil {
				t.Fatalf("Failed to resolve did:jwk: %v", err)
			}

			if res.DIDDocument.ID != didStr {
				t.Errorf("Expected DID %s, got %s", didStr, res.DIDDocument.ID)
			}
			if len(res.DIDDocument.VerificationMethod) != 1 {
				t.Fatalf("Expected 1 verification method, got %d", len(res.DIDDocument.VerificationMethod))
			}

			vm := res.DIDDocument.VerificationMethod[0]
			if vm.Type != TypeJsonWebKey2020 {
				t.Errorf("Expected type %s, got %s", TypeJsonWebKey2020, vm.Type)
			}
			if vm.JSONWebKey() == nil {
				t.Error("Expected JWK key, got nil")
			}
			if vm.Controller != didStr {
				t.Errorf("Expected controller %s, got %s", didStr, vm.Controller)
			}
			if vm.ID != didStr+"#0" {
				t.Errorf("Expected VM ID %s#0, got %s", didStr, vm.ID)
			}
		})
	}
}

func TestJWKVDR_Read_Invalid(t *testing.T) {
	vdr := NewJWKVDR()

	t.Run("too short", func(t *testing.T) {
		_, err := vdr.Read("did:jwk")
		if err == nil {
			t.Error("Expected error for short DID")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, err := vdr.Read("did:jwk:!!!invalid!!!")
		if err == nil {
			t.Error("Expected error for invalid base64")
		}
	})

	t.Run("invalid JWK", func(t *testing.T) {
		encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"not":"a-jwk"}`))
		_, err := vdr.Read("did:jwk:" + encoded)
		if err == nil {
			t.Error("Expected error for invalid JWK content")
		}
	})
}
