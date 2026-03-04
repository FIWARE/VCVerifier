package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/multiformats/go-multibase"
)

func TestKeyVDR_Accept(t *testing.T) {
	vdr := NewKeyVDR()
	if !vdr.Accept("key") {
		t.Error("Expected Accept(key) = true")
	}
	if vdr.Accept("web") {
		t.Error("Expected Accept(web) = false")
	}
}

func TestKeyVDR_Read_Ed25519(t *testing.T) {
	// Generate an Ed25519 key and encode as did:key
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	didStr := ed25519ToDIDKey(pub)
	vdr := NewKeyVDR()
	res, err := vdr.Read(didStr)
	if err != nil {
		t.Fatalf("Failed to resolve did:key: %v", err)
	}

	if res.DIDDocument.ID != didStr {
		t.Errorf("Expected DID %s, got %s", didStr, res.DIDDocument.ID)
	}
	if len(res.DIDDocument.VerificationMethod) != 1 {
		t.Fatalf("Expected 1 verification method, got %d", len(res.DIDDocument.VerificationMethod))
	}

	vm := res.DIDDocument.VerificationMethod[0]
	if vm.Type != TypeEd25519VerificationKey2020 {
		t.Errorf("Expected type %s, got %s", TypeEd25519VerificationKey2020, vm.Type)
	}
	if vm.JSONWebKey() == nil {
		t.Error("Expected JWK key, got nil")
	}
}

func TestKeyVDR_Read_P256(t *testing.T) {
	// Generate a P-256 key and encode as did:key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	didStr := ecdsaToDIDKey(elliptic.P256(), &privKey.PublicKey, multicodecP256Pub)
	vdr := NewKeyVDR()
	res, err := vdr.Read(didStr)
	if err != nil {
		t.Fatalf("Failed to resolve did:key: %v", err)
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
}

func TestKeyVDR_Read_P384(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	didStr := ecdsaToDIDKey(elliptic.P384(), &privKey.PublicKey, multicodecP384Pub)
	vdr := NewKeyVDR()
	res, err := vdr.Read(didStr)
	if err != nil {
		t.Fatalf("Failed to resolve did:key: %v", err)
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
}

func TestKeyVDR_Read_Invalid(t *testing.T) {
	vdr := NewKeyVDR()

	t.Run("too short", func(t *testing.T) {
		_, err := vdr.Read("did:key")
		if err == nil {
			t.Error("Expected error for short DID")
		}
	})

	t.Run("invalid multibase", func(t *testing.T) {
		_, err := vdr.Read("did:key:notmultibase")
		if err == nil {
			t.Error("Expected error for invalid multibase")
		}
	})
}

// Test helpers

func ed25519ToDIDKey(pub ed25519.PublicKey) string {
	// multicodec prefix for ed25519-pub is 0xed
	prefix := []byte{0xed, 0x01}
	multicodecKey := append(prefix, pub...)
	encoded, _ := multibase.Encode(multibase.Base58BTC, multicodecKey)
	return "did:key:" + encoded
}

func ecdsaToDIDKey(curve elliptic.Curve, pub *ecdsa.PublicKey, codec uint64) string {
	// Encode as compressed point
	compressed := elliptic.MarshalCompressed(curve, pub.X, pub.Y)

	// Encode multicodec prefix as varint
	var prefix [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(prefix[:], codec)

	multicodecKey := append(prefix[:n], compressed...)
	encoded, _ := multibase.Encode(multibase.Base58BTC, multicodecKey)
	return "did:key:" + encoded
}
