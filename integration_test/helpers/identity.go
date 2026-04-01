package helpers

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/trustbloc/kms-go/doc/jose/jwk/jwksupport"
	"github.com/trustbloc/kms-go/doc/util/fingerprint"
)

// TestIdentity represents a cryptographic identity for test purposes,
// consisting of a key pair and an associated DID.
type TestIdentity struct {
	// PrivateKey is the ECDSA private key for signing.
	PrivateKey crypto.Signer
	// PublicKeyJWK is the public key in JWK format (lestrrat-go/jwx).
	PublicKeyJWK jwk.Key
	// DID is the decentralized identifier (e.g., did:key:z...).
	DID string
	// KeyID is the full verification method ID (e.g., did:key:z...#z...).
	KeyID string
}

// GenerateDidKeyIdentity creates a new ECDSA P-256 key pair and derives a did:key DID from it.
func GenerateDidKeyIdentity() (*TestIdentity, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA P-256 key: %w", err)
	}

	// Create the did:key using trustbloc's fingerprint utility with a JWK.
	tbJWK, err := jwksupport.JWKFromKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("creating trustbloc JWK from public key: %w", err)
	}

	didKey, keyID, err := fingerprint.CreateDIDKeyByJwk(tbJWK)
	if err != nil {
		return nil, fmt.Errorf("creating did:key fingerprint: %w", err)
	}

	// Convert public key to lestrrat-go/jwx JWK format for use in JWT headers.
	jwxKey, err := jwk.Import(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("importing public key to jwx JWK: %w", err)
	}
	if err := jwk.AssignKeyID(jwxKey); err != nil {
		return nil, fmt.Errorf("assigning key ID: %w", err)
	}

	return &TestIdentity{
		PrivateKey:   privateKey,
		PublicKeyJWK: jwxKey,
		DID:          didKey,
		KeyID:        keyID,
	}, nil
}

// GenerateDidWebIdentity creates a new ECDSA P-256 key pair and associates it with a did:web DID
// derived from the given host (e.g., "localhost:12345" -> "did:web:localhost%3A12345").
func GenerateDidWebIdentity(host string) (*TestIdentity, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA P-256 key: %w", err)
	}

	// Build the did:web DID (colons in host are percent-encoded).
	encodedHost := didWebEncode(host)
	did := "did:web:" + encodedHost
	keyID := did + "#key-1"

	// Convert public key to lestrrat-go/jwx JWK format.
	jwxKey, err := jwk.Import(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("importing public key to jwx JWK: %w", err)
	}
	if err := jwxKey.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, fmt.Errorf("setting key ID: %w", err)
	}

	return &TestIdentity{
		PrivateKey:   privateKey,
		PublicKeyJWK: jwxKey,
		DID:          did,
		KeyID:        keyID,
	}, nil
}

// didWebEncode percent-encodes colons in a host string for did:web.
func didWebEncode(host string) string {
	var result []byte
	for i := 0; i < len(host); i++ {
		if host[i] == ':' {
			result = append(result, '%', '3', 'A')
		} else {
			result = append(result, host[i])
		}
	}
	return string(result)
}
