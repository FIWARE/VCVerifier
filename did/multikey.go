package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/multiformats/go-multibase"
)

const (
	// TypeMultikey is the W3C Multikey verification method type, the one a
	// Data Integrity issuer normally publishes.
	// See https://www.w3.org/TR/controller-document/#multikey
	//
	// Key resolution deliberately does not branch on it: a verification method
	// is usable when it yields a key, whatever type it declares. The constant
	// exists to name the type in DID documents and tests rather than to gate
	// on it.
	TypeMultikey = "Multikey"

	// TypeEd25519VerificationKey2020 is the verification method type for
	// Ed25519 keys in the Ed25519VerificationKey2020 format.
	TypeEd25519VerificationKey2020 = "Ed25519VerificationKey2020"

	// TypeEcdsaSecp256k1VerificationKey2019 is the verification method type
	// for secp256k1 keys.
	TypeEcdsaSecp256k1VerificationKey2019 = "EcdsaSecp256k1VerificationKey2019"

	// MulticodecEd25519Pub is the multicodec code for Ed25519 public keys.
	MulticodecEd25519Pub = 0xed
	// MulticodecP256Pub is the multicodec code for P-256 (secp256r1) public keys.
	MulticodecP256Pub = 0x1200
	// MulticodecP384Pub is the multicodec code for P-384 (secp384r1) public keys.
	MulticodecP384Pub = 0x1201
	// MulticodecSecp256k1Pub is the multicodec code for secp256k1 public keys.
	MulticodecSecp256k1Pub = 0xe7
)

// DecodeMultibaseKey decodes a multibase-encoded public key (e.g. "z6Mk...")
// that carries a multicodec varint prefix, and returns the corresponding JWK.
// This handles the encoding used by W3C Multikey verification methods and
// did:key identifiers. It discards the verification method type; use
// DecodeMultibaseKeyWithType when the type string is also needed (e.g. for
// DID document construction).
func DecodeMultibaseKey(multibaseEncoded string) (jwk.Key, error) {
	key, _, err := DecodeMultibaseKeyWithType(multibaseEncoded)
	return key, err
}

// DecodeMultibaseKeyWithType decodes a multibase-encoded public key (e.g.
// "z6Mk...") that carries a multicodec varint prefix, and returns both the
// JWK and the verification method type string (e.g. "Ed25519VerificationKey2020",
// "JsonWebKey2020"). This is the mid-level entry point used by both
// DecodeMultibaseKey and did:key resolution.
func DecodeMultibaseKeyWithType(multibaseEncoded string) (jwk.Key, string, error) {
	_, keyBytes, err := multibase.Decode(multibaseEncoded)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode multibase: %w", err)
	}

	if len(keyBytes) < 2 {
		return nil, "", fmt.Errorf("key data too short: %d bytes", len(keyBytes))
	}

	codec, n := binary.Uvarint(keyBytes)
	if n <= 0 {
		return nil, "", fmt.Errorf("invalid multicodec varint prefix")
	}
	rawKey := keyBytes[n:]

	return MulticodecToJWK(codec, rawKey)
}

// MulticodecToJWK converts raw public key bytes identified by a multicodec
// code into a JWK key. It returns the JWK key and a verification method type
// string suitable for DID document construction.
//
// Supported codecs:
//   - 0xed   (Ed25519)  -> OKP/Ed25519 JWK, type Ed25519VerificationKey2020
//   - 0x1200 (P-256)    -> EC/P-256 JWK, type JsonWebKey2020
//   - 0x1201 (P-384)    -> EC/P-384 JWK, type JsonWebKey2020
func MulticodecToJWK(codec uint64, rawKey []byte) (jwk.Key, string, error) {
	switch codec {
	case MulticodecEd25519Pub:
		if len(rawKey) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("invalid Ed25519 key size: %d", len(rawKey))
		}
		pubKey := ed25519.PublicKey(rawKey)
		key, err := jwk.Import(pubKey)
		if err != nil {
			return nil, "", err
		}
		return key, TypeEd25519VerificationKey2020, nil

	case MulticodecP256Pub:
		pubKey, err := decodeCompressedEC(elliptic.P256(), rawKey)
		if err != nil {
			return nil, "", fmt.Errorf("invalid P-256 key: %w", err)
		}
		key, err := jwk.Import(pubKey)
		if err != nil {
			return nil, "", err
		}
		return key, TypeJsonWebKey2020, nil

	case MulticodecP384Pub:
		pubKey, err := decodeCompressedEC(elliptic.P384(), rawKey)
		if err != nil {
			return nil, "", fmt.Errorf("invalid P-384 key: %w", err)
		}
		key, err := jwk.Import(pubKey)
		if err != nil {
			return nil, "", err
		}
		return key, TypeJsonWebKey2020, nil

	case MulticodecSecp256k1Pub:
		return nil, "", fmt.Errorf("unsupported multicodec: 0x%x (secp256k1 is not supported in Go's standard crypto library)", codec)

	default:
		return nil, "", fmt.Errorf("unsupported multicodec: 0x%x", codec)
	}
}

// decodeCompressedEC decodes a compressed or uncompressed EC point into an
// ECDSA public key for the given curve.
func decodeCompressedEC(curve elliptic.Curve, data []byte) (*ecdsa.PublicKey, error) {
	byteLen := (curve.Params().BitSize + 7) / 8

	if len(data) == 1+2*byteLen && data[0] == 0x04 {
		// Uncompressed point
		x := new(big.Int).SetBytes(data[1 : 1+byteLen])
		y := new(big.Int).SetBytes(data[1+byteLen:])
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}

	if len(data) == 1+byteLen && (data[0] == 0x02 || data[0] == 0x03) {
		// Compressed point
		x, y := elliptic.UnmarshalCompressed(curve, data)
		if x == nil {
			return nil, fmt.Errorf("failed to decompress EC point on %s", curve.Params().Name)
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}

	return nil, fmt.Errorf("unexpected key length %d for curve %s", len(data), curve.Params().Name)
}
