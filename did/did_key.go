package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/fiware/VCVerifier/logging"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/multiformats/go-multibase"
)

const (
	MethodKey = "key"

	TypeEd25519VerificationKey2020        = "Ed25519VerificationKey2020"
	TypeEcdsaSecp256k1VerificationKey2019 = "EcdsaSecp256k1VerificationKey2019"

	// Multicodec prefixes
	multicodecEd25519Pub   = 0xed
	multicodecP256Pub      = 0x1200
	multicodecP384Pub      = 0x1201
	multicodecSecp256k1Pub = 0xe7
)

// KeyVDR resolves did:key DIDs by decoding the multibase/multicodec key.
type KeyVDR struct{}

// NewKeyVDR creates a new did:key resolver.
func NewKeyVDR() *KeyVDR {
	return &KeyVDR{}
}

// Accept returns true for the "key" method.
func (k *KeyVDR) Accept(method string) bool {
	return method == MethodKey
}

// Read resolves a did:key DID.
// Format: did:key:<multibase-encoded-multicodec-key>
// See https://w3c-ccg.github.io/did-method-key/
func (k *KeyVDR) Read(didStr string) (*DocResolution, error) {
	logging.Log().Debugf("Resolving did:key: %s", didStr)

	// Extract the method-specific identifier (everything after "did:key:")
	if len(didStr) <= 8 { // "did:key:" = 8 chars
		return nil, fmt.Errorf("%w: %s", ErrInvalidDID, didStr)
	}
	// Remove fragment if present
	methodSpecificID := didStr[8:]
	fragIdx := -1
	for i, c := range methodSpecificID {
		if c == '#' {
			fragIdx = i
			break
		}
	}
	baseDID := didStr
	if fragIdx >= 0 {
		methodSpecificID = methodSpecificID[:fragIdx]
		baseDID = didStr[:8+fragIdx]
		logging.Log().Debugf("Stripped fragment from did:key, base DID: %s", baseDID)
	}

	// Decode multibase
	_, keyBytes, err := multibase.Decode(methodSpecificID)
	if err != nil {
		logging.Log().Debugf("Failed to decode multibase for did:key %s: %v", didStr, err)
		return nil, fmt.Errorf("failed to decode did:key multibase: %w", err)
	}

	if len(keyBytes) < 2 {
		return nil, fmt.Errorf("%w: key data too short: %s", ErrInvalidDID, didStr)
	}

	// Read multicodec varint prefix
	codec, n := binary.Uvarint(keyBytes)
	if n <= 0 {
		return nil, fmt.Errorf("%w: invalid multicodec prefix: %s", ErrInvalidDID, didStr)
	}
	rawKey := keyBytes[n:]

	logging.Log().Debugf("did:key multicodec=0x%x, raw key length=%d", codec, len(rawKey))

	// Convert to JWK based on codec
	jwkKey, vmType, err := multicodecToJWK(codec, rawKey)
	if err != nil {
		logging.Log().Infof("Failed to convert did:key to JWK (codec=0x%x): %v", codec, err)
		return nil, fmt.Errorf("failed to convert did:key to JWK: %w", err)
	}

	vmID := baseDID + "#" + methodSpecificID

	vm, err := NewVerificationMethodFromJWK(vmID, vmType, baseDID, jwkKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create verification method: %w", err)
	}

	logging.Log().Debugf("Successfully resolved did:key %s with type %s", baseDID, vmType)

	doc := &Doc{
		ID:                 baseDID,
		VerificationMethod: []VerificationMethod{*vm},
	}

	return &DocResolution{DIDDocument: doc}, nil
}

// multicodecToJWK converts multicodec-prefixed raw key bytes into a JWK key.
func multicodecToJWK(codec uint64, rawKey []byte) (jwk.Key, string, error) {
	switch codec {
	case multicodecEd25519Pub:
		if len(rawKey) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("invalid Ed25519 key size: %d", len(rawKey))
		}
		pubKey := ed25519.PublicKey(rawKey)
		key, err := jwk.Import(pubKey)
		if err != nil {
			return nil, "", err
		}
		return key, TypeEd25519VerificationKey2020, nil

	case multicodecP256Pub:
		pubKey, err := decodeCompressedEC(elliptic.P256(), rawKey)
		if err != nil {
			return nil, "", fmt.Errorf("invalid P-256 key: %w", err)
		}
		key, err := jwk.Import(pubKey)
		if err != nil {
			return nil, "", err
		}
		return key, TypeJsonWebKey2020, nil

	case multicodecP384Pub:
		pubKey, err := decodeCompressedEC(elliptic.P384(), rawKey)
		if err != nil {
			return nil, "", fmt.Errorf("invalid P-384 key: %w", err)
		}
		key, err := jwk.Import(pubKey)
		if err != nil {
			return nil, "", err
		}
		return key, TypeJsonWebKey2020, nil

	case multicodecSecp256k1Pub:
		logging.Log().Info("secp256k1 keys (multicodec 0xe7) are not supported: secp256k1 curve is not available in Go's standard library")
		return nil, "", fmt.Errorf("unsupported multicodec: 0x%x (secp256k1 is not supported in Go's standard crypto library)", codec)

	default:
		return nil, "", fmt.Errorf("unsupported multicodec: 0x%x", codec)
	}
}

// decodeCompressedEC decodes a compressed or uncompressed EC point.
func decodeCompressedEC(curve elliptic.Curve, data []byte) (*ecdsa.PublicKey, error) {
	byteLen := (curve.Params().BitSize + 7) / 8

	if len(data) == 1+2*byteLen && data[0] == 0x04 {
		// Uncompressed point
		x := new(big.Int).SetBytes(data[1 : 1+byteLen])
		y := new(big.Int).SetBytes(data[1+byteLen:])
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}

	if len(data) == 1+byteLen && (data[0] == 0x02 || data[0] == 0x03) {
		// Compressed point — decompress using elliptic.UnmarshalCompressed (Go 1.15+)
		x, y := elliptic.UnmarshalCompressed(curve, data)
		if x == nil {
			return nil, fmt.Errorf("failed to decompress EC point on %s", curve.Params().Name)
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}

	return nil, fmt.Errorf("unexpected key length %d for curve %s", len(data), curve.Params().Name)
}
