package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// multicodecX25519Pub is the multicodec code for X25519 key-agreement public
// keys. DID documents publish them routinely next to their signing keys, and
// they are the reason an unsupported codec must not warn.
const multicodecX25519Pub = 0xec

// encodeMultibaseKey is a test helper that multibase-encodes a raw public key
// with the given multicodec prefix using base58btc ('z') encoding.
func encodeMultibaseKey(codec uint64, rawKey []byte) string {
	var prefix [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(prefix[:], codec)
	multicodecKey := append(prefix[:n], rawKey...)
	encoded, _ := multibase.Encode(multibase.Base58BTC, multicodecKey)
	return encoded
}

func TestDecodeMultibaseKey(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) string // returns multibase-encoded key
		wantKeyType jwa.KeyType
		wantCurve   jwa.EllipticCurveAlgorithm
		checkCurve  bool   // whether to verify the curve
		wantErr     string // substring of expected error; empty means success
		// wantUnsupported says whether the error must be
		// ErrorUnsupportedMulticodec. did_web.go decides between Debug and
		// Warn on it, so a decoding failure that started matching it - or an
		// unsupported codec that stopped - would silently invert the log
		// level for every DID document that publishes such a key.
		wantUnsupported bool
	}{
		{
			name: "valid Ed25519 key",
			setup: func(t *testing.T) string {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				return encodeMultibaseKey(MulticodecEd25519Pub, pub)
			},
			wantKeyType: jwa.OKP(),
			wantCurve:   jwa.Ed25519(),
			checkCurve:  true,
		},
		{
			name: "valid P-256 compressed key",
			setup: func(t *testing.T) string {
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				compressed := elliptic.MarshalCompressed(elliptic.P256(), privKey.X, privKey.Y)
				return encodeMultibaseKey(MulticodecP256Pub, compressed)
			},
			wantKeyType: jwa.EC(),
			wantCurve:   jwa.P256(),
			checkCurve:  true,
		},
		{
			name: "valid P-384 compressed key",
			setup: func(t *testing.T) string {
				privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				compressed := elliptic.MarshalCompressed(elliptic.P384(), privKey.X, privKey.Y)
				return encodeMultibaseKey(MulticodecP384Pub, compressed)
			},
			wantKeyType: jwa.EC(),
			wantCurve:   jwa.P384(),
			checkCurve:  true,
		},
		{
			name: "invalid multibase encoding",
			setup: func(t *testing.T) string {
				return "not-valid-multibase!!!"
			},
			wantErr: "failed to decode multibase",
		},
		{
			name: "unknown multicodec prefix",
			setup: func(t *testing.T) string {
				// Use a multicodec code that is not supported (0xFF)
				return encodeMultibaseKey(0xFF, make([]byte, 32))
			},
			wantErr:         "unsupported_multicodec",
			wantUnsupported: true,
		},
		{
			name: "X25519 key agreement key",
			setup: func(t *testing.T) string {
				return encodeMultibaseKey(multicodecX25519Pub, make([]byte, 32))
			},
			wantErr:         "unsupported_multicodec",
			wantUnsupported: true,
		},
		{
			name: "truncated Ed25519 key data",
			setup: func(t *testing.T) string {
				// Ed25519 requires 32 bytes; provide only 16
				return encodeMultibaseKey(MulticodecEd25519Pub, make([]byte, 16))
			},
			wantErr: "invalid Ed25519 key size",
		},
		{
			name: "truncated P-256 key data",
			setup: func(t *testing.T) string {
				// P-256 compressed needs 33 bytes (1 prefix + 32 coord);
				// provide only 10 bytes that look like compressed form
				return encodeMultibaseKey(MulticodecP256Pub, append([]byte{0x02}, make([]byte, 9)...))
			},
			wantErr: "invalid P-256 key",
		},
		{
			name: "key data too short for varint and key",
			setup: func(t *testing.T) string {
				// Only 1 byte total — not enough for varint + key
				encoded, _ := multibase.Encode(multibase.Base58BTC, []byte{0xed})
				return encoded
			},
			wantErr: "key data too short",
		},
		{
			name: "secp256k1 unsupported",
			setup: func(t *testing.T) string {
				return encodeMultibaseKey(MulticodecSecp256k1Pub, make([]byte, 33))
			},
			wantErr:         "unsupported_multicodec",
			wantUnsupported: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			multibaseEncoded := tc.setup(t)
			key, err := DecodeMultibaseKey(multibaseEncoded)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Equal(t, tc.wantUnsupported, errors.Is(err, ErrorUnsupportedMulticodec))
				assert.Nil(t, key)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, key)
			assert.Equal(t, tc.wantKeyType, key.KeyType())

			if tc.checkCurve {
				var crv jwa.EllipticCurveAlgorithm
				err := key.Get(jwk.ECDSACrvKey, &crv)
				if err != nil {
					// OKP keys use OKPCrvKey
					err = key.Get(jwk.OKPCrvKey, &crv)
				}
				require.NoError(t, err, "key should have crv parameter")
				assert.Equal(t, tc.wantCurve, crv)
			}
		})
	}
}

func TestMulticodecToJWK(t *testing.T) {
	tests := []struct {
		name       string
		codec      uint64
		rawKey     func(t *testing.T) []byte
		wantVMType string
		wantErr    string
	}{
		{
			name:  "Ed25519",
			codec: MulticodecEd25519Pub,
			rawKey: func(t *testing.T) []byte {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				return pub
			},
			wantVMType: TypeEd25519VerificationKey2020,
		},
		{
			name:  "P-256",
			codec: MulticodecP256Pub,
			rawKey: func(t *testing.T) []byte {
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return elliptic.MarshalCompressed(elliptic.P256(), privKey.X, privKey.Y)
			},
			wantVMType: TypeJsonWebKey2020,
		},
		{
			name:  "P-384",
			codec: MulticodecP384Pub,
			rawKey: func(t *testing.T) []byte {
				privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return elliptic.MarshalCompressed(elliptic.P384(), privKey.X, privKey.Y)
			},
			wantVMType: TypeJsonWebKey2020,
		},
		{
			name:  "unsupported codec",
			codec: 0xABCD,
			rawKey: func(t *testing.T) []byte {
				return make([]byte, 32)
			},
			wantErr: "unsupported_multicodec: 0xabcd",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.rawKey(t)
			key, vmType, err := MulticodecToJWK(tc.codec, raw)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.ErrorIs(t, err, ErrorUnsupportedMulticodec)
				assert.Nil(t, key)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, key)
			assert.Equal(t, tc.wantVMType, vmType)
		})
	}
}

func TestDecodeCompressedEC(t *testing.T) {
	tests := []struct {
		name    string
		curve   elliptic.Curve
		setup   func(t *testing.T) []byte
		wantErr string
	}{
		{
			name:  "P-256 compressed point",
			curve: elliptic.P256(),
			setup: func(t *testing.T) []byte {
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return elliptic.MarshalCompressed(elliptic.P256(), privKey.X, privKey.Y)
			},
		},
		{
			name:  "P-256 uncompressed point",
			curve: elliptic.P256(),
			setup: func(t *testing.T) []byte {
				privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				// crypto/ecdh's Bytes() is the uncompressed SEC 1 encoding
				// (0x04 || x || y) that the deprecated elliptic.Marshal
				// produced.
				ecdhKey, err := privKey.ECDH()
				require.NoError(t, err)
				return ecdhKey.PublicKey().Bytes()
			},
		},
		{
			name:  "P-384 compressed point",
			curve: elliptic.P384(),
			setup: func(t *testing.T) []byte {
				privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return elliptic.MarshalCompressed(elliptic.P384(), privKey.X, privKey.Y)
			},
		},
		{
			name:  "unexpected key length",
			curve: elliptic.P256(),
			setup: func(t *testing.T) []byte {
				return []byte{0x04, 0x01, 0x02} // too short for uncompressed P-256
			},
			wantErr: "unexpected key length",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.setup(t)
			pubKey, err := decodeCompressedEC(tc.curve, data)

			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, pubKey)
			// ECDH() performs the on-curve check the deprecated
			// elliptic.Curve.IsOnCurve did: crypto/ecdh's NewPublicKey
			// rejects a point that is not on the curve.
			_, err = pubKey.ECDH()
			assert.NoError(t, err, "decoded point should be on the curve")
		})
	}
}
