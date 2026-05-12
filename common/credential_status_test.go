package common

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"testing"
)

// encodeBitstring is a test helper that produces the base64url(gzip(raw))
// encoding expected on a status-list credential's `encodedList` field.
func encodeBitstring(t *testing.T, raw []byte) string {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(raw); err != nil {
		t.Fatalf("gzip write failed: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close failed: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func TestParseStatusListEntries(t *testing.T) {
	type testCase struct {
		name    string
		input   interface{}
		want    []StatusListEntry
		wantErr error
	}

	singleEntry := map[string]interface{}{
		JSONLDKeyID:                            "urn:status:1",
		StatusListEntryKeyType:                 TypeBitstringStatusListEntry,
		StatusListEntryKeyStatusPurpose:        "revocation",
		StatusListEntryKeyStatusListCredential: "https://example.org/status/1",
		StatusListEntryKeyStatusListIndex:      "42",
	}
	expectedSingle := StatusListEntry{
		ID:                   "urn:status:1",
		Type:                 TypeBitstringStatusListEntry,
		StatusPurpose:        "revocation",
		StatusListCredential: "https://example.org/status/1",
		StatusListIndex:      42,
		StatusSize:           DefaultStatusSizeBits,
	}

	arrayEntries := []interface{}{
		map[string]interface{}{
			StatusListEntryKeyType:                 TypeBitstringStatusListEntry,
			StatusListEntryKeyStatusPurpose:        "revocation",
			StatusListEntryKeyStatusListCredential: "https://example.org/status/r",
			StatusListEntryKeyStatusListIndex:      float64(3),
			StatusListEntryKeyStatusSize:           float64(2),
		},
		map[string]interface{}{
			StatusListEntryKeyType:                 TypeStatusList2021Entry,
			StatusListEntryKeyStatusPurpose:        "suspension",
			StatusListEntryKeyStatusListCredential: "https://example.org/status/s",
			StatusListEntryKeyStatusListIndex:      "7",
		},
	}

	expectedArray := []StatusListEntry{
		{
			Type:                 TypeBitstringStatusListEntry,
			StatusPurpose:        "revocation",
			StatusListCredential: "https://example.org/status/r",
			StatusListIndex:      3,
			StatusSize:           2,
		},
		{
			Type:                 TypeStatusList2021Entry,
			StatusPurpose:        "suspension",
			StatusListCredential: "https://example.org/status/s",
			StatusListIndex:      7,
			StatusSize:           DefaultStatusSizeBits,
		},
	}

	tests := []testCase{
		{
			name:  "nil input returns empty slice",
			input: nil,
			want:  nil,
		},
		{
			name:  "single object",
			input: singleEntry,
			want:  []StatusListEntry{expectedSingle},
		},
		{
			name:  "array of objects",
			input: arrayEntries,
			want:  expectedArray,
		},
		{
			name: "numeric index as float",
			input: map[string]interface{}{
				StatusListEntryKeyType:                 TypeBitstringStatusListEntry,
				StatusListEntryKeyStatusListCredential: "https://example.org/s",
				StatusListEntryKeyStatusListIndex:      float64(123),
			},
			want: []StatusListEntry{{
				Type:                 TypeBitstringStatusListEntry,
				StatusListCredential: "https://example.org/s",
				StatusListIndex:      123,
				StatusSize:           DefaultStatusSizeBits,
			}},
		},
		{
			name:    "unsupported top-level type",
			input:   "not an object",
			wantErr: ErrorStatusListEntryMalformed,
		},
		{
			name: "array element is not an object",
			input: []interface{}{
				"not an object",
			},
			wantErr: ErrorStatusListEntryMalformed,
		},
		{
			name: "non-string statusListCredential",
			input: map[string]interface{}{
				StatusListEntryKeyStatusListCredential: 123,
			},
			wantErr: ErrorStatusListEntryMalformed,
		},
		{
			name: "invalid numeric string index",
			input: map[string]interface{}{
				StatusListEntryKeyStatusListIndex: "not-a-number",
			},
			wantErr: ErrorStatusListEntryMalformed,
		},
		{
			name: "negative numeric index",
			input: map[string]interface{}{
				StatusListEntryKeyStatusListIndex: float64(-1),
			},
			wantErr: ErrorStatusListEntryMalformed,
		},
		{
			name: "invalid statusSize",
			input: map[string]interface{}{
				StatusListEntryKeyStatusListIndex: "0",
				StatusListEntryKeyStatusSize:      float64(0),
			},
			wantErr: ErrorStatusListInvalidStatusSize,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseStatusListEntries(tc.input)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("expected %d entries, got %d (%#v)", len(tc.want), len(got), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("entry %d mismatch:\n got:  %#v\n want: %#v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestDecodeBitstring(t *testing.T) {
	// Round-trip a known payload.
	payload := []byte{0x00, 0x01, 0x80, 0xFF}
	encoded := encodeBitstring(t, payload)

	decoded, err := DecodeBitstring(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("round-trip mismatch:\n got:  %x\n want: %x", decoded, payload)
	}
}

func TestDecodeBitstring_Padded(t *testing.T) {
	// Some issuers use padded base64url. DecodeBitstring must accept both.
	payload := []byte{0xAA, 0xBB, 0xCC}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(payload); err != nil {
		t.Fatalf("gzip write failed: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close failed: %v", err)
	}
	padded := base64.URLEncoding.EncodeToString(buf.Bytes())

	decoded, err := DecodeBitstring(padded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("round-trip mismatch:\n got:  %x\n want: %x", decoded, payload)
	}
}

func TestDecodeBitstring_Errors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "invalid base64", input: "not*valid*base64"},
		{name: "valid base64 but not gzip", input: base64.RawURLEncoding.EncodeToString([]byte{0x00, 0x01, 0x02})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeBitstring(tc.input)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !errors.Is(err, ErrorStatusListBitstringDecode) {
				t.Fatalf("expected ErrorStatusListBitstringDecode, got %v", err)
			}
		})
	}
}

func TestIsStatusSet(t *testing.T) {
	// bitstring layout in MSB-first order per byte:
	// byte 0 = 0b10000001 -> bit 0 set, bit 7 set
	// byte 1 = 0b00001000 -> bit 12 set
	bitstring := []byte{0b10000001, 0b00001000}

	tests := []struct {
		name       string
		index      uint64
		statusSize int
		want       bool
		wantErr    error
	}{
		{name: "first bit set", index: 0, statusSize: 1, want: true},
		{name: "second bit clear", index: 1, statusSize: 1, want: false},
		{name: "last bit of first byte set", index: 7, statusSize: 1, want: true},
		{name: "middle bit set (index 12)", index: 12, statusSize: 1, want: true},
		{name: "adjacent bit clear (index 11)", index: 11, statusSize: 1, want: false},
		{name: "last bit in bitstring clear", index: 15, statusSize: 1, want: false},
		{name: "index out of range", index: 16, statusSize: 1, wantErr: ErrorStatusListIndexOutOfRange},
		{name: "zero statusSize", index: 0, statusSize: 0, wantErr: ErrorStatusListInvalidStatusSize},
		{name: "negative statusSize", index: 0, statusSize: -1, wantErr: ErrorStatusListInvalidStatusSize},
		{name: "multi-bit group all clear", index: 1, statusSize: 2, want: false},   // bits 2,3 = 00
		{name: "multi-bit group with set bit", index: 3, statusSize: 2, want: true}, // bits 6,7 = 01
		{name: "multi-bit group exceeds bitstring", index: 8, statusSize: 2, wantErr: ErrorStatusListIndexOutOfRange},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := IsStatusSet(bitstring, tc.index, tc.statusSize)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("IsStatusSet(%d, %d) = %v, want %v", tc.index, tc.statusSize, got, tc.want)
			}
		})
	}
}

func TestIsStatusSet_RoundTripWithDecodeBitstring(t *testing.T) {
	// Build a bitstring with bit 42 set (MSB-first): byte 5 bit 2 = 0b00100000.
	const revokedIndex uint64 = 42
	const bitstringBytes = 16
	raw := make([]byte, bitstringBytes)
	byteIndex := revokedIndex / BitsPerByte
	bitInByte := revokedIndex % BitsPerByte
	raw[byteIndex] = byte(1) << (BitsPerByte - 1 - bitInByte)

	encoded := encodeBitstring(t, raw)
	decoded, err := DecodeBitstring(encoded)
	if err != nil {
		t.Fatalf("DecodeBitstring failed: %v", err)
	}

	got, err := IsStatusSet(decoded, revokedIndex, DefaultStatusSizeBits)
	if err != nil {
		t.Fatalf("IsStatusSet failed: %v", err)
	}
	if !got {
		t.Fatalf("expected index %d to be set after round-trip", revokedIndex)
	}

	// A neighbouring index must be clear.
	got, err = IsStatusSet(decoded, revokedIndex+1, DefaultStatusSizeBits)
	if err != nil {
		t.Fatalf("IsStatusSet failed: %v", err)
	}
	if got {
		t.Fatalf("expected index %d to be clear after round-trip", revokedIndex+1)
	}
}
