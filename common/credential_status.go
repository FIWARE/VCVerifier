// Package common contains shared types and helpers used across the VCVerifier
// codebase. This file defines the data model and helpers for W3C Bitstring
// Status List / StatusList2021 credentials referenced from a Verifiable
// Credential's `credentialStatus` field, as well as the IETF OAuth 2.0
// Token Status List format (draft-ietf-oauth-status-list).
//
// References:
//   - https://www.w3.org/TR/vc-bitstring-status-list/
//   - https://www.w3.org/TR/2023/WD-vc-status-list-20230427/ (StatusList2021)
//   - https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html
package common

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Type names for status-list entries and status-list credentials as defined by
// the W3C Bitstring Status List and the legacy StatusList2021 specifications.
const (
	// TypeBitstringStatusListEntry is the `type` value of a credential's
	// `credentialStatus` entry that references a BitstringStatusListCredential.
	TypeBitstringStatusListEntry = "BitstringStatusListEntry"
	// TypeBitstringStatusListCredential is the `type` value of a status-list
	// credential that carries an encoded bitstring.
	TypeBitstringStatusListCredential = "BitstringStatusListCredential"
	// TypeStatusList2021Entry is the legacy StatusList2021 entry type.
	TypeStatusList2021Entry = "StatusList2021Entry"
	// TypeStatusList2021Credential is the legacy StatusList2021 credential type.
	TypeStatusList2021Credential = "StatusList2021Credential"
)

// JSON field keys used by status-list credentials and status-list entries.
const (
	// StatusListKeyEncodedList is the key on a status-list credential's
	// `credentialSubject` that carries the base64url-encoded, gzip-compressed
	// bitstring.
	StatusListKeyEncodedList = "encodedList"
	// StatusListKeyStatusPurpose is the key on a status-list credential's
	// `credentialSubject` that carries the purpose of the list (e.g.
	// "revocation" or "suspension").
	StatusListKeyStatusPurpose = "statusPurpose"

	// StatusListEntryKeyType is the JSON-LD type key for a status-list entry.
	StatusListEntryKeyType = "type"
	// StatusListEntryKeyStatusListIndex is the key holding the index (as a
	// numeric string or number) into the referenced bitstring.
	StatusListEntryKeyStatusListIndex = "statusListIndex"
	// StatusListEntryKeyStatusListCredential is the URL key pointing at the
	// status-list credential to fetch.
	StatusListEntryKeyStatusListCredential = "statusListCredential"
	// StatusListEntryKeyStatusPurpose is the purpose declared on the entry
	// (must match the purpose of the fetched status-list credential).
	StatusListEntryKeyStatusPurpose = "statusPurpose"
	// StatusListEntryKeyStatusSize is the optional bit size per status on the
	// entry. Defaults to DefaultStatusSizeBits.
	StatusListEntryKeyStatusSize = "statusSize"
)

// IETF Token Status List constants — keys and types used by the OAuth 2.0
// Token Status List specification (draft-ietf-oauth-status-list).
const (
	// IETFStatusClaimKey is the top-level key inside credentialSubject that
	// carries the IETF status reference.
	IETFStatusClaimKey = "status"
	// IETFStatusListKey is the nested key inside the status object.
	IETFStatusListKey = "status_list"
	// IETFStatusListIdx is the index key inside the status_list object.
	IETFStatusListIdx = "idx"
	// IETFStatusListURI is the URI key inside the status_list object.
	IETFStatusListURI = "uri"
	// IETFStatusListBits is the bits-per-status key in a fetched status list JWT payload.
	IETFStatusListBits = "bits"
	// IETFStatusListLst is the encoded-list key in a fetched status list JWT payload.
	IETFStatusListLst = "lst"

	// ContentTypeStatusListJWT is the Accept / Content-Type header for
	// IETF Token Status List JWT responses.
	ContentTypeStatusListJWT = "application/statuslist+jwt"
)

// Numeric defaults for status-list encoding.
const (
	// DefaultStatusSizeBits is the number of bits per status when an entry
	// does not declare `statusSize`.
	DefaultStatusSizeBits = 1
	// BitsPerByte is the number of bits in a single byte.
	BitsPerByte = 8
)

// Typed errors returned by the helpers in this file. They are exported so
// callers can match against them using `errors.Is`.
var (
	// ErrorStatusListEntryMalformed is returned by ParseStatusListEntries when a
	// credential's `credentialStatus` value is of an unexpected shape or a
	// required field is missing or has the wrong type.
	ErrorStatusListEntryMalformed = errors.New("malformed credentialStatus entry")
	// ErrorStatusListBitstringDecode is returned by DecodeBitstring when the
	// encoded value cannot be base64url-decoded or gzip-inflated.
	ErrorStatusListBitstringDecode = errors.New("failed to decode status-list bitstring")
	// ErrorStatusListIndexOutOfRange is returned by IsStatusSet when the index
	// falls outside the range represented by the decoded bitstring.
	ErrorStatusListIndexOutOfRange = errors.New("status-list index out of range")
	// ErrorStatusListInvalidStatusSize is returned by IsStatusSet when
	// statusSize is not a positive integer.
	ErrorStatusListInvalidStatusSize = errors.New("invalid status-list statusSize")
)

// StatusListEntry represents a parsed `credentialStatus` entry pointing at a
// Bitstring Status List or StatusList2021 credential.
type StatusListEntry struct {
	// ID is the optional `id` of the entry.
	ID string
	// Type is the JSON-LD type value of the entry (e.g.
	// "BitstringStatusListEntry"). Empty when the source object omitted the
	// field.
	Type string
	// StatusPurpose describes what the referenced bit represents (for example
	// "revocation" or "suspension"). Empty when the source object omitted the
	// field.
	StatusPurpose string
	// StatusListCredential is the URL of the status-list credential to fetch.
	StatusListCredential string
	// StatusListIndex is the zero-based bit index into the decoded bitstring.
	StatusListIndex uint64
	// StatusSize is the number of bits per status. Defaults to
	// DefaultStatusSizeBits when not declared on the entry.
	StatusSize int
}

// StatusListCredential is a lightweight, decoded view of a status-list
// credential. The encoded bitstring is kept verbatim on the struct; use
// DecodeBitstring to obtain the raw bytes.
type StatusListCredential struct {
	// EncodedList is the base64url-encoded, gzip-compressed bitstring as it
	// appears on the status-list credential's `credentialSubject.encodedList`
	// field.
	EncodedList string
	// StatusPurpose is the purpose declared by the status-list credential
	// (e.g. "revocation" or "suspension"). Callers must ensure this matches
	// the purpose declared on the referencing status-list entry.
	StatusPurpose string
}

// ParseStatusListEntries converts the raw value found under a credential's
// `credentialStatus` field into a slice of StatusListEntry values.
//
// The W3C VC Data Model 2.0 allows `credentialStatus` to be either a single
// object or an array of objects, so this helper accepts both shapes. A nil or
// missing value returns an empty slice with a nil error — callers treat
// "no status entries" as "nothing to check".
//
// A non-nil error is returned if the value is of an unexpected shape or if a
// required field on any entry cannot be parsed into its target type.
func ParseStatusListEntries(raw interface{}) ([]StatusListEntry, error) {
	if raw == nil {
		return nil, nil
	}
	switch v := raw.(type) {
	case map[string]interface{}:
		entry, err := parseStatusListEntry(v)
		if err != nil {
			return nil, err
		}
		return []StatusListEntry{entry}, nil
	case []interface{}:
		entries := make([]StatusListEntry, 0, len(v))
		for i, item := range v {
			obj, ok := item.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("%w: entry at index %d is not a JSON object", ErrorStatusListEntryMalformed, i)
			}
			entry, err := parseStatusListEntry(obj)
			if err != nil {
				return nil, fmt.Errorf("entry at index %d: %w", i, err)
			}
			entries = append(entries, entry)
		}
		return entries, nil
	default:
		return nil, fmt.Errorf("%w: expected object or array, got %T", ErrorStatusListEntryMalformed, raw)
	}
}

// parseStatusListEntry converts a single JSON object into a StatusListEntry.
// It is the internal worker behind ParseStatusListEntries and applies the same
// validation rules to every element regardless of whether it came from a
// single-object or an array-shaped `credentialStatus` field.
func parseStatusListEntry(obj map[string]interface{}) (StatusListEntry, error) {
	entry := StatusListEntry{StatusSize: DefaultStatusSizeBits}

	if id, ok := obj[JSONLDKeyID]; ok && id != nil {
		s, ok := id.(string)
		if !ok {
			return StatusListEntry{}, fmt.Errorf("%w: %q must be a string", ErrorStatusListEntryMalformed, JSONLDKeyID)
		}
		entry.ID = s
	}
	if t, ok := obj[StatusListEntryKeyType]; ok && t != nil {
		s, ok := t.(string)
		if !ok {
			return StatusListEntry{}, fmt.Errorf("%w: %q must be a string", ErrorStatusListEntryMalformed, StatusListEntryKeyType)
		}
		entry.Type = s
	}
	if p, ok := obj[StatusListEntryKeyStatusPurpose]; ok && p != nil {
		s, ok := p.(string)
		if !ok {
			return StatusListEntry{}, fmt.Errorf("%w: %q must be a string", ErrorStatusListEntryMalformed, StatusListEntryKeyStatusPurpose)
		}
		entry.StatusPurpose = s
	}
	if c, ok := obj[StatusListEntryKeyStatusListCredential]; ok && c != nil {
		s, ok := c.(string)
		if !ok {
			return StatusListEntry{}, fmt.Errorf("%w: %q must be a string", ErrorStatusListEntryMalformed, StatusListEntryKeyStatusListCredential)
		}
		entry.StatusListCredential = s
	}
	if idx, ok := obj[StatusListEntryKeyStatusListIndex]; ok && idx != nil {
		parsed, err := parseStatusListIndex(idx)
		if err != nil {
			return StatusListEntry{}, err
		}
		entry.StatusListIndex = parsed
	}
	if sz, ok := obj[StatusListEntryKeyStatusSize]; ok && sz != nil {
		parsed, err := parseStatusSize(sz)
		if err != nil {
			return StatusListEntry{}, err
		}
		entry.StatusSize = parsed
	}
	return entry, nil
}

// parseStatusListIndex accepts the several JSON shapes that a
// `statusListIndex` value may take (per W3C VC 2.0 it is usually serialised
// as a string, but the numeric form is common in the wild) and returns a
// uint64.
func parseStatusListIndex(raw interface{}) (uint64, error) {
	switch v := raw.(type) {
	case string:
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: %q is not a valid unsigned integer: %v", ErrorStatusListEntryMalformed, StatusListEntryKeyStatusListIndex, err)
		}
		return n, nil
	case float64:
		if v < 0 {
			return 0, fmt.Errorf("%w: %q must be non-negative, got %v", ErrorStatusListEntryMalformed, StatusListEntryKeyStatusListIndex, v)
		}
		return uint64(v), nil
	case int:
		if v < 0 {
			return 0, fmt.Errorf("%w: %q must be non-negative, got %d", ErrorStatusListEntryMalformed, StatusListEntryKeyStatusListIndex, v)
		}
		return uint64(v), nil
	case int64:
		if v < 0 {
			return 0, fmt.Errorf("%w: %q must be non-negative, got %d", ErrorStatusListEntryMalformed, StatusListEntryKeyStatusListIndex, v)
		}
		return uint64(v), nil
	case uint64:
		return v, nil
	default:
		return 0, fmt.Errorf("%w: %q must be a numeric string or number, got %T", ErrorStatusListEntryMalformed, StatusListEntryKeyStatusListIndex, raw)
	}
}

// parseStatusSize accepts the numeric or string shapes that a `statusSize`
// value may take and returns a positive int.
func parseStatusSize(raw interface{}) (int, error) {
	var size int
	switch v := raw.(type) {
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("%w: %q is not a valid integer: %v", ErrorStatusListEntryMalformed, StatusListEntryKeyStatusSize, err)
		}
		size = n
	case float64:
		size = int(v)
	case int:
		size = v
	case int64:
		size = int(v)
	default:
		return 0, fmt.Errorf("%w: %q must be an integer, got %T", ErrorStatusListEntryMalformed, StatusListEntryKeyStatusSize, raw)
	}
	if size <= 0 {
		return 0, fmt.Errorf("%w: %q must be positive, got %d", ErrorStatusListInvalidStatusSize, StatusListEntryKeyStatusSize, size)
	}
	return size, nil
}

// DecodeBitstring returns the raw bitstring bytes referenced by a status-list
// credential. The input is the value carried on the credential's
// `credentialSubject.encodedList` field: a base64url-encoded, gzip-compressed
// byte sequence.
//
// The returned slice is the inflated payload. Individual bits can be read
// with IsStatusSet.
func DecodeBitstring(encoded string) ([]byte, error) {
	compressed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		// Accept padded base64url too: some issuers include trailing '='.
		padded, padErr := base64.URLEncoding.DecodeString(encoded)
		if padErr != nil {
			return nil, fmt.Errorf("%w: base64url decode failed: %v", ErrorStatusListBitstringDecode, err)
		}
		compressed = padded
	}

	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("%w: gzip reader init failed: %v", ErrorStatusListBitstringDecode, err)
	}
	defer func() { _ = reader.Close() }()

	decoded, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("%w: gzip inflate failed: %v", ErrorStatusListBitstringDecode, err)
	}
	return decoded, nil
}

// IsStatusSet reports whether the bit at the given status index is set in the
// provided bitstring. The bit ordering follows the W3C Bitstring Status List
// specification: bits are numbered from the most significant bit (bit 0) to
// the least significant bit (bit 7) within each byte, and bytes are read
// left-to-right.
//
// Indexing uses `statusSize` bits per status. When statusSize > 1 the function
// currently returns true if ANY bit in the group is set — this matches the
// common "revoked / suspended" semantics where a non-zero group flags the
// credential. Callers requiring full multi-bit values should build on
// DecodeBitstring directly.
//
// Returns ErrorStatusListIndexOutOfRange when the requested group is not
// covered by `bitstring`, and ErrorStatusListInvalidStatusSize when
// `statusSize` is not a positive integer.
func IsStatusSet(bitstring []byte, index uint64, statusSize int) (bool, error) {
	if statusSize <= 0 {
		return false, fmt.Errorf("%w: got %d", ErrorStatusListInvalidStatusSize, statusSize)
	}

	startBit := index * uint64(statusSize)
	endBitExclusive := startBit + uint64(statusSize)

	totalBits := uint64(len(bitstring)) * uint64(BitsPerByte)
	if endBitExclusive > totalBits {
		return false, fmt.Errorf("%w: index %d with size %d exceeds bitstring of %d bits", ErrorStatusListIndexOutOfRange, index, statusSize, totalBits)
	}

	for bit := startBit; bit < endBitExclusive; bit++ {
		byteIndex := bit / uint64(BitsPerByte)
		bitInByte := bit % uint64(BitsPerByte)
		// Most-significant-bit-first ordering within each byte.
		mask := byte(1) << (uint64(BitsPerByte) - 1 - bitInByte)
		if bitstring[byteIndex]&mask != 0 {
			return true, nil
		}
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// IETF Token Status List helpers
// ---------------------------------------------------------------------------

// IETFStatusEntry represents a parsed status reference from the IETF
// OAuth 2.0 Token Status List format. The entry is extracted from
// `credentialSubject.status.status_list` with fields `idx` and `uri`.
type IETFStatusEntry struct {
	// Idx is the zero-based index into the status list bitstring.
	Idx uint64
	// URI is the URL of the status list resource to fetch.
	URI string
}

// IETFStatusList represents the decoded payload of a fetched IETF Token
// Status List JWT. The `lst` field is the base64url-encoded,
// zlib-compressed bitstring; `bits` declares the number of bits per
// status entry.
type IETFStatusList struct {
	// Bits is the number of bits per status entry (e.g. 1, 2, 4, 8).
	Bits int
	// Lst is the base64url-encoded, zlib-compressed bitstring.
	Lst string
}

// ParseIETFStatusEntry extracts an IETFStatusEntry from the
// `credentialSubject` map of a Verifiable Credential. The expected
// structure is: `{ "status": { "status_list": { "idx": N, "uri": "..." } } }`.
//
// Returns (entry, true) on success, or (zero, false) when the required
// structure is absent or malformed.
func ParseIETFStatusEntry(credentialSubject map[string]interface{}) (IETFStatusEntry, bool) {
	statusRaw, ok := credentialSubject[IETFStatusClaimKey]
	if !ok || statusRaw == nil {
		return IETFStatusEntry{}, false
	}
	statusMap, ok := statusRaw.(map[string]interface{})
	if !ok {
		return IETFStatusEntry{}, false
	}
	listRaw, ok := statusMap[IETFStatusListKey]
	if !ok || listRaw == nil {
		return IETFStatusEntry{}, false
	}
	listMap, ok := listRaw.(map[string]interface{})
	if !ok {
		return IETFStatusEntry{}, false
	}

	uri, ok := listMap[IETFStatusListURI].(string)
	if !ok || uri == "" {
		return IETFStatusEntry{}, false
	}

	idx, err := parseIETFIdx(listMap[IETFStatusListIdx])
	if err != nil {
		return IETFStatusEntry{}, false
	}

	return IETFStatusEntry{Idx: idx, URI: uri}, true
}

// parseIETFIdx converts the `idx` value (which may be a float64 from
// JSON unmarshalling or an integer) to a uint64.
func parseIETFIdx(raw interface{}) (uint64, error) {
	switch v := raw.(type) {
	case float64:
		if v < 0 {
			return 0, fmt.Errorf("idx must be non-negative")
		}
		return uint64(v), nil
	case int:
		if v < 0 {
			return 0, fmt.Errorf("idx must be non-negative")
		}
		return uint64(v), nil
	case int64:
		if v < 0 {
			return 0, fmt.Errorf("idx must be non-negative")
		}
		return uint64(v), nil
	case uint64:
		return v, nil
	case string:
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("idx is not a valid unsigned integer: %v", err)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("idx has unexpected type %T", raw)
	}
}

// DecodeIETFBitstring decodes an IETF Token Status List bitstring.
// The input is base64url-encoded, zlib (DEFLATE) compressed — note that
// this differs from the W3C format which uses gzip compression.
func DecodeIETFBitstring(encoded string) ([]byte, error) {
	compressed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		padded, padErr := base64.URLEncoding.DecodeString(encoded)
		if padErr != nil {
			return nil, fmt.Errorf("%w: base64url decode failed: %v", ErrorStatusListBitstringDecode, err)
		}
		compressed = padded
	}

	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("%w: zlib reader init failed: %v", ErrorStatusListBitstringDecode, err)
	}
	defer func() { _ = reader.Close() }()

	decoded, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("%w: zlib inflate failed: %v", ErrorStatusListBitstringDecode, err)
	}
	return decoded, nil
}

// IsIETFStatusSet reports whether the status value at the given index is
// non-zero in the IETF Token Status List bitstring. The IETF format uses
// LSB-first bit ordering within each byte, unlike the W3C format which
// uses MSB-first.
func IsIETFStatusSet(bitstring []byte, index uint64, bitsPerStatus int) (bool, error) {
	if bitsPerStatus <= 0 {
		return false, fmt.Errorf("%w: got %d", ErrorStatusListInvalidStatusSize, bitsPerStatus)
	}

	startBit := index * uint64(bitsPerStatus)
	endBitExclusive := startBit + uint64(bitsPerStatus)

	totalBits := uint64(len(bitstring)) * uint64(BitsPerByte)
	if endBitExclusive > totalBits {
		return false, fmt.Errorf("%w: index %d with size %d exceeds bitstring of %d bits",
			ErrorStatusListIndexOutOfRange, index, bitsPerStatus, totalBits)
	}

	for bit := startBit; bit < endBitExclusive; bit++ {
		byteIndex := bit / uint64(BitsPerByte)
		bitInByte := bit % uint64(BitsPerByte)
		// LSB-first ordering within each byte (IETF spec).
		mask := byte(1) << bitInByte
		if bitstring[byteIndex]&mask != 0 {
			return true, nil
		}
	}
	return false, nil
}
