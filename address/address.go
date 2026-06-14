// Package address implements QOGE address derivation from SLH-DSA public keys.
//
// Derivation scheme (SIP-QOGE-PQC-01, Section 5.2):
//
//	hash    = SHA256(SHA256(pubkey))   // HASH256 — same as Bitcoin P2PKH
//	address = Bech32(hrp="bq", hash) // custom HRP, witness version 0
//
// The HASH256 layer keeps the public key hidden behind a hash at rest.
// The public key is only revealed in the witness field at spend time.
// This is the fundamental HNDL defence: a quantum computer cannot attack
// a key it cannot see.
//
// NOTE: Taproot (P2TR / Bech32m) is intentionally NOT implemented.
// P2TR encodes the public key directly in the address, defeating HNDL
// defence. Its absence here is a security requirement, not an omission.
// See SIP-QOGE-PQC-01 Section 3.1.
package address

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/bech32"
)

// HRP is the human-readable part for QOGE Bech32 addresses.
// All QOGE addresses start with "bq1".
const HRP = "bq"

// WitnessVersion is the SegWit witness version (0 = P2WPKH equivalent).
const WitnessVersion = 0

// AddressLength is the expected byte length of a decoded QOGE address hash.
// SHA256(SHA256(pubkey)) = 32 bytes.
const AddressLength = 32

// ErrInvalidPublicKeyLength is returned when a public key has wrong length.
var ErrInvalidPublicKeyLength = errors.New("address: invalid SLH-DSA public key length (want 32 bytes)")

// ErrInvalidAddress is returned when Bech32 decoding fails.
var ErrInvalidAddress = errors.New("address: invalid QOGE address")

// ErrWrongHRP is returned when an address has a non-QOGE HRP.
var ErrWrongHRP = errors.New("address: wrong human-readable part (not a QOGE address)")

// ErrTaprootDetected is returned when a Taproot address is supplied.
// Taproot is disabled — see package doc.
var ErrTaprootDetected = errors.New("address: Taproot (Bech32m/P2TR) addresses are disabled in QOGE wallet — HNDL risk")

// FromPublicKey derives a QOGE Bech32 address from a 32-byte SLH-DSA public key.
// This is the canonical address derivation function for the QOGE SPHINCS wallet.
//
// Equivalent to Bitcoin P2WPKH derivation but using our own HRP and
// replacing the 20-byte HASH160 with a 32-byte HASH256 for stronger
// pre-image resistance against both Grover and classical attacks.
func FromPublicKey(pubKey []byte) (string, error) {
	if len(pubKey) != 32 {
		return "", ErrInvalidPublicKeyLength
	}
	hash := hash256(pubKey)
	return encode(hash)
}

// ToHash decodes a QOGE address string and returns the 32-byte HASH256.
// Use this to verify that a received address matches an expected public key.
func ToHash(addr string) ([]byte, error) {
	return decode(addr)
}

// ValidateAddress checks that addr is a well-formed QOGE address.
// Returns nil if valid, a descriptive error otherwise.
func ValidateAddress(addr string) error {
	_, err := decode(addr)
	return err
}

// MatchesPublicKey returns true if addr was derived from pubKey.
// Use this before signing to assert the address belongs to the held keypair.
func MatchesPublicKey(addr string, pubKey []byte) (bool, error) {
	if len(pubKey) != 32 {
		return false, ErrInvalidPublicKeyLength
	}
	decoded, err := decode(addr)
	if err != nil {
		return false, err
	}
	expected := hash256(pubKey)
	if len(decoded) != len(expected) {
		return false, nil
	}
	// Constant-time comparison to prevent timing side-channels.
	var diff byte
	for i := range expected {
		diff |= decoded[i] ^ expected[i]
	}
	return diff == 0, nil
}

// ─── internal helpers ────────────────────────────────────────────────────────

// hash256 computes SHA256(SHA256(data)) — Bitcoin's HASH256.
func hash256(data []byte) []byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second[:]
}

// encode converts a 32-byte hash to a Bech32 address with HRP="qoge".
func encode(hash []byte) (string, error) {
	// Bech32 encodes 5-bit groups; convert 8-bit bytes to 5-bit groups.
	converted, err := bech32.ConvertBits(hash, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("address: ConvertBits failed: %w", err)
	}
	// Prepend witness version byte (0x00).
	payload := append([]byte{WitnessVersion}, converted...)
	addr, err := bech32.Encode(HRP, payload)
	if err != nil {
		return "", fmt.Errorf("address: Bech32 encode failed: %w", err)
	}
	return addr, nil
}

// decode decodes a Bech32 QOGE address and returns the 32-byte hash.
func decode(addr string) ([]byte, error) {
	hrp, payload, err := bech32.Decode(addr)
	if err != nil {
		// Distinguish Bech32m (Taproot) from regular Bech32 errors.
		if isBech32m(addr) {
			return nil, ErrTaprootDetected
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	if hrp != HRP {
		return nil, fmt.Errorf("%w: got %q", ErrWrongHRP, hrp)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("%w: empty payload", ErrInvalidAddress)
	}
	// First byte is witness version.
	if payload[0] != WitnessVersion {
		return nil, fmt.Errorf("%w: unexpected witness version %d", ErrInvalidAddress, payload[0])
	}
	// Convert 5-bit groups back to 8-bit bytes.
	decoded, err := bech32.ConvertBits(payload[1:], 5, 8, false)
	if err != nil {
		return nil, fmt.Errorf("address: ConvertBits decode failed: %w", err)
	}
	if len(decoded) != AddressLength {
		return nil, fmt.Errorf("%w: decoded length %d (want %d)",
			ErrInvalidAddress, len(decoded), AddressLength)
	}
	return decoded, nil
}

// isBech32m does a quick heuristic check for Taproot (bc1p / bq1p-style).
// Full Bech32m detection is not needed — we just want a helpful error.
func isBech32m(addr string) bool {
	if len(addr) < 5 {
		return false
	}
	// Bech32m addresses use a different checksum constant (0x2bc830a3).
	// A simpler heuristic: Taproot witness version is 1, encoded as 'p'
	// in Bech32's charset after the separator.
	// For QOGE this would appear as "bq1p...".
	for i, c := range addr {
		if c == '1' && i+1 < len(addr) {
			return addr[i+1] == 'p'
		}
	}
	return false
}
