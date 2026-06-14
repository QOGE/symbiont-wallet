// Package address implements QOGE address derivation from SLH-DSA public keys.
//
// Derivation scheme (SIP-QOGE-PQC-01 Section 5.2, updated by
// SIP-QOGE-PQC-02 Phase A and SIP-QOGE-PQC-02 Section 5.1):
//
//	hash    = SHA256(SHA256(pubkey))             // HASH256
//	address = Bech32m(hrp="bq", witver=2, hash)  // P2QPK, BIP350 encoding
//
// The HASH256 layer keeps the public key hidden behind a hash at rest.
// The public key is only revealed in the witness field at spend time.
// This is the fundamental HNDL defence: a quantum computer cannot attack
// a key it cannot see.
//
// ── Witness version history ──────────────────────────────────────────────
//
// SIP-QOGE-PQC-01 originally specified witness version 0. SIP-QOGE-PQC-02
// corrected this: a 32-byte witness-v0 program is defined by BIP141 as
// P2WSH (= SHA256(script)), an unrelated commitment — addresses in that
// format would not carry the intended meaning on the real Qogecoin network.
//
// Witness version 2 ("P2QPK" — Pay to Quantum Public Key, SIP-QOGE-PQC-02
// Section 5) has no BIP141-defined meaning: per the confirmed behaviour of
// VerifyWitnessProgram in qogecoin/qogecoin (src/script/interpreter.cpp,
// witversion>=2 branch), v2 programs are currently "anyone can spend",
// pending the SIP-QOGE-PQC-02 soft fork that gives them SLH-DSA meaning.
//
// Per BIP350, witness version 0 uses Bech32 (checksum constant 1) and
// witness versions 1-16 use Bech32m (checksum constant 0x2bc830a3). Since
// this package now uses witver=2, addresses are Bech32m-encoded. See
// bech32m.go for the codec (vendored — the project's btcutil dependency
// implements BIP173/Bech32 only, not BIP350/Bech32m).
//
// ── Taproot (witver=1) ────────────────────────────────────────────────────
//
// Taproot (P2TR / witver=1) addresses are explicitly rejected by decode().
// SIP-QOGE-PQC-02 Section 4 explains why: a Taproot output's key-path
// spending condition is a secp256k1 point present in the address at rest,
// which a CRQC can attack via Shor's algorithm independent of any script-
// path logic. This is a security requirement, not an omission — see
// ErrTaprootDetected.
package address

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/bech32"
)

// HRP is the human-readable part for QOGE Bech32m addresses.
// All QOGE addresses start with "bq1". Confirmed against qogecoin/qogecoin
// release notes ("Bech32 addresses have a bq prefix") — see SIP-QOGE-PQC-01
// HRP correction.
const HRP = "bq"

// WitnessVersion is the SegWit witness version for P2QPK addresses.
//
// SIP-QOGE-PQC-02 Section 5.1: witness version 2, pending the soft fork
// that defines its consensus meaning. Witness versions 0 (P2WPKH/P2WSH)
// and 1 (Taproot) are already defined by BIP141/BIP341 and are NOT
// available for this purpose.
const WitnessVersion = 2

// AddressLength is the expected byte length of a decoded QOGE address
// program. SHA256(SHA256(pubkey)) = 32 bytes.
const AddressLength = 32

// ErrInvalidPublicKeyLength is returned when a public key has wrong length.
var ErrInvalidPublicKeyLength = errors.New("address: invalid SLH-DSA public key length (want 32 bytes)")

// ErrInvalidAddress is returned when address decoding fails.
var ErrInvalidAddress = errors.New("address: invalid QOGE address")

// ErrWrongHRP is returned when an address has a non-QOGE HRP.
var ErrWrongHRP = errors.New("address: wrong human-readable part (not a QOGE address)")

// ErrTaprootDetected is returned when a Taproot (witver=1) address is
// supplied. Taproot is rejected — see package doc and SIP-QOGE-PQC-02
// Section 4.
var ErrTaprootDetected = errors.New("address: Taproot (witness v1 / P2TR) addresses are rejected — HNDL risk via key-path spending, see SIP-QOGE-PQC-02 Section 4")

// FromPublicKey derives a QOGE P2QPK address from a 32-byte SLH-DSA public key.
// This is the canonical address derivation function for the QOGE SPHINCS
// (Symbiont) wallet.
func FromPublicKey(pubKey []byte) (string, error) {
	if len(pubKey) != 32 {
		return "", ErrInvalidPublicKeyLength
	}
	hash := hash256(pubKey)
	return encode(hash)
}

// ToHash decodes a QOGE address string and returns the 32-byte HASH256
// program. Use this to verify that a received address matches an expected
// public key.
func ToHash(addr string) ([]byte, error) {
	return decode(addr)
}

// ValidateAddress checks that addr is a well-formed QOGE P2QPK address.
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

// constantForWitnessVersion returns the BIP350-mandated checksum constant
// for a given witness version: witver 0 -> Bech32 (BIP173), witver 1-16 ->
// Bech32m (BIP350).
func constantForWitnessVersion(witver int) int {
	if witver == 0 {
		return bech32Const
	}
	return bech32mConst
}

// encode converts a 32-byte HASH256 program to a Bech32m address with
// HRP="bq" and witness version WitnessVersion (2).
func encode(hash []byte) (string, error) {
	// bech32.ConvertBits (from btcutil — unaffected by BIP350, exported)
	// regroups 8-bit bytes into 5-bit values.
	converted, err := bech32.ConvertBits(hash, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("address: ConvertBits failed: %w", err)
	}
	// Prepend the witness version byte (already a valid 5-bit value, 0-16).
	payload := append([]byte{WitnessVersion}, converted...)
	addr, err := encodeGeneric(HRP, payload, constantForWitnessVersion(WitnessVersion))
	if err != nil {
		return "", fmt.Errorf("address: bech32m encode failed: %w", err)
	}
	return addr, nil
}

// decode decodes a QOGE P2QPK address and returns the 32-byte HASH256
// program.
//
// Validation performed, in order:
//  1. bech32/bech32m structural decode + checksum (bech32m.go)
//  2. HRP must be "bq"
//  3. BIP350 binding rule: the checksum constant used must match the
//     witness version found in the payload (witver 0 -> Bech32,
//     witver>=1 -> Bech32m). A mismatch is rejected outright — this is
//     BIP350's defence against cross-version checksum confusion.
//  4. witver == 1 (Taproot) is explicitly rejected (ErrTaprootDetected).
//  5. witver must equal WitnessVersion (2) — any other version (0, 3-16)
//     is not a QOGE P2QPK address.
//  6. The remaining payload, converted back to 8-bit bytes, must be
//     exactly AddressLength (32) bytes.
func decode(addr string) ([]byte, error) {
	hrp, payload, constant, err := decodeGeneric(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	if hrp != HRP {
		return nil, fmt.Errorf("%w: got %q", ErrWrongHRP, hrp)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("%w: empty payload", ErrInvalidAddress)
	}

	witver := int(payload[0])

	// BIP350 binding rule.
	if constant != constantForWitnessVersion(witver) {
		return nil, fmt.Errorf("%w: checksum encoding does not match witness version %d (BIP350)",
			ErrInvalidAddress, witver)
	}

	if witver == 1 {
		return nil, ErrTaprootDetected
	}
	if witver != WitnessVersion {
		return nil, fmt.Errorf("%w: unexpected witness version %d (want %d)",
			ErrInvalidAddress, witver, WitnessVersion)
	}

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
