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
// Taproot (P2TR / witver=1) addresses are explicitly rejected by decode(),
// which is the wallet-owned P2QPK decoder. DecodeMainnetDestination accepts
// P2TR only as an output destination; it does not make Taproot wallet-owned.
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
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/bech32"
)

// HRP is the human-readable part for QOGE Bech32m mainnet addresses.
// All mainnet QOGE addresses start with "bq1". Confirmed against qogecoin/qogecoin
// release notes ("Bech32 addresses have a bq prefix") — see SIP-QOGE-PQC-01
// HRP correction.
const HRP = "bq"

// Network identifies which Qogecoin network an address belongs to.
type Network uint8

const (
	Mainnet Network = iota // bq1z...
	Testnet                // bqt1z...
	Regtest                // bq1z... (same as mainnet for now; bqrt future consideration)
)

// HRP returns the bech32m human-readable part for the network.
func (n Network) HRP() string {
	switch n {
	case Testnet:
		return "bqt"
	default: // Mainnet and Regtest both use "bq"
		return "bq"
	}
}

// DefaultNetwork is the network used by FromPublicKey and ToHash when no
// explicit network is provided. Defaults to Mainnet.
var DefaultNetwork = Mainnet

// knownHRPs maps every recognised QOGE HRP to its Network.
var knownHRPs = map[string]Network{
	"bq":  Mainnet,
	"bqt": Testnet,
}

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

// FromPublicKey derives a QOGE P2QPK address from a 32-byte SLH-DSA public key
// using DefaultNetwork (Mainnet unless overridden).
func FromPublicKey(pubKey []byte) (string, error) {
	return FromPublicKeyOnNetwork(pubKey, DefaultNetwork)
}

// FromPublicKeyOnNetwork derives a QOGE P2QPK address for the given network.
func FromPublicKeyOnNetwork(pubKey []byte, net Network) (string, error) {
	if len(pubKey) != 32 {
		return "", ErrInvalidPublicKeyLength
	}
	hash := hash256(pubKey)
	return encode(hash, net)
}

// ToHash decodes a QOGE address string and returns the 32-byte HASH256
// program. Accepts any known QOGE network HRP ("bq", "bqt").
// Use ParseAddress to also retrieve which network the address belongs to.
func ToHash(addr string) ([]byte, error) {
	hash, _, err := decode(addr)
	return hash, err
}

// ParseAddress decodes a QOGE address and returns the 32-byte HASH256 program
// and the network the address belongs to.
func ParseAddress(addr string) ([]byte, Network, error) {
	return decode(addr)
}

// DecodeForNetwork decodes addr and returns an error if it does not belong to
// the expected network. Use this to enforce network separation at API
// boundaries (e.g. reject a bqt1z... testnet address where bq1z... is expected).
func DecodeForNetwork(addr string, net Network) ([]byte, error) {
	hash, got, err := decode(addr)
	if err != nil {
		return nil, err
	}
	if got != net {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrWrongHRP, got.HRP(), net.HRP())
	}
	return hash, nil
}

// ValidateAddress checks that addr is a well-formed QOGE P2QPK address on any
// known network. Returns nil if valid, a descriptive error otherwise.
func ValidateAddress(addr string) error {
	_, _, err := decode(addr)
	return err
}

const (
	MainnetPubKeyHashPrefix byte = 120
	MainnetScriptHashPrefix byte = 102
)

// DestinationType identifies the locking-script form encoded by an address.
type DestinationType string

const (
	DestinationP2PKH  DestinationType = "Legacy P2PKH"
	DestinationP2SH   DestinationType = "Legacy P2SH"
	DestinationP2WPKH DestinationType = "P2WPKH"
	DestinationP2WSH  DestinationType = "P2WSH"
	DestinationP2TR   DestinationType = "P2TR"
	DestinationP2QPK  DestinationType = "P2QPK"
)

// Destination is a strictly validated Qogecoin mainnet destination and its
// canonical scriptPubKey.
type Destination struct {
	Type         DestinationType
	ScriptPubKey []byte
}

// DecodeMainnetDestination validates a Qogecoin mainnet address and constructs
// its canonical scriptPubKey. It accepts legacy Base58Check and defined SegWit
// destination forms, including this wallet's witness-v2 P2QPK format.
func DecodeMainnetDestination(addr string) (Destination, error) {
	if addr == "" || strings.TrimSpace(addr) != addr {
		return Destination{}, fmt.Errorf("%w: empty address or surrounding whitespace", ErrInvalidAddress)
	}

	payload, version, baseErr := base58.CheckDecode(addr)
	if baseErr == nil {
		if len(payload) != 20 {
			return Destination{}, fmt.Errorf("%w: legacy payload length %d (want 20)", ErrInvalidAddress, len(payload))
		}
		switch version {
		case MainnetPubKeyHashPrefix:
			script := append([]byte{0x76, 0xa9, 0x14}, payload...)
			script = append(script, 0x88, 0xac)
			return Destination{Type: DestinationP2PKH, ScriptPubKey: script}, nil
		case MainnetScriptHashPrefix:
			script := append([]byte{0xa9, 0x14}, payload...)
			script = append(script, 0x87)
			return Destination{Type: DestinationP2SH, ScriptPubKey: script}, nil
		default:
			return Destination{}, fmt.Errorf("%w: legacy version byte %d is not Qogecoin mainnet", ErrInvalidAddress, version)
		}
	}

	hrp, data, constant, err := decodeGeneric(addr)
	if err != nil {
		return Destination{}, fmt.Errorf("%w: Base58Check: %v; SegWit: %v", ErrInvalidAddress, baseErr, err)
	}
	if hrp != Mainnet.HRP() {
		return Destination{}, fmt.Errorf("%w: got %q, want %q", ErrWrongHRP, hrp, Mainnet.HRP())
	}
	if len(data) == 0 || data[0] > 16 {
		return Destination{}, fmt.Errorf("%w: invalid witness version", ErrInvalidAddress)
	}
	witver := int(data[0])
	if constant != constantForWitnessVersion(witver) {
		return Destination{}, fmt.Errorf("%w: checksum encoding does not match witness version %d (BIP350)", ErrInvalidAddress, witver)
	}
	program, err := bech32.ConvertBits(data[1:], 5, 8, false)
	if err != nil {
		return Destination{}, fmt.Errorf("%w: invalid witness program encoding: %v", ErrInvalidAddress, err)
	}
	if len(program) < 2 || len(program) > 40 {
		return Destination{}, fmt.Errorf("%w: witness program length %d outside 2..40", ErrInvalidAddress, len(program))
	}

	var typ DestinationType
	switch {
	case witver == 0 && len(program) == 20:
		typ = DestinationP2WPKH
	case witver == 0 && len(program) == 32:
		typ = DestinationP2WSH
	case witver == 1 && len(program) == 32:
		typ = DestinationP2TR
	case witver == WitnessVersion && len(program) == AddressLength:
		typ = DestinationP2QPK
	default:
		return Destination{}, fmt.Errorf("%w: unsupported witness version/program length %d/%d", ErrInvalidAddress, witver, len(program))
	}

	opcode := byte(0x00)
	if witver > 0 {
		opcode = byte(0x50 + witver)
	}
	script := make([]byte, 2+len(program))
	script[0] = opcode
	script[1] = byte(len(program))
	copy(script[2:], program)
	return Destination{Type: typ, ScriptPubKey: script}, nil
}

// MatchesPublicKey returns true if addr was derived from pubKey.
// Use this before signing to assert the address belongs to the held keypair.
func MatchesPublicKey(addr string, pubKey []byte) (bool, error) {
	if len(pubKey) != 32 {
		return false, ErrInvalidPublicKeyLength
	}
	decoded, _, err := decode(addr)
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

// encode converts a 32-byte HASH256 program to a Bech32m address using the
// HRP for net and witness version WitnessVersion (2).
func encode(hash []byte, net Network) (string, error) {
	// bech32.ConvertBits (from btcutil — unaffected by BIP350, exported)
	// regroups 8-bit bytes into 5-bit values.
	converted, err := bech32.ConvertBits(hash, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("address: ConvertBits failed: %w", err)
	}
	// Prepend the witness version byte (already a valid 5-bit value, 0-16).
	payload := append([]byte{WitnessVersion}, converted...)
	addr, err := encodeGeneric(net.HRP(), payload, constantForWitnessVersion(WitnessVersion))
	if err != nil {
		return "", fmt.Errorf("address: bech32m encode failed: %w", err)
	}
	return addr, nil
}

// decode decodes a QOGE P2QPK address and returns the 32-byte HASH256 program
// and the network inferred from the HRP.
//
// Validation performed, in order:
//  1. bech32/bech32m structural decode + checksum (bech32m.go)
//  2. HRP must be a known QOGE HRP ("bq" or "bqt"); unknown HRPs → ErrWrongHRP
//  3. BIP350 binding rule: the checksum constant used must match the
//     witness version found in the payload (witver 0 -> Bech32,
//     witver>=1 -> Bech32m). A mismatch is rejected outright — this is
//     BIP350's defence against cross-version checksum confusion.
//  4. witver == 1 (Taproot) is explicitly rejected (ErrTaprootDetected).
//  5. witver must equal WitnessVersion (2) — any other version (0, 3-16)
//     is not a QOGE P2QPK address.
//  6. The remaining payload, converted back to 8-bit bytes, must be
//     exactly AddressLength (32) bytes.
func decode(addr string) ([]byte, Network, error) {
	hrp, payload, constant, err := decodeGeneric(addr)
	if err != nil {
		return nil, Mainnet, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	net, ok := knownHRPs[hrp]
	if !ok {
		return nil, Mainnet, fmt.Errorf("%w: got %q", ErrWrongHRP, hrp)
	}
	if len(payload) == 0 {
		return nil, net, fmt.Errorf("%w: empty payload", ErrInvalidAddress)
	}

	witver := int(payload[0])

	// BIP350 binding rule.
	if constant != constantForWitnessVersion(witver) {
		return nil, net, fmt.Errorf("%w: checksum encoding does not match witness version %d (BIP350)",
			ErrInvalidAddress, witver)
	}

	if witver == 1 {
		return nil, net, ErrTaprootDetected
	}
	if witver != WitnessVersion {
		return nil, net, fmt.Errorf("%w: unexpected witness version %d (want %d)",
			ErrInvalidAddress, witver, WitnessVersion)
	}

	decoded, err := bech32.ConvertBits(payload[1:], 5, 8, false)
	if err != nil {
		return nil, net, fmt.Errorf("address: ConvertBits decode failed: %w", err)
	}
	if len(decoded) != AddressLength {
		return nil, net, fmt.Errorf("%w: decoded length %d (want %d)",
			ErrInvalidAddress, len(decoded), AddressLength)
	}
	return decoded, net, nil
}
