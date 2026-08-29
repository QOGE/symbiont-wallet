// Package txbuilder serializes signed P2QPK transactions in BIP144 extended
// witness format for submission to qogecoind via sendrawtransaction.
//
// It is a pure-Go package with no CGo dependency — safe to use in tests
// without a liboqs install.
package txbuilder

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/saogen/qoge-sphincs-wallet/address"
)

const (
	SLHDSASigLen = 17088 // exact SLH-DSA-SHA2-128f signature length (FIPS 205)
	SLHDSAPKLen  = 32    // exact SLH-DSA-SHA2-128f public key length
	FixedFeeSats = int64(10_000) // 0.0001 QOGE — project-standard reference fee
)

// TxInput is one input in a raw P2QPK transaction.
type TxInput struct {
	TxIDLE    [32]byte // txid in wire byte order (reversed from RPC display hex)
	Vout      uint32
	NSequence uint32
}

// TxOutput is one output in a raw P2QPK transaction.
type TxOutput struct {
	Amount int64  // satoshis
	Script []byte // scriptPubKey bytes
}

// SignedP2QPKTx is a fully-signed single-input P2QPK transaction.
// Witness stack layout (BIP144 order, bottom to top):
//   - witness[0] = Sig    (17088 bytes SLH-DSA signature, popped second by interpreter)
//   - witness[1] = PubKey (32 bytes SLH-DSA public key,  popped first  by interpreter)
//
// This matches the qogecoind interpreter (interpreter.cpp VerifyWitnessProgram):
//   pubkey = SpanPopBack(stack) // top  = witness[1]
//   sig    = SpanPopBack(stack) // next = witness[0]
type SignedP2QPKTx struct {
	NVersion  int32
	NLockTime uint32
	Inputs    []TxInput
	Outputs   []TxOutput
	Sig       []byte // SLH-DSA signature: exactly SLHDSASigLen bytes
	PubKey    []byte // SLH-DSA public key: exactly SLHDSAPKLen bytes
}

// SerializeBIP144 encodes tx in Bitcoin BIP144 extended serialization format:
//   nVersion | 0x00 0x01 | vin | vout | witness-per-input | nLockTime
//
// All inputs beyond index 0 are given empty witness stacks.
// Returns an error if the signature or public key lengths are wrong.
func SerializeBIP144(tx SignedP2QPKTx) ([]byte, error) {
	if len(tx.Inputs) == 0 {
		return nil, fmt.Errorf("txbuilder: SerializeBIP144: no inputs")
	}
	if len(tx.Outputs) == 0 {
		return nil, fmt.Errorf("txbuilder: SerializeBIP144: no outputs")
	}
	if len(tx.Sig) != SLHDSASigLen {
		return nil, fmt.Errorf("txbuilder: SerializeBIP144: sig length %d, want %d", len(tx.Sig), SLHDSASigLen)
	}
	if len(tx.PubKey) != SLHDSAPKLen {
		return nil, fmt.Errorf("txbuilder: SerializeBIP144: pubkey length %d, want %d", len(tx.PubKey), SLHDSAPKLen)
	}

	var buf bytes.Buffer

	writeLE32(&buf, uint32(tx.NVersion)) // nVersion (int32 LE)
	buf.Write([]byte{0x00, 0x01})        // BIP144 marker + flag

	// Inputs
	writeCompact(&buf, uint64(len(tx.Inputs)))
	for _, in := range tx.Inputs {
		buf.Write(in.TxIDLE[:])      // txid wire order (32 bytes)
		writeLE32(&buf, in.Vout)     // vout (4 bytes LE)
		writeCompact(&buf, 0)        // scriptSig: empty (segwit spends have no scriptSig)
		writeLE32(&buf, in.NSequence)
	}

	// Outputs
	writeCompact(&buf, uint64(len(tx.Outputs)))
	for _, out := range tx.Outputs {
		writeLE64(&buf, uint64(out.Amount))
		writeCompact(&buf, uint64(len(out.Script)))
		buf.Write(out.Script)
	}

	// Witness (parallel with inputs; non-zero only for input 0)
	for i := range tx.Inputs {
		if i == 0 {
			writeCompact(&buf, 2) // 2 witness items
			writeCompact(&buf, uint64(len(tx.Sig)))
			buf.Write(tx.Sig)
			writeCompact(&buf, uint64(len(tx.PubKey)))
			buf.Write(tx.PubKey)
		} else {
			writeCompact(&buf, 0) // 0 items — empty witness
		}
	}

	writeLE32(&buf, tx.NLockTime)

	return buf.Bytes(), nil
}

// TxIDLEFromHex converts a txid from RPC display format (64 hex chars,
// bytes reversed from wire) to wire byte order (little-endian, as stored
// in the raw transaction). The [32]byte result can be used directly as
// TxInput.TxIDLE.
func TxIDLEFromHex(txidHex string) ([32]byte, error) {
	b, err := hex.DecodeString(txidHex)
	if err != nil {
		return [32]byte{}, fmt.Errorf("txbuilder: TxIDLEFromHex: %w", err)
	}
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("txbuilder: TxIDLEFromHex: expected 32 bytes, got %d", len(b))
	}
	var le [32]byte
	for i, v := range b {
		le[31-i] = v
	}
	return le, nil
}

// P2QPKScript returns the 34-byte scriptPubKey for a bq1z P2QPK address:
//   OP_2 (0x52) || PUSH32 (0x20) || 32-byte witness program (HASH256 of pubkey)
func P2QPKScript(addr string) ([]byte, error) {
	hash, err := address.ToHash(addr)
	if err != nil {
		return nil, fmt.Errorf("txbuilder: P2QPKScript: %w", err)
	}
	s := make([]byte, 34)
	s[0] = 0x52 // OP_2 (witness version 2)
	s[1] = 0x20 // PUSH 32 bytes
	copy(s[2:], hash)
	return s, nil
}

// QOGEToSatoshis parses a user-entered QOGE amount string ("1", "1.5",
// "0.0001") into satoshis using integer arithmetic to avoid float drift.
// Accepts up to 8 decimal places. Returns an error on invalid input.
func QOGEToSatoshis(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("txbuilder: empty amount")
	}
	parts := strings.SplitN(s, ".", 2)
	if parts[0] == "" {
		parts[0] = "0"
	}
	whole, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || whole < 0 {
		return 0, fmt.Errorf("txbuilder: invalid amount %q", s)
	}
	// Overflow check before multiplying: whole * 100_000_000 must fit in int64.
	// math.MaxInt64 (9223372036854775807) / 100_000_000 = 92_233_720_368 (floor).
	if whole > math.MaxInt64/100_000_000 {
		return 0, fmt.Errorf("txbuilder: amount %q exceeds maximum representable satoshis", s)
	}
	sats := whole * 100_000_000

	if len(parts) == 2 {
		frac := parts[1]
		if len(frac) > 8 {
			return 0, fmt.Errorf("txbuilder: too many decimal places in %q (max 8)", s)
		}
		for len(frac) < 8 {
			frac += "0"
		}
		fracVal, err := strconv.ParseInt(frac, 10, 64)
		if err != nil || fracVal < 0 {
			return 0, fmt.Errorf("txbuilder: invalid fractional part in %q", s)
		}
		// Overflow check before adding frac: sats + fracVal must fit in int64.
		// Since whole <= 92233720 and sats = whole*1e8 <= 9223372000000000,
		// and fracVal <= 99999999, the sum <= 9223372099999999 < math.MaxInt64.
		// So this addition cannot overflow given the whole check above.
		sats += fracVal
	}
	return sats, nil
}

// CalcChange returns the change amount in satoshis, or an error if the UTXO
// does not cover sendSats + feeSats (insufficient funds). Returns 0 when the
// UTXO exactly covers send + fee; the caller must handle the zero-change case
// by building a single-output transaction (no change output, no change address
// consumed) rather than adding a zero-value change output.
func CalcChange(utxoSats, sendSats, feeSats int64) (int64, error) {
	if sendSats <= 0 {
		return 0, fmt.Errorf("txbuilder: send amount must be positive, got %d", sendSats)
	}
	if feeSats < 0 {
		return 0, fmt.Errorf("txbuilder: fee must be non-negative, got %d", feeSats)
	}
	// Overflow check: sendSats + feeSats must not wrap.
	if feeSats > math.MaxInt64-sendSats {
		return 0, fmt.Errorf("txbuilder: send %d + fee %d overflows int64", sendSats, feeSats)
	}
	change := utxoSats - sendSats - feeSats
	if change < 0 {
		return 0, fmt.Errorf("txbuilder: insufficient funds: utxo %d sat, need %d sat (send %d + fee %d)",
			utxoSats, sendSats+feeSats, sendSats, feeSats)
	}
	return change, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func writeLE32(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

func writeLE64(buf *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	buf.Write(b[:])
}

// writeCompact writes a Bitcoin compact-size (variable-length) integer.
func writeCompact(buf *bytes.Buffer, n uint64) {
	var b [9]byte
	switch {
	case n < 0xfd:
		b[0] = byte(n)
		buf.Write(b[:1])
	case n <= 0xffff:
		b[0] = 0xfd
		binary.LittleEndian.PutUint16(b[1:], uint16(n))
		buf.Write(b[:3])
	case n <= 0xffffffff:
		b[0] = 0xfe
		binary.LittleEndian.PutUint32(b[1:], uint32(n))
		buf.Write(b[:5])
	default:
		b[0] = 0xff
		binary.LittleEndian.PutUint64(b[1:], n)
		buf.Write(b[:9])
	}
}
