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
	SLHDSASigLen       = 17088 // exact SLH-DSA-SHA2-128f signature length (FIPS 205)
	SLHDSAPKLen        = 32    // exact SLH-DSA-SHA2-128f public key length
	DefaultFeeRateQOGE = "0.0001"
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

// P2QPKFeePlan is the final fee/change result for a transaction shape.
type P2QPKFeePlan struct {
	FeeSats       int64
	ChangeSats    int64
	VSize         int64
	IncludeChange bool
}

// P2QPKWitness is the witness stack for one P2QPK input.
// Witness stack layout (BIP144 order, bottom to top):
//   - witness[0] = Sig    (17088 bytes SLH-DSA signature, popped second by interpreter)
//   - witness[1] = PubKey (32 bytes SLH-DSA public key,  popped first  by interpreter)
//
// This matches the qogecoind interpreter (interpreter.cpp VerifyWitnessProgram):
//
//	pubkey = SpanPopBack(stack) // top  = witness[1]
//	sig    = SpanPopBack(stack) // next = witness[0]
type P2QPKWitness struct {
	Sig    []byte
	PubKey []byte
}

// SignedP2QPKTx is a fully-signed P2QPK transaction. Witnesses is parallel
// with Inputs and must contain exactly one P2QPK witness per input.
type SignedP2QPKTx struct {
	NVersion  int32
	NLockTime uint32
	Inputs    []TxInput
	Outputs   []TxOutput
	Witnesses []P2QPKWitness
}

// SerializeBIP144 encodes tx in Bitcoin BIP144 extended serialization format:
//
//	nVersion | 0x00 0x01 | vin | vout | witness-per-input | nLockTime
//
// Returns an error unless every input has a correctly-sized witness.
func SerializeBIP144(tx SignedP2QPKTx) ([]byte, error) {
	if len(tx.Inputs) == 0 {
		return nil, fmt.Errorf("txbuilder: SerializeBIP144: no inputs")
	}
	if len(tx.Outputs) == 0 {
		return nil, fmt.Errorf("txbuilder: SerializeBIP144: no outputs")
	}
	if len(tx.Witnesses) != len(tx.Inputs) {
		return nil, fmt.Errorf("txbuilder: SerializeBIP144: witnesses len %d, want inputs len %d", len(tx.Witnesses), len(tx.Inputs))
	}
	for i, witness := range tx.Witnesses {
		if len(witness.Sig) != SLHDSASigLen {
			return nil, fmt.Errorf("txbuilder: SerializeBIP144: witness %d sig length %d, want %d", i, len(witness.Sig), SLHDSASigLen)
		}
		if len(witness.PubKey) != SLHDSAPKLen {
			return nil, fmt.Errorf("txbuilder: SerializeBIP144: witness %d pubkey length %d, want %d", i, len(witness.PubKey), SLHDSAPKLen)
		}
	}
	for i, output := range tx.Outputs {
		if output.Amount < 0 {
			return nil, fmt.Errorf("txbuilder: SerializeBIP144: output %d amount is negative", i)
		}
	}

	var buf bytes.Buffer

	writeLE32(&buf, uint32(tx.NVersion)) // nVersion (int32 LE)
	buf.Write([]byte{0x00, 0x01})        // BIP144 marker + flag

	// Inputs
	writeCompact(&buf, uint64(len(tx.Inputs)))
	for _, in := range tx.Inputs {
		buf.Write(in.TxIDLE[:])  // txid wire order (32 bytes)
		writeLE32(&buf, in.Vout) // vout (4 bytes LE)
		writeCompact(&buf, 0)    // scriptSig: empty (segwit spends have no scriptSig)
		writeLE32(&buf, in.NSequence)
	}

	// Outputs
	writeCompact(&buf, uint64(len(tx.Outputs)))
	for _, out := range tx.Outputs {
		writeLE64(&buf, uint64(out.Amount))
		writeCompact(&buf, uint64(len(out.Script)))
		buf.Write(out.Script)
	}

	// Witnesses, exactly parallel with inputs.
	for _, witness := range tx.Witnesses {
		writeCompact(&buf, 2)
		writeCompact(&buf, uint64(len(witness.Sig)))
		buf.Write(witness.Sig)
		writeCompact(&buf, uint64(len(witness.PubKey)))
		buf.Write(witness.PubKey)
	}

	writeLE32(&buf, tx.NLockTime)

	return buf.Bytes(), nil
}

// P2QPKVirtualSize returns the exact vsize of a final transaction shape. P2QPK
// signatures and public keys have fixed lengths, so no signature bytes are
// needed to calculate the final BIP141 weight.
func P2QPKVirtualSize(inputCount int, outputs []TxOutput) (int64, error) {
	if inputCount <= 0 {
		return 0, fmt.Errorf("txbuilder: P2QPKVirtualSize: input count must be positive")
	}
	if len(outputs) == 0 {
		return 0, fmt.Errorf("txbuilder: P2QPKVirtualSize: no outputs")
	}
	stripped := int64(4 + compactSizeLen(uint64(inputCount)) + inputCount*41 + compactSizeLen(uint64(len(outputs))) + 4)
	for _, output := range outputs {
		if output.Amount < 0 {
			return 0, fmt.Errorf("txbuilder: P2QPKVirtualSize: negative output amount")
		}
		stripped += int64(8 + compactSizeLen(uint64(len(output.Script))) + len(output.Script))
	}
	witnessPerInput := 1 + compactSizeLen(SLHDSASigLen) + SLHDSASigLen + compactSizeLen(SLHDSAPKLen) + SLHDSAPKLen
	witness := int64(2 + inputCount*witnessPerInput) // marker+flag plus every input witness
	weight := stripped*4 + witness
	return (weight + 3) / 4, nil
}

// FeeForRate calculates Core-compatible fees: ceil(rate_sats_per_kB*vsize/1000).
func FeeForRate(rateSatsPerKB, vsize int64) (int64, error) {
	if rateSatsPerKB <= 0 {
		return 0, fmt.Errorf("txbuilder: fee rate must be positive")
	}
	if vsize <= 0 {
		return 0, fmt.Errorf("txbuilder: vsize must be positive")
	}
	if rateSatsPerKB > (math.MaxInt64-999)/vsize {
		return 0, fmt.Errorf("txbuilder: fee calculation overflows int64")
	}
	return (rateSatsPerKB*vsize + 999) / 1000, nil
}

// ParseFeeRate parses a positive QOGE/kB fee rate using exact satoshi units.
func ParseFeeRate(value string) (int64, error) {
	if strings.HasPrefix(strings.TrimSpace(value), "-") {
		return 0, fmt.Errorf("txbuilder: fee rate must be positive")
	}
	rate, err := QOGEToSatoshis(value)
	if err != nil {
		return 0, fmt.Errorf("txbuilder: invalid fee rate: %w", err)
	}
	if rate <= 0 {
		return 0, fmt.Errorf("txbuilder: fee rate must be positive")
	}
	return rate, nil
}

// PlanP2QPKFee computes a fee against the actual final vsize. Change outputs
// are always 34-byte wallet-owned P2QPK scripts. If the remainder cannot fund
// a change-bearing transaction but can fund the one-output shape, it becomes
// the actual fee rather than creating an underfunded or zero-valued output.
func PlanP2QPKFee(totalInputSats, sendSats, rateSatsPerKB int64, inputCount int, destinationScript []byte) (P2QPKFeePlan, error) {
	if totalInputSats <= 0 {
		return P2QPKFeePlan{}, fmt.Errorf("txbuilder: total input must be positive")
	}
	if sendSats <= 0 || sendSats > totalInputSats {
		return P2QPKFeePlan{}, fmt.Errorf("txbuilder: send amount %d is not covered by total input %d", sendSats, totalInputSats)
	}
	if len(destinationScript) == 0 {
		return P2QPKFeePlan{}, fmt.Errorf("txbuilder: destination script is empty")
	}
	noChangeOutputs := []TxOutput{{Amount: sendSats, Script: destinationScript}}
	noChangeVSize, err := P2QPKVirtualSize(inputCount, noChangeOutputs)
	if err != nil {
		return P2QPKFeePlan{}, err
	}
	noChangeMinimum, err := FeeForRate(rateSatsPerKB, noChangeVSize)
	if err != nil {
		return P2QPKFeePlan{}, err
	}
	remainder := totalInputSats - sendSats
	if remainder < noChangeMinimum {
		return P2QPKFeePlan{}, fmt.Errorf("txbuilder: insufficient funds: total input %d, send %d, minimum fee %d", totalInputSats, sendSats, noChangeMinimum)
	}

	changeOutputs := append(noChangeOutputs, TxOutput{Script: make([]byte, 34)})
	changeVSize, err := P2QPKVirtualSize(inputCount, changeOutputs)
	if err != nil {
		return P2QPKFeePlan{}, err
	}
	changeFee, err := FeeForRate(rateSatsPerKB, changeVSize)
	if err != nil {
		return P2QPKFeePlan{}, err
	}
	if remainder > changeFee {
		return P2QPKFeePlan{FeeSats: changeFee, ChangeSats: remainder - changeFee, VSize: changeVSize, IncludeChange: true}, nil
	}
	return P2QPKFeePlan{FeeSats: remainder, VSize: noChangeVSize}, nil
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
//
//	OP_2 (0x52) || PUSH32 (0x20) || 32-byte witness program (HASH256 of pubkey)
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

func compactSizeLen(n uint64) int {
	switch {
	case n < 0xfd:
		return 1
	case n <= 0xffff:
		return 3
	case n <= 0xffffffff:
		return 5
	default:
		return 9
	}
}
