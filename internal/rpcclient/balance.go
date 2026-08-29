package rpcclient

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/saogen/qoge-sphincs-wallet/address"
)

// SatoshisPerQOGE is 1e8 — the fixed integer scale for QOGE amounts.
const SatoshisPerQOGE = int64(100_000_000)

// BalanceWarningThresholdSats is the single-address balance safety threshold
// expressed in satoshis: 5,000,000 QOGE. Chosen with a large safety margin
// below the float64 precision boundary (~67.1 million QOGE) in the RPC
// amount-conversion path. Balances strictly above this value trigger a
// concentration warning in the GUI.
const BalanceWarningThresholdSats = int64(5_000_000) * SatoshisPerQOGE

// ExceedsConcentrationThreshold reports whether satoshis strictly exceeds the
// single-address balance safety threshold (5,000,000 QOGE). Exactly
// 5,000,000 QOGE returns false; one satoshi above returns true.
func ExceedsConcentrationThreshold(satoshis int64) bool {
	return satoshis > BalanceWarningThresholdSats
}

// FloatQOGEToSatoshis converts a float64 QOGE amount (as returned by the
// scantxoutset RPC) to satoshis without float64 multiplication.
//
// It formats the value to exactly 8 decimal places via fmt.Sprintf("%.8f",
// amount) and then parses the result using integer arithmetic.  This avoids
// the class of error where float64 representation of a value like 1.005 QOGE
// produces 100499999.999… instead of 100500000, which the +0.5 rounding trick
// can silently mis-round in edge cases near 0.5 satoshi boundaries.
func FloatQOGEToSatoshis(amount float64) (int64, error) {
	return parseQOGEDecimal(fmt.Sprintf("%.8f", amount))
}

// parseQOGEDecimal parses a decimal QOGE string with exactly 8 fractional
// digits (the format produced by fmt.Sprintf("%.8f")) into satoshis using
// pure integer arithmetic.
func parseQOGEDecimal(s string) (int64, error) {
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 || len(parts[1]) != 8 {
		return 0, fmt.Errorf("rpcclient: parseQOGEDecimal: expected X.YYYYYYYY, got %q", s)
	}
	whole, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || whole < 0 {
		return 0, fmt.Errorf("rpcclient: parseQOGEDecimal: invalid integer part %q", parts[0])
	}
	// Overflow check: whole * 100_000_000 must fit in int64.
	// math.MaxInt64 (9223372036854775807) / 100_000_000 = 92_233_720_368 (floor).
	if whole > 92_233_720_368 {
		return 0, fmt.Errorf("rpcclient: parseQOGEDecimal: amount too large (%d QOGE)", whole)
	}
	frac, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || frac < 0 {
		return 0, fmt.Errorf("rpcclient: parseQOGEDecimal: invalid fractional part %q", parts[1])
	}
	return whole*SatoshisPerQOGE + frac, nil
}

// P2QPKScript returns the 34-byte P2QPK scriptPubKey for a bq1z address:
//
//	OP_2 (0x52) || PUSH32 (0x20) || <32-byte witness program>
//
// This is the exact script that ends up in the UTXO set when a P2QPK output
// is created for addr. We use it to reverse-map scantxoutset's scriptPubKey
// field back to the originating address, because the "desc" field returned
// by qogecoind's InferDescriptor for a witness-v2 script is "raw(...)", not
// "addr(...)", and cannot be reliably parsed back to the address string.
func P2QPKScript(addr string) ([]byte, error) {
	hash, err := address.ToHash(addr)
	if err != nil {
		return nil, fmt.Errorf("rpcclient: P2QPKScript: decode address %q: %w", addr, err)
	}
	script := make([]byte, 34)
	script[0] = 0x52 // OP_2 (witness version 2)
	script[1] = 0x20 // PUSH 32 bytes
	copy(script[2:], hash)
	return script, nil
}

// AggregateBalances maps a scantxoutset result back to per-address satoshi
// balances. It builds a lookup from hex(P2QPKScript) → address string, then
// sums each UTXO's amount into its matching address.
//
// Addresses present in addrs but with no matching UTXO in result are included
// in the returned map with a zero balance. This ensures callers always get a
// complete result for every address they asked about.
//
// The returned map has one entry per element of addrs (no duplicates, even if
// addrs itself contains duplicates — the last entry wins, consistent with how
// addresses are unique in the wallet).
//
// amount is converted from float64 QOGE → int64 satoshis using round-to-nearest
// to avoid floating-point drift at QOGE boundary values (e.g. 1.0 QOGE
// occasionally returns as 0.99999999... in float64 arithmetic).
func AggregateBalances(result ScanResult, addrs []string) (map[string]int64, error) {
	// Build scriptPubKey → address lookup.
	scriptToAddr := make(map[string]string, len(addrs))
	balances := make(map[string]int64, len(addrs))

	for _, addr := range addrs {
		script, err := P2QPKScript(addr)
		if err != nil {
			return nil, err
		}
		scriptHex := hex.EncodeToString(script)
		scriptToAddr[scriptHex] = addr
		balances[addr] = 0 // initialize so every input address has an entry
	}

	for _, u := range result.Unspents {
		addr, ok := scriptToAddr[u.ScriptPubKey]
		if !ok {
			continue
		}
		satoshis, err := FloatQOGEToSatoshis(u.Amount)
		if err != nil {
			return nil, fmt.Errorf("rpcclient: AggregateBalances: %w", err)
		}
		balances[addr] += satoshis
	}

	return balances, nil
}

// FormatQOGE formats an int64 satoshi amount as a QOGE decimal string with
// exactly 8 decimal places, e.g. 220000000 → "2.20000000".
func FormatQOGE(satoshis int64) string {
	whole := satoshis / SatoshisPerQOGE
	frac := satoshis % SatoshisPerQOGE
	return fmt.Sprintf("%d.%08d", whole, frac)
}
