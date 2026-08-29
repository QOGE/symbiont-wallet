package rpcclient

import (
	"encoding/hex"
	"fmt"

	"github.com/saogen/qoge-sphincs-wallet/address"
)

// SatoshisPerQOGE is 1e8 — the fixed integer scale for QOGE amounts.
// scantxoutset returns amounts as float64 QOGE; we convert to int64 satoshis
// by rounding to avoid floating-point drift at the boundary.
const SatoshisPerQOGE = int64(100_000_000)

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
			// UTXO does not correspond to any of the queried addresses.
			// This can occur if the node returns UTXOs from non-P2QPK scripts
			// matched by the same addr() descriptor fallback. Skip silently.
			continue
		}
		// Round to satoshis: multiply then round to nearest integer.
		satoshis := int64(u.Amount*float64(SatoshisPerQOGE) + 0.5)
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
