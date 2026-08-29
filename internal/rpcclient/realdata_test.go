package rpcclient

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/saogen/qoge-sphincs-wallet/address"
)

// TestAggregateBalances_RealMainnetResponse verifies the aggregation logic
// against the exact JSON the production mainnet node returned for
// bq1z9zuhmnlat45jk8y3p4sxaptz0k082nsy82z2aa5f3k9u9campa7qzpy9hg (22 QOGE).
func TestAggregateBalances_RealMainnetResponse(t *testing.T) {
	const addr = "bq1z9zuhmnlat45jk8y3p4sxaptz0k082nsy82z2aa5f3k9u9campa7qzpy9hg"
	const rawJSON = `{"success":true,"txouts":987037,"height":2466760,"bestblock":"b97fa6ab64e6c141b93e8d5b82cb18510f8d1b98cf331c00240835a2fd020907","unspents":[{"txid":"ba436f3ee58cbbc80b536af13a37d949de42008bec20cd8c35004f09be9e7dcb","vout":0,"scriptPubKey":"522028b97dcffd5d692b1c910d606e85627d9e754e043a84aef6898d8bc2e3bb0f7c","desc":"addr(bq1z9zuhmnlat45jk8y3p4sxaptz0k082nsy82z2aa5f3k9u9campa7qzpy9hg)#3srgxvmd","amount":22.00000000,"height":2466717}],"total_amount":22.00000000}`

	var result ScanResult
	if err := json.Unmarshal([]byte(rawJSON), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	balances, err := AggregateBalances(result, []string{addr})
	if err != nil {
		t.Fatalf("AggregateBalances: %v", err)
	}

	const wantSats = int64(2_200_000_000)
	if got := balances[addr]; got != wantSats {
		t.Fatalf("balance = %d satoshis, want %d (22 QOGE)", got, wantSats)
	}
	t.Logf("balance: %s QOGE (%d satoshis) — PASS", FormatQOGE(balances[addr]), balances[addr])

	// Confirm derived script matches node-returned scriptPubKey exactly.
	script, err := P2QPKScript(addr)
	if err != nil {
		t.Fatalf("P2QPKScript: %v", err)
	}
	hash, _ := address.ToHash(addr)
	t.Logf("witness program (ToHash): %x", hash)
	t.Logf("derived script:           %x", script)
	t.Logf("node scriptPubKey:        %s", result.Unspents[0].ScriptPubKey)

	got := fmt.Sprintf("%x", script)
	want := result.Unspents[0].ScriptPubKey
	if got != want {
		t.Fatalf("script mismatch:\n  derived: %s\n  node:    %s", got, want)
	}
	t.Log("scriptPubKey derived == scriptPubKey from node — PASS")
}
