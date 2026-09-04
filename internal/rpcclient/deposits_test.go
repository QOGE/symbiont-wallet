package rpcclient

import "testing"

func TestAnalyzeDepositsGroupsOutputsByAddressAndTxID(t *testing.T) {
	addr := makeTestAddr(t, 91)
	script := makeScript(t, addr)
	result := ScanResult{Unspents: []ScanUnspent{
		{Txid: "tx-a", Vout: 0, ScriptPubKey: script, Amount: 1.25},
		{Txid: "tx-a", Vout: 1, ScriptPubKey: script, Amount: 0.75},
		{Txid: "tx-b", Vout: 0, ScriptPubKey: script, Amount: 3},
	}}
	deposits, err := AnalyzeDeposits(result, []string{addr})
	if err != nil {
		t.Fatal(err)
	}
	if len(deposits[addr]) != 2 {
		t.Fatalf("deposit count = %d, want 2: %+v", len(deposits[addr]), deposits[addr])
	}
	amounts := make(map[string]int64)
	for _, deposit := range deposits[addr] {
		amounts[deposit.TxID] = deposit.AmountSats
	}
	if amounts["tx-a"] != 2*SatoshisPerQOGE || amounts["tx-b"] != 3*SatoshisPerQOGE {
		t.Fatalf("grouped deposits = %+v", amounts)
	}
}
