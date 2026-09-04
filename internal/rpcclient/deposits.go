package rpcclient

import (
	"encoding/hex"
	"fmt"
)

type Deposit struct {
	TxID       string
	AmountSats int64
}

// AnalyzeDeposits groups current UTXOs by wallet address and source txid.
func AnalyzeDeposits(result ScanResult, addrs []string) (map[string][]Deposit, error) {
	scriptToAddr := make(map[string]string, len(addrs))
	grouped := make(map[string]map[string]int64, len(addrs))
	for _, addr := range addrs {
		script, err := P2QPKScript(addr)
		if err != nil {
			return nil, err
		}
		scriptToAddr[hex.EncodeToString(script)] = addr
		grouped[addr] = make(map[string]int64)
	}
	for _, unspent := range result.Unspents {
		addr, ok := scriptToAddr[unspent.ScriptPubKey]
		if !ok {
			continue
		}
		if unspent.Txid == "" {
			return nil, fmt.Errorf("rpcclient: AnalyzeDeposits: unspent has empty txid")
		}
		sats, err := FloatQOGEToSatoshis(unspent.Amount)
		if err != nil {
			return nil, fmt.Errorf("rpcclient: AnalyzeDeposits: %w", err)
		}
		grouped[addr][unspent.Txid] += sats
	}
	resultByAddr := make(map[string][]Deposit, len(addrs))
	for _, addr := range addrs {
		for txid, sats := range grouped[addr] {
			resultByAddr[addr] = append(resultByAddr[addr], Deposit{TxID: txid, AmountSats: sats})
		}
	}
	return resultByAddr, nil
}
