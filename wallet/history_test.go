package wallet

import (
	"testing"
	"time"
)

func TestOutgoingTransactionHistoryPersistsExactRecord(t *testing.T) {
	w := newTestWallet(t)
	recordedAt := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	out := OutgoingTransaction{TxID: "outgoing-txid", SourceAddress: "source", Destination: "destination", DestinationType: "P2WPKH", AmountSats: 250_000_000, FeeSats: 10_000, BroadcastAt: recordedAt}
	if err := w.RecordOutgoingTransaction(out); err != nil {
		t.Fatal(err)
	}
	records, err := w.ListTransactions()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("history length = %d, want 1", len(records))
	}
	got := records[0]
	if got.Direction != TransactionOutgoing || got.TxID != out.TxID || got.SourceAddress != out.SourceAddress || got.Destination != out.Destination || got.DestinationType != out.DestinationType || got.AmountSats != out.AmountSats || got.FeeSats != out.FeeSats || !got.RecordedAt.Equal(recordedAt) {
		t.Fatalf("outgoing record = %+v, want %+v", got, out)
	}
}

func TestExternalFundingCreatesOneIncomingRecord(t *testing.T) {
	w := newTestWallet(t)
	addr := testFreshAddresses(t, w, 1)[0]
	recordedAt := time.Date(2026, 9, 4, 13, 0, 0, 0, time.UTC)
	changed, err := w.ObserveFundingWithHistory(addr, 75_000_000, FundingMinConfirmations, []IncomingDeposit{{TxID: "deposit-txid", AmountSats: 75_000_000}}, recordedAt)
	if err != nil || !changed {
		t.Fatalf("ObserveFundingWithHistory = %v, %v; want true, nil", changed, err)
	}
	records, err := w.ListTransactions()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Direction != TransactionIncoming || records[0].TxID != "deposit-txid" || records[0].Destination != addr || records[0].AmountSats != 75_000_000 || !records[0].RecordedAt.Equal(recordedAt) {
		t.Fatalf("incoming history = %+v", records)
	}
}

func TestReservedChangeFundingCreatesNoIncomingRecord(t *testing.T) {
	w := newTestWallet(t)
	addrs := testFreshAddresses(t, w, 2)
	if err := testFundAddress(w, addrs[0]); err != nil {
		t.Fatal(err)
	}
	if err := w.index.MarkSpendPendingAndReserveChange(addrs[0], addrs[1], "spend-txid"); err != nil {
		t.Fatal(err)
	}
	changed, err := w.ObserveFundingWithHistory(addrs[1], 25_000_000, FundingMinConfirmations, []IncomingDeposit{{TxID: "spend-txid", AmountSats: 1}}, time.Now())
	if err != nil || !changed {
		t.Fatalf("reserved ObserveFundingWithHistory = %v, %v", changed, err)
	}
	records, err := w.ListTransactions()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("reserved change created incoming history: %+v", records)
	}
}

func TestTransactionHistoryIsScopedPerWalletDatabase(t *testing.T) {
	w1 := newTestWallet(t)
	w2 := newTestWallet(t)
	if err := w1.RecordOutgoingTransaction(OutgoingTransaction{TxID: "wallet-one", SourceAddress: "source", Destination: "destination", DestinationType: "P2QPK", AmountSats: 1, FeeSats: 0, BroadcastAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	records, err := w2.ListTransactions()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("second wallet saw first wallet history: %+v", records)
	}
}
