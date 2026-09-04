package wallet

import (
	"fmt"
	"time"

	"github.com/saogen/qoge-sphincs-wallet/keystore"
)

type TransactionRecord = keystore.TransactionRecord
type TransactionDirection = keystore.TransactionDirection

const (
	TransactionIncoming = keystore.TransactionIncoming
	TransactionOutgoing = keystore.TransactionOutgoing
)

type IncomingDeposit struct {
	TxID       string
	AmountSats int64
}

type OutgoingTransaction struct {
	TxID            string
	SourceAddress   string
	Destination     string
	DestinationType string
	AmountSats      int64
	FeeSats         int64
	BroadcastAt     time.Time
}

func (w *Wallet) ObserveFundingWithHistory(addr string, balanceSats int64, confirmations int, deposits []IncomingDeposit, observedAt time.Time) (bool, error) {
	if balanceSats <= 0 || confirmations < FundingMinConfirmations {
		return false, nil
	}
	records := make([]keystore.TransactionRecord, 0, len(deposits))
	for _, deposit := range deposits {
		records = append(records, keystore.TransactionRecord{Direction: keystore.TransactionIncoming, TxID: deposit.TxID, Destination: addr, AmountSats: deposit.AmountSats, RecordedAt: observedAt.UTC()})
	}
	if _, err := w.index.MarkFundedAndRecordIncoming(addr, balanceSats, records); err != nil {
		return false, fmt.Errorf("wallet: ObserveFundingWithHistory: %w", err)
	}
	if err := w.fillPool(); err != nil {
		fmt.Printf("wallet: WARNING pool refill failed after funding detection: %v\n", err)
	}
	return true, nil
}

func (w *Wallet) RecordOutgoingTransaction(out OutgoingTransaction) error {
	return w.index.PutTransaction(keystore.TransactionRecord{Direction: keystore.TransactionOutgoing, TxID: out.TxID, SourceAddress: out.SourceAddress, Destination: out.Destination, DestinationType: out.DestinationType, AmountSats: out.AmountSats, FeeSats: out.FeeSats, RecordedAt: out.BroadcastAt.UTC()})
}

func (w *Wallet) ListTransactions() ([]TransactionRecord, error) {
	return w.index.ListTransactions()
}
