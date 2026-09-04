package keystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketTransactions = []byte("transactions")

var ErrTransactionRecordConflict = errors.New("keystore: transaction history record conflicts with existing write-once entry")

type TransactionDirection string

const (
	TransactionIncoming TransactionDirection = "incoming"
	TransactionOutgoing TransactionDirection = "outgoing"
)

type TransactionRecord struct {
	Direction       TransactionDirection `json:"direction"`
	TxID            string               `json:"txid"`
	SourceAddress   string               `json:"source_address,omitempty"`
	Destination     string               `json:"destination_address"`
	DestinationType string               `json:"destination_type,omitempty"`
	AmountSats      int64                `json:"amount_sats"`
	FeeSats         int64                `json:"fee_sats,omitempty"`
	RecordedAt      time.Time            `json:"recorded_at"`
}

func historyKey(rec TransactionRecord) ([]byte, error) {
	if rec.TxID == "" || rec.Destination == "" || rec.AmountSats <= 0 || rec.RecordedAt.IsZero() {
		return nil, errors.New("keystore: incomplete transaction history record")
	}
	switch rec.Direction {
	case TransactionIncoming:
		return []byte("in:" + rec.TxID + ":" + rec.Destination), nil
	case TransactionOutgoing:
		if rec.SourceAddress == "" || rec.DestinationType == "" || rec.FeeSats < 0 {
			return nil, errors.New("keystore: incomplete outgoing transaction history record")
		}
		return []byte("out:" + rec.TxID), nil
	default:
		return nil, errors.New("keystore: invalid transaction direction")
	}
}

func putHistoryRecord(tx *bolt.Tx, rec TransactionRecord) error {
	key, err := historyKey(rec)
	if err != nil {
		return err
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	bucket := tx.Bucket(bucketTransactions)
	if existing := bucket.Get(key); existing != nil {
		if bytes.Equal(existing, data) {
			return nil
		}
		return ErrTransactionRecordConflict
	}
	return bucket.Put(key, data)
}

func (ki *KeyIndex) PutTransaction(rec TransactionRecord) error {
	ki.mu.Lock()
	defer ki.mu.Unlock()
	return ki.db.Update(func(tx *bolt.Tx) error { return putHistoryRecord(tx, rec) })
}

// MarkFundedAndRecordIncoming captures Reserved before clearing it. Reserved
// change addresses transition normally but never create incoming history.
func (ki *KeyIndex) MarkFundedAndRecordIncoming(addr string, balanceSats int64, incoming []TransactionRecord) (bool, error) {
	ki.mu.Lock()
	defer ki.mu.Unlock()
	var wasReserved bool
	err := ki.db.Update(func(tx *bolt.Tx) error {
		rec, key, err := findRecord(tx, addr)
		if err != nil {
			return err
		}
		if rec.State != StateFresh {
			return ErrAddressNotFresh
		}
		wasReserved = rec.Reserved
		if !wasReserved {
			if len(incoming) == 0 {
				return errors.New("keystore: external funding has no anchored transaction record")
			}
			var recordedSats int64
			for _, history := range incoming {
				recordedSats += history.AmountSats
				if history.Direction != TransactionIncoming || history.Destination != addr {
					return errors.New("keystore: invalid incoming funding record")
				}
				if err := putHistoryRecord(tx, history); err != nil {
					return err
				}
			}
			if recordedSats != balanceSats {
				return fmt.Errorf("keystore: incoming history total %d does not match funded balance %d", recordedSats, balanceSats)
			}
		}
		rec.State = StateFunded
		rec.Reserved = false
		return putRecord(tx, key, rec)
	})
	return wasReserved, err
}

func (ki *KeyIndex) ListTransactions() ([]TransactionRecord, error) {
	ki.mu.Lock()
	defer ki.mu.Unlock()
	var records []TransactionRecord
	err := ki.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTransactions).ForEach(func(_, value []byte) error {
			var rec TransactionRecord
			if err := json.Unmarshal(value, &rec); err != nil {
				return fmt.Errorf("keystore: decode transaction history: %w", err)
			}
			records = append(records, rec)
			return nil
		})
	})
	sort.Slice(records, func(i, j int) bool {
		if records[i].RecordedAt.Equal(records[j].RecordedAt) {
			return records[i].TxID > records[j].TxID
		}
		return records[i].RecordedAt.After(records[j].RecordedAt)
	})
	return records, err
}
