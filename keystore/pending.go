package keystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Pending broadcasts are signed, public transactions. The raw hex is kept
// plaintext in the same 0600 wallet database as transaction history; it is
// broadcast-capable data, not seed or private-key material.
var bucketPendingBroadcasts = []byte("pending_broadcasts")

var ErrPendingBroadcastConflict = errors.New("keystore: pending broadcast conflicts with existing record")

type PendingBroadcast struct {
	TxID            string    `json:"txid"`
	RawHex          string    `json:"raw_hex"`
	Kind            string    `json:"kind"`
	SourceAddress   string    `json:"source_address"`
	Destination     string    `json:"destination"`
	DestinationType string    `json:"destination_type"`
	AmountSats      int64     `json:"amount_sats"`
	FeeSats         int64     `json:"fee_sats"`
	SignedAt        time.Time `json:"signed_at"`
}

func putPendingBroadcast(tx *bolt.Tx, rec PendingBroadcast) error {
	if len(rec.TxID) != 64 || rec.RawHex == "" || rec.SourceAddress == "" || rec.AmountSats <= 0 || rec.FeeSats < 0 || rec.SignedAt.IsZero() || (rec.Kind != "spend" && rec.Kind != "recovery") {
		return errors.New("keystore: incomplete pending broadcast")
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	bucket := tx.Bucket(bucketPendingBroadcasts)
	if bucket.Get([]byte(rec.TxID)) != nil {
		return ErrPendingBroadcastConflict
	}
	return bucket.Put([]byte(rec.TxID), data)
}

func putPendingForTransition(tx *bolt.Tx, txid, source, kind string, pending []PendingBroadcast) error {
	if len(pending) == 0 {
		return nil
	}
	if len(pending) != 1 || pending[0].TxID != txid || pending[0].SourceAddress != source || pending[0].Kind != kind {
		return errors.New("keystore: pending broadcast does not match signing transition")
	}
	return putPendingBroadcast(tx, pending[0])
}

func (ki *KeyIndex) ListPendingBroadcasts() ([]PendingBroadcast, error) {
	ki.mu.Lock()
	defer ki.mu.Unlock()
	var records []PendingBroadcast
	err := ki.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPendingBroadcasts).ForEach(func(_, value []byte) error {
			var rec PendingBroadcast
			if err := json.Unmarshal(value, &rec); err != nil {
				return fmt.Errorf("keystore: decode pending broadcast: %w", err)
			}
			records = append(records, rec)
			return nil
		})
	})
	sort.Slice(records, func(i, j int) bool {
		if records[i].SignedAt.Equal(records[j].SignedAt) {
			return records[i].TxID > records[j].TxID
		}
		return records[i].SignedAt.After(records[j].SignedAt)
	})
	return records, err
}

func (ki *KeyIndex) DeletePendingBroadcast(txid string) error {
	ki.mu.Lock()
	defer ki.mu.Unlock()
	return ki.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketPendingBroadcasts).Delete([]byte(txid)) })
}
