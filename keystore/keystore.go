// Package keystore implements the QOGE single-use address index.
//
// Design (SIP-QOGE-PQC-01, Section 5.3 & 5.4):
//
//   - Every SLH-DSA keypair is derived from a master seed via an index counter.
//   - The index is monotonically incrementing and never decrements.
//   - Each address has an immutable lifecycle:
//     FRESH → FUNDED → SPEND_PENDING → SPENT → RETIRED.
//   - Private key material is zeroed from memory on transition to RETIRED.
//   - The index DB is persisted encrypted to disk (bbolt + AES-256-GCM).
//
// Security invariants (hard-coded, never configurable):
//  1. Only FUNDED addresses may sign, and they may enter SPEND_PENDING once.
//  2. RETIRED is permanent. No address is ever un-retired.
//  3. Change outputs route to an unreserved FRESH address, which is reserved
//     atomically with the source's transition to SPEND_PENDING.
//  4. The master seed never leaves this package unencrypted.
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/hkdf"
)

// ─── Address state constants ─────────────────────────────────────────────────

// AddressState represents the lifecycle stage of a single-use address.
type AddressState uint8

const (
	StateFresh        AddressState = iota // Generated, unreserved, and unfunded
	StateFunded                           // Confirmed balance; key never exposed
	StateSpendPending                     // Successfully signed; awaiting confirmation
	StateSpent                            // Spending transaction confirmed
	StateRetired                          // Private key zeroed; permanent
)

func (s AddressState) String() string {
	switch s {
	case StateFresh:
		return "FRESH"
	case StateFunded:
		return "FUNDED"
	case StateSpendPending:
		return "SPEND_PENDING"
	case StateSpent:
		return "SPENT"
	case StateRetired:
		return "RETIRED"
	default:
		return "UNKNOWN"
	}
}

// ─── Errors ───────────────────────────────────────────────────────────────────

var (
	ErrAddressNotFresh     = errors.New("keystore: address is not an unreserved FRESH address")
	ErrAddressNotFunded    = errors.New("keystore: address is not FUNDED")
	ErrAddressNotPending   = errors.New("keystore: cannot mark spent — address is not SPEND_PENDING")
	ErrAddressNotSpent     = errors.New("keystore: cannot retire — address is not SPENT")
	ErrNoFreshAddress      = errors.New("keystore: no FRESH address available — call PreGenerate first")
	ErrMasterSeedNotLoaded = errors.New("keystore: master seed not loaded — call Open first")
	ErrInvalidSeedLength   = errors.New("keystore: invalid seed length (want 32 bytes)")
	ErrIncompatibleDB      = errors.New("keystore: incompatible pre-five-state database; delete qoge_wallet.db and create a new wallet with a new seed")
	ErrSeedMismatch        = errors.New("keystore: seed does not authenticate this wallet database")
	ErrNoValidationRecord  = errors.New("keystore: wallet database has no encrypted key available for seed validation")
)

// ─── AddressRecord ────────────────────────────────────────────────────────────

// AddressRecord is persisted for each generated address.
// The private key seed is stored encrypted in the DB until retirement,
// then zeroed.
type AddressRecord struct {
	Index       uint64       `json:"index"`
	Address     string       `json:"address"`    // Bech32 "qoge1..." address
	PublicKey   []byte       `json:"public_key"` // 32-byte SLH-DSA pubkey
	EncSeedBlob []byte       `json:"enc_seed"`   // AES-256-GCM encrypted seed (nil after retirement)
	State       AddressState `json:"state"`
	Reserved    bool         `json:"reserved,omitempty"`   // FRESH change output committed by a signed transaction
	SpendTxID   string       `json:"spend_txid,omitempty"` // txid awaited while SPEND_PENDING
}

// ─── DB bucket names ─────────────────────────────────────────────────────────

var (
	bucketAddresses = []byte("addresses") // index (uint64 big-endian) → AddressRecord JSON
	bucketMeta      = []byte("meta")      // "next_index" → uint64; "master_salt" → []byte
)

const schemaVersion = uint64(2)

var keySchemaVersion = []byte("schema_version")

// ─── KeyIndex ─────────────────────────────────────────────────────────────────

// KeyIndex manages the single-use address index for the QOGE SPHINCS wallet.
type KeyIndex struct {
	mu         sync.Mutex
	db         *bolt.DB
	masterSeed []byte // 32-byte seed; held in memory while wallet is open
	encKey     []byte // 32-byte AES key derived from masterSeed for DB encryption
}

// Open opens (or creates) the index database at dbPath.
// seed must be 32 bytes of master entropy from hardware RNG.
// SECURITY: seed is kept in memory only for the lifetime of KeyIndex.
// Call Close() to zero it.
func Open(dbPath string, seed []byte) (*KeyIndex, error) {
	if len(seed) != 32 {
		return nil, ErrInvalidSeedLength
	}
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("keystore: open DB: %w", err)
	}

	// Initialise buckets and reject old records rather than interpreting their
	// numeric state values under the new five-state lifecycle.
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, bkt := range [][]byte{bucketAddresses, bucketMeta, bucketTransactions} {
			if _, err := tx.CreateBucketIfNotExists(bkt); err != nil {
				return err
			}
		}
		meta := tx.Bucket(bucketMeta)
		addresses := tx.Bucket(bucketAddresses)
		version := meta.Get(keySchemaVersion)
		if version == nil {
			if k, _ := addresses.Cursor().First(); k != nil {
				return ErrIncompatibleDB
			}
			buf := make([]byte, 8)
			binary.BigEndian.PutUint64(buf, schemaVersion)
			return meta.Put(keySchemaVersion, buf)
		}
		if len(version) != 8 || binary.BigEndian.Uint64(version) != schemaVersion {
			return ErrIncompatibleDB
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("keystore: init/validate database: %w", err)
	}

	// Derive AES key from master seed using HKDF-SHA256.
	// Separation from the signing key derivation prevents key reuse.
	encKey, err := hkdfDerive(seed, []byte("qoge-keyindex-aes256-gcm"), 32)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("keystore: derive enc key: %w", err)
	}

	ki := &KeyIndex{
		db:         db,
		masterSeed: seed,
		encKey:     encKey,
	}
	return ki, nil
}

// ValidateExisting opens an already-formatted database read-only, verifies its
// schema, and authenticates seed against an encrypted private-key record. The
// read-only preflight ensures a rejected open cannot advance bbolt metadata or
// modify wallet data.
func ValidateExisting(dbPath string, seed []byte) error {
	if len(seed) != 32 {
		return ErrInvalidSeedLength
	}
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("keystore: open existing DB read-only: %w", err)
	}
	defer db.Close()

	encKey, err := hkdfDerive(seed, []byte("qoge-keyindex-aes256-gcm"), 32)
	if err != nil {
		return fmt.Errorf("keystore: derive validation key: %w", err)
	}
	defer ZeroBytes(encKey)

	return db.View(func(tx *bolt.Tx) error {
		addresses := tx.Bucket(bucketAddresses)
		meta := tx.Bucket(bucketMeta)
		if addresses == nil || meta == nil {
			return ErrIncompatibleDB
		}
		version := meta.Get(keySchemaVersion)
		if len(version) != 8 || binary.BigEndian.Uint64(version) != schemaVersion {
			return ErrIncompatibleDB
		}

		var blob []byte
		err := addresses.ForEach(func(_, v []byte) error {
			var rec AddressRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if len(rec.EncSeedBlob) > 0 {
				blob = append([]byte(nil), rec.EncSeedBlob...)
				return errStopIteration
			}
			return nil
		})
		if err != nil && !errors.Is(err, errStopIteration) {
			return err
		}
		if len(blob) == 0 {
			return ErrNoValidationRecord
		}
		plain, err := decryptWithKey(encKey, blob)
		if err != nil {
			return ErrSeedMismatch
		}
		ZeroBytes(plain)
		return nil
	})
}

// Close zeros sensitive memory and closes the database.
// Always call this (via defer) when the wallet is done.
func (ki *KeyIndex) Close() error {
	ki.mu.Lock()
	defer ki.mu.Unlock()
	ZeroBytes(ki.masterSeed)
	ZeroBytes(ki.encKey)
	return ki.db.Close()
}

// ─── Index counter ────────────────────────────────────────────────────────────

// nextIndex reads the monotonic index counter from the DB.
// Must be called inside a write transaction.
func nextIndex(tx *bolt.Tx) (uint64, error) {
	bkt := tx.Bucket(bucketMeta)
	v := bkt.Get([]byte("next_index"))
	if v == nil {
		return 0, nil
	}
	if len(v) != 8 {
		return 0, fmt.Errorf("keystore: corrupted next_index length %d", len(v))
	}
	return binary.BigEndian.Uint64(v), nil
}

// incrementIndex writes idx+1 to the DB. Never decrements.
func incrementIndex(tx *bolt.Tx, idx uint64) error {
	bkt := tx.Bucket(bucketMeta)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, idx+1)
	return bkt.Put([]byte("next_index"), buf)
}

// ─── Address generation ───────────────────────────────────────────────────────

// GenerateAddress derives a fresh SLH-DSA keypair at the next index,
// stores the record, and returns the QOGE address string.
//
// This function is the integration point for the signer and address packages.
// It is called with a deriveFn that wraps slhdsa.NewSigner to keep this
// package free of CGo dependencies during unit testing.
//
// deriveFn(seed []byte, index uint64) returns (pubKey []byte, encSeedBlob []byte, address string, err error)
func (ki *KeyIndex) GenerateAddress(deriveFn func([]byte, uint64) ([]byte, []byte, string, error)) (string, error) {
	ki.mu.Lock()
	defer ki.mu.Unlock()
	if ki.masterSeed == nil {
		return "", ErrMasterSeedNotLoaded
	}

	var addr string
	err := ki.db.Update(func(tx *bolt.Tx) error {
		idx, err := nextIndex(tx)
		if err != nil {
			return err
		}

		pubKey, encSeed, derivedAddr, err := deriveFn(ki.masterSeed, idx)
		if err != nil {
			return fmt.Errorf("keystore: deriveFn failed at index %d: %w", idx, err)
		}

		rec := AddressRecord{
			Index:       idx,
			Address:     derivedAddr,
			PublicKey:   pubKey,
			EncSeedBlob: encSeed,
			State:       StateFresh,
		}
		data, err := json.Marshal(rec)
		if err != nil {
			return err
		}

		key := indexKey(idx)
		if err := tx.Bucket(bucketAddresses).Put(key, data); err != nil {
			return err
		}
		if err := incrementIndex(tx, idx); err != nil {
			return err
		}

		addr = derivedAddr
		return nil
	})
	return addr, err
}

// PreGenerate generates addresses until the pool has N unreserved FRESH entries.
// Calls GenerateAddress N times as needed.
func (ki *KeyIndex) PreGenerate(n int, deriveFn func([]byte, uint64) ([]byte, []byte, string, error)) error {
	current, err := ki.CountAvailableFresh()
	if err != nil {
		return err
	}
	needed := n - current
	for i := 0; i < needed; i++ {
		if _, err := ki.GenerateAddress(deriveFn); err != nil {
			return fmt.Errorf("keystore: PreGenerate failed at iteration %d: %w", i, err)
		}
	}
	return nil
}

// ─── State transitions ────────────────────────────────────────────────────────

// MarkFunded transitions an address from FRESH → FUNDED after the wallet
// observes a positive balance at the required confirmation depth. A reserved
// change address is valid here; reservation is cleared as it becomes spendable.
func (ki *KeyIndex) MarkFunded(addr string) error {
	ki.mu.Lock()
	defer ki.mu.Unlock()
	return ki.db.Update(func(tx *bolt.Tx) error {
		rec, key, err := findRecord(tx, addr)
		if err != nil {
			return err
		}
		if rec.State != StateFresh {
			return ErrAddressNotFresh
		}
		rec.State = StateFunded
		rec.Reserved = false
		return putRecord(tx, key, rec)
	})
}

// MarkSpendPendingAndReserveChange atomically transitions the signing source
// FUNDED → SPEND_PENDING, persists the transaction it is awaiting, and
// optionally reserves a FRESH change address.
func (ki *KeyIndex) MarkSpendPendingAndReserveChange(fromAddr, changeAddr, spendTxID string) error {
	ki.mu.Lock()
	defer ki.mu.Unlock()
	return ki.db.Update(func(tx *bolt.Tx) error {
		from, fromKey, err := findRecord(tx, fromAddr)
		if err != nil {
			return err
		}
		if from.State != StateFunded {
			return ErrAddressNotFunded
		}
		var change *AddressRecord
		var changeKey []byte
		if changeAddr != "" {
			change, changeKey, err = findRecord(tx, changeAddr)
			if err != nil {
				return err
			}
			if change.State != StateFresh || change.Reserved {
				return ErrAddressNotFresh
			}
		}
		from.State = StateSpendPending
		from.SpendTxID = spendTxID
		if err := putRecord(tx, fromKey, from); err != nil {
			return err
		}
		if change != nil {
			change.Reserved = true
			if err := putRecord(tx, changeKey, change); err != nil {
				return err
			}
		}
		return nil
	})
}

// MarkSpent transitions address addr from SPEND_PENDING → SPENT.
func (ki *KeyIndex) MarkSpent(addr string) error {
	return ki.transition(addr, StateSpendPending, StateSpent, false)
}

// Retire transitions address addr from SPENT → RETIRED and zeros the
// encrypted seed blob from the record. The private key material is gone.
// This transition is irreversible. See SIP-QOGE-PQC-01 Section 5.4.
func (ki *KeyIndex) Retire(addr string) error {
	return ki.transition(addr, StateSpent, StateRetired, true)
}

// transition is the internal state machine executor.
// zeroSeed: if true, the EncSeedBlob field is zeroed and removed from the record.
func (ki *KeyIndex) transition(addr string, from, to AddressState, zeroSeed bool) error {
	ki.mu.Lock()
	defer ki.mu.Unlock()

	return ki.db.Update(func(tx *bolt.Tx) error {
		rec, key, err := findRecord(tx, addr)
		if err != nil {
			return err
		}
		if rec.State != from {
			switch from {
			case StateFresh:
				return ErrAddressNotFresh
			case StateFunded:
				return ErrAddressNotFunded
			case StateSpendPending:
				return ErrAddressNotPending
			case StateSpent:
				return ErrAddressNotSpent
			}
		}
		rec.State = to
		if zeroSeed {
			ZeroBytes(rec.EncSeedBlob)
			rec.EncSeedBlob = nil
		}
		return putRecord(tx, key, rec)
	})
}

// ─── Queries ──────────────────────────────────────────────────────────────────

// NextFreshAddress returns the lowest-index unreserved FRESH address.
// Returns ErrNoFreshAddress if the pool is empty.
func (ki *KeyIndex) NextFreshAddress() (string, error) {
	ki.mu.Lock()
	defer ki.mu.Unlock()

	var addr string
	err := ki.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAddresses).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var rec AddressRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.State == StateFresh && !rec.Reserved {
				addr = rec.Address
				return nil
			}
		}
		return ErrNoFreshAddress
	})
	return addr, err
}

// GetRecord returns the full AddressRecord for addr, or an error if not found.
func (ki *KeyIndex) GetRecord(addr string) (*AddressRecord, error) {
	ki.mu.Lock()
	defer ki.mu.Unlock()

	var result *AddressRecord
	err := ki.db.View(func(tx *bolt.Tx) error {
		rec, _, err := findRecord(tx, addr)
		if err != nil {
			return err
		}
		result = rec
		return nil
	})
	return result, err
}

// ListByState returns all AddressRecords in the given state, ordered by index.
func (ki *KeyIndex) ListByState(state AddressState) ([]AddressRecord, error) {
	ki.mu.Lock()
	defer ki.mu.Unlock()

	var results []AddressRecord
	err := ki.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAddresses).ForEach(func(_, v []byte) error {
			var rec AddressRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.State == state {
				results = append(results, rec)
			}
			return nil
		})
	})
	return results, err
}

// CountByState returns the number of records in the given state.
func (ki *KeyIndex) CountByState(state AddressState) (int, error) {
	ki.mu.Lock()
	defer ki.mu.Unlock()

	count := 0
	err := ki.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAddresses).ForEach(func(_, v []byte) error {
			var rec AddressRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.State == state {
				count++
			}
			return nil
		})
	})
	return count, err
}

// CountAvailableFresh counts FRESH records which are not reserved for change.
func (ki *KeyIndex) CountAvailableFresh() (int, error) {
	ki.mu.Lock()
	defer ki.mu.Unlock()
	count := 0
	err := ki.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAddresses).ForEach(func(_, v []byte) error {
			var rec AddressRecord
			if err := json.Unmarshal(v, &rec); err != nil {
				return err
			}
			if rec.State == StateFresh && !rec.Reserved {
				count++
			}
			return nil
		})
	})
	return count, err
}

// ─── Encryption helpers (AES-256-GCM) ────────────────────────────────────────

// EncryptSeed encrypts a raw 64-byte SLH-DSA secret key seed for storage.
// Returns a self-contained blob: nonce (12 bytes) || ciphertext.
func (ki *KeyIndex) EncryptSeed(seed []byte) ([]byte, error) {
	block, err := aes.NewCipher(ki.encKey)
	if err != nil {
		return nil, fmt.Errorf("keystore: AES init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keystore: GCM init: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("keystore: nonce generation: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, seed, nil)
	return ciphertext, nil
}

// DecryptSeed decrypts a blob produced by EncryptSeed.
// Returns the raw seed. Zero it immediately after use.
func (ki *KeyIndex) DecryptSeed(blob []byte) ([]byte, error) {
	return ki.decryptSeed(blob)
}

func (ki *KeyIndex) decryptSeed(blob []byte) ([]byte, error) {
	return decryptWithKey(ki.encKey, blob)
}

func decryptWithKey(encKey, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("keystore: AES init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keystore: GCM init: %w", err)
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("keystore: encrypted blob too short")
	}
	nonce, ct := blob[:ns], blob[ns:]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("keystore: GCM Open failed: %w", err)
	}
	return plain, nil
}

// ─── Utility ─────────────────────────────────────────────────────────────────

// ZeroBytes overwrites b with zeros. Call this on any sensitive byte slice
// (secret keys, seeds) immediately after use to minimise memory exposure.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// indexKey converts a uint64 index to an 8-byte big-endian DB key.
// Big-endian ordering ensures bbolt's cursor iterates in index order.
func indexKey(idx uint64) []byte {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, idx)
	return k
}

// findRecord scans the addresses bucket for the record matching addr.
// Returns the record, the DB key, and an error.
var errStopIteration = errors.New("keystore: stop iteration")

func findRecord(tx *bolt.Tx, addr string) (*AddressRecord, []byte, error) {
	var found *AddressRecord
	var foundKey []byte
	err := tx.Bucket(bucketAddresses).ForEach(func(k, v []byte) error {
		var rec AddressRecord
		if err := json.Unmarshal(v, &rec); err != nil {
			return err
		}
		if rec.Address == addr {
			found = &rec
			foundKey = append([]byte{}, k...)
			return errStopIteration
		}
		return nil
	})
	if found != nil {
		return found, foundKey, nil
	}
	if err != nil && !errors.Is(err, errStopIteration) {
		return nil, nil, err
	}
	return nil, nil, fmt.Errorf("keystore: address not found: %s", addr)
}

func putRecord(tx *bolt.Tx, key []byte, rec *AddressRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return tx.Bucket(bucketAddresses).Put(key, data)
}

// hkdfDerive derives keyLen bytes from seed using HKDF-SHA256 with info.
func hkdfDerive(seed, info []byte, keyLen int) ([]byte, error) {
	h := hkdf.New(sha256.New, seed, nil, info)
	out := make([]byte, keyLen)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}
