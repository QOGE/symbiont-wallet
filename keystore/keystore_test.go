package keystore

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/saogen/qoge-sphincs-wallet/address"
)

// ─── Test helpers ───────────────────────────────────────────────────────────

// testSeed returns a fixed 32-byte seed for deterministic tests.
func testSeed() []byte {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	return seed
}

// openTestIndex creates a fresh KeyIndex backed by a temp file.
// Cleanup is registered automatically via t.Cleanup.
func openTestIndex(t *testing.T) *KeyIndex {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	seed := testSeed()
	ki, err := Open(dbPath, seed)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() {
		ki.Close()
	})
	return ki
}

// mockDeriveFn returns a deriveFn suitable for GenerateAddress/PreGenerate
// that does NOT require liboqs/CGo. It produces a deterministic 32-byte
// "public key" via SHA256(masterSeed || index), a 64-byte fake secret key,
// and derives a real QOGE address from the fake public key using the
// production address package.
//
// This lets keystore tests run without the signer package's CGo dependency,
// while still exercising the real address derivation and encryption code.
func mockDeriveFn(ki *KeyIndex) func([]byte, uint64) ([]byte, []byte, string, error) {
	return func(masterSeed []byte, index uint64) ([]byte, []byte, string, error) {
		h := sha256.New()
		h.Write(masterSeed)
		idxBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(idxBytes, index)
		h.Write(idxBytes)
		pub := h.Sum(nil) // 32 bytes

		// Fake 64-byte secret key (not cryptographically meaningful, just
		// needs to round-trip through EncryptSeed/DecryptSeed).
		sk := make([]byte, 64)
		copy(sk, pub)
		copy(sk[32:], pub)

		addr, err := address.FromPublicKey(pub)
		if err != nil {
			return nil, nil, "", err
		}

		enc, err := ki.EncryptSeed(sk)
		if err != nil {
			return nil, nil, "", err
		}

		return pub, enc, addr, nil
	}
}

// ─── Open / Close / validation ───────────────────────────────────────────────

func TestOpenAndClose(t *testing.T) {
	ki := openTestIndex(t)
	if ki == nil {
		t.Fatal("Open returned nil KeyIndex")
	}
}

func TestOpenRejectsInvalidSeedLength(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	_, err := Open(dbPath, []byte{0x01, 0x02}) // too short
	if err != ErrInvalidSeedLength {
		t.Fatalf("expected ErrInvalidSeedLength, got: %v", err)
	}
}

// ─── Address generation ───────────────────────────────────────────────────────

func TestGenerateAddressBasic(t *testing.T) {
	ki := openTestIndex(t)
	deriveFn := mockDeriveFn(ki)

	addr, err := ki.GenerateAddress(deriveFn)
	if err != nil {
		t.Fatalf("GenerateAddress failed: %v", err)
	}
	if addr == "" {
		t.Fatal("GenerateAddress returned empty address")
	}
	if addr[:3] != "bq1" {
		t.Errorf("address should start with 'qoge1', got: %s", addr)
	}

	rec, err := ki.GetRecord(addr)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if rec.Index != 0 {
		t.Errorf("first generated address should have Index=0, got %d", rec.Index)
	}
	if rec.State != StateFresh {
		t.Errorf("newly generated address should be FRESH, got %s", rec.State)
	}
	if len(rec.PublicKey) != 32 {
		t.Errorf("public key should be 32 bytes, got %d", len(rec.PublicKey))
	}
	if len(rec.EncSeedBlob) == 0 {
		t.Error("EncSeedBlob should not be empty for a FRESH address")
	}
}

func TestIndexMonotonicallyIncreases(t *testing.T) {
	ki := openTestIndex(t)
	deriveFn := mockDeriveFn(ki)

	var addrs []string
	for i := 0; i < 3; i++ {
		addr, err := ki.GenerateAddress(deriveFn)
		if err != nil {
			t.Fatalf("GenerateAddress[%d] failed: %v", i, err)
		}
		addrs = append(addrs, addr)
	}

	for i, addr := range addrs {
		rec, err := ki.GetRecord(addr)
		if err != nil {
			t.Fatalf("GetRecord[%d] failed: %v", i, err)
		}
		if rec.Index != uint64(i) {
			t.Errorf("address %d: Index = %d, want %d", i, rec.Index, i)
		}
	}

	// Addresses must all be distinct (single-use derivation produces
	// different pubkeys per index).
	if addrs[0] == addrs[1] || addrs[1] == addrs[2] || addrs[0] == addrs[2] {
		t.Error("generated addresses are not unique")
	}
}

func TestPreGeneratePool(t *testing.T) {
	ki := openTestIndex(t)
	deriveFn := mockDeriveFn(ki)

	if err := ki.PreGenerate(5, deriveFn); err != nil {
		t.Fatalf("PreGenerate failed: %v", err)
	}

	count, err := ki.CountByState(StateFresh)
	if err != nil {
		t.Fatalf("CountByState failed: %v", err)
	}
	if count != 5 {
		t.Errorf("CountByState(FRESH) = %d, want 5", count)
	}

	// Calling PreGenerate again with the same target should be a no-op
	// (pool already has 5 FRESH addresses).
	if err := ki.PreGenerate(5, deriveFn); err != nil {
		t.Fatalf("PreGenerate (second call) failed: %v", err)
	}
	count, err = ki.CountByState(StateFresh)
	if err != nil {
		t.Fatalf("CountByState failed: %v", err)
	}
	if count != 5 {
		t.Errorf("CountByState(FRESH) after second PreGenerate = %d, want 5 (no-op expected)", count)
	}
}

// ─── NextFreshAddress ──────────────────────────────────────────────────────────

func TestNextFreshAddress_EmptyPoolFails(t *testing.T) {
	ki := openTestIndex(t)
	_, err := ki.NextFreshAddress()
	if err != ErrNoFreshAddress {
		t.Fatalf("expected ErrNoFreshAddress on empty index, got: %v", err)
	}
}

func TestNextFreshAddress_ReturnsLowestIndex(t *testing.T) {
	ki := openTestIndex(t)
	deriveFn := mockDeriveFn(ki)

	if err := ki.PreGenerate(3, deriveFn); err != nil {
		t.Fatalf("PreGenerate failed: %v", err)
	}

	first, err := ki.NextFreshAddress()
	if err != nil {
		t.Fatalf("NextFreshAddress failed: %v", err)
	}

	rec, err := ki.GetRecord(first)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if rec.Index != 0 {
		t.Errorf("NextFreshAddress should return Index=0 first, got %d", rec.Index)
	}
}

// ─── State machine: happy path ─────────────────────────────────────────────────

func TestStateMachineHappyPath(t *testing.T) {
	ki := openTestIndex(t)
	deriveFn := mockDeriveFn(ki)

	addr, err := ki.GenerateAddress(deriveFn)
	if err != nil {
		t.Fatalf("GenerateAddress failed: %v", err)
	}

	// FRESH -> PENDING
	if err := ki.MarkPending(addr); err != nil {
		t.Fatalf("MarkPending failed: %v", err)
	}
	rec, _ := ki.GetRecord(addr)
	if rec.State != StatePending {
		t.Fatalf("state after MarkPending = %s, want PENDING", rec.State)
	}

	// PENDING -> SPENT
	if err := ki.MarkSpent(addr); err != nil {
		t.Fatalf("MarkSpent failed: %v", err)
	}
	rec, _ = ki.GetRecord(addr)
	if rec.State != StateSpent {
		t.Fatalf("state after MarkSpent = %s, want SPENT", rec.State)
	}
	if len(rec.EncSeedBlob) == 0 {
		t.Error("EncSeedBlob should still be present at SPENT (zeroed only on Retire)")
	}

	// SPENT -> RETIRED (key destruction)
	if err := ki.Retire(addr); err != nil {
		t.Fatalf("Retire failed: %v", err)
	}
	rec, _ = ki.GetRecord(addr)
	if rec.State != StateRetired {
		t.Fatalf("state after Retire = %s, want RETIRED", rec.State)
	}
	if rec.EncSeedBlob != nil {
		t.Error("EncSeedBlob should be nil after RETIRED — key must be destroyed")
	}
}

// ─── State machine: invariant violations ───────────────────────────────────────

// TestSingleUseInvariant_DoubleMarkPending is the core security test:
// an address must never transition FRESH -> PENDING twice.
func TestSingleUseInvariant_DoubleMarkPending(t *testing.T) {
	ki := openTestIndex(t)
	deriveFn := mockDeriveFn(ki)

	addr, err := ki.GenerateAddress(deriveFn)
	if err != nil {
		t.Fatalf("GenerateAddress failed: %v", err)
	}

	if err := ki.MarkPending(addr); err != nil {
		t.Fatalf("first MarkPending failed: %v", err)
	}

	// Second call must fail with ErrAddressAlreadyUsed.
	err = ki.MarkPending(addr)
	if err != ErrAddressAlreadyUsed {
		t.Fatalf("second MarkPending: got %v, want ErrAddressAlreadyUsed", err)
	}
}

func TestMarkSpentWithoutPendingFails(t *testing.T) {
	ki := openTestIndex(t)
	deriveFn := mockDeriveFn(ki)

	addr, err := ki.GenerateAddress(deriveFn)
	if err != nil {
		t.Fatalf("GenerateAddress failed: %v", err)
	}

	// Address is FRESH, not PENDING — MarkSpent must fail.
	err = ki.MarkSpent(addr)
	if err != ErrAddressNotPending {
		t.Fatalf("MarkSpent on FRESH address: got %v, want ErrAddressNotPending", err)
	}
}

func TestRetireWithoutSpentFails(t *testing.T) {
	ki := openTestIndex(t)
	deriveFn := mockDeriveFn(ki)

	addr, err := ki.GenerateAddress(deriveFn)
	if err != nil {
		t.Fatalf("GenerateAddress failed: %v", err)
	}
	if err := ki.MarkPending(addr); err != nil {
		t.Fatalf("MarkPending failed: %v", err)
	}

	// Address is PENDING, not SPENT — Retire must fail.
	err = ki.Retire(addr)
	if err != ErrAddressNotSpent {
		t.Fatalf("Retire on PENDING address: got %v, want ErrAddressNotSpent", err)
	}
}

func TestRetireIsPermanent(t *testing.T) {
	ki := openTestIndex(t)
	deriveFn := mockDeriveFn(ki)

	addr, err := ki.GenerateAddress(deriveFn)
	if err != nil {
		t.Fatalf("GenerateAddress failed: %v", err)
	}
	if err := ki.MarkPending(addr); err != nil {
		t.Fatalf("MarkPending failed: %v", err)
	}
	if err := ki.MarkSpent(addr); err != nil {
		t.Fatalf("MarkSpent failed: %v", err)
	}
	if err := ki.Retire(addr); err != nil {
		t.Fatalf("Retire failed: %v", err)
	}

	// Any further transition attempts must fail — RETIRED is terminal.
	if err := ki.MarkPending(addr); err != ErrAddressAlreadyUsed {
		t.Errorf("MarkPending on RETIRED address: got %v, want ErrAddressAlreadyUsed", err)
	}
	if err := ki.MarkSpent(addr); err != ErrAddressNotPending {
		t.Errorf("MarkSpent on RETIRED address: got %v, want ErrAddressNotPending", err)
	}
	if err := ki.Retire(addr); err != ErrAddressNotSpent {
		t.Errorf("Retire on RETIRED address: got %v, want ErrAddressNotSpent", err)
	}
}

// ─── GetRecord on unknown address ───────────────────────────────────────────────

func TestGetRecordUnknownAddress(t *testing.T) {
	ki := openTestIndex(t)
	_, err := ki.GetRecord("qoge1doesnotexist")
	if err == nil {
		t.Fatal("GetRecord should fail for an unknown address")
	}
}

// ─── Encryption ──────────────────────────────────────────────────────────────

func TestEncryptDecryptSeedRoundTrip(t *testing.T) {
	ki := openTestIndex(t)

	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(255 - i)
	}

	enc, err := ki.EncryptSeed(seed)
	if err != nil {
		t.Fatalf("EncryptSeed failed: %v", err)
	}
	if bytes.Equal(enc, seed) {
		t.Error("encrypted blob should not equal plaintext")
	}

	dec, err := ki.DecryptSeed(enc)
	if err != nil {
		t.Fatalf("DecryptSeed failed: %v", err)
	}
	if !bytes.Equal(dec, seed) {
		t.Errorf("decrypted seed does not match original:\n got  %x\n want %x", dec, seed)
	}
}

func TestDecryptSeedRejectsTamperedBlob(t *testing.T) {
	ki := openTestIndex(t)

	seed := make([]byte, 64)
	enc, err := ki.EncryptSeed(seed)
	if err != nil {
		t.Fatalf("EncryptSeed failed: %v", err)
	}

	// Flip a byte in the ciphertext — GCM must detect this.
	tampered := make([]byte, len(enc))
	copy(tampered, enc)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = ki.DecryptSeed(tampered)
	if err == nil {
		t.Fatal("DecryptSeed should fail on tampered ciphertext (GCM auth failure)")
	}
}

// ─── ZeroBytes ───────────────────────────────────────────────────────────────

func TestZeroBytes(t *testing.T) {
	b := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("ZeroBytes: byte %d = 0x%02x, want 0x00", i, v)
		}
	}
}

// ─── End-to-end: full single-use lifecycle with pool refill ─────────────────────

// TestFullLifecycleWithPoolRefill simulates the wallet-level flow:
// pre-generate a pool, take the next fresh address, run it through the
// full state machine, and confirm the retired address never reappears
// from NextFreshAddress.
func TestFullLifecycleWithPoolRefill(t *testing.T) {
	ki := openTestIndex(t)
	deriveFn := mockDeriveFn(ki)

	const poolSize = 3
	if err := ki.PreGenerate(poolSize, deriveFn); err != nil {
		t.Fatalf("PreGenerate failed: %v", err)
	}

	used, err := ki.NextFreshAddress()
	if err != nil {
		t.Fatalf("NextFreshAddress failed: %v", err)
	}

	if err := ki.MarkPending(used); err != nil {
		t.Fatalf("MarkPending failed: %v", err)
	}
	if err := ki.MarkSpent(used); err != nil {
		t.Fatalf("MarkSpent failed: %v", err)
	}
	if err := ki.Retire(used); err != nil {
		t.Fatalf("Retire failed: %v", err)
	}

	// FRESH count should have dropped by 1.
	freshCount, err := ki.CountByState(StateFresh)
	if err != nil {
		t.Fatalf("CountByState failed: %v", err)
	}
	if freshCount != poolSize-1 {
		t.Errorf("FRESH count after retiring one = %d, want %d", freshCount, poolSize-1)
	}

	// Refill the pool back to poolSize.
	if err := ki.PreGenerate(poolSize, deriveFn); err != nil {
		t.Fatalf("PreGenerate (refill) failed: %v", err)
	}
	freshCount, err = ki.CountByState(StateFresh)
	if err != nil {
		t.Fatalf("CountByState failed: %v", err)
	}
	if freshCount != poolSize {
		t.Errorf("FRESH count after refill = %d, want %d", freshCount, poolSize)
	}

	// The next fresh address must NOT be the retired one.
	next, err := ki.NextFreshAddress()
	if err != nil {
		t.Fatalf("NextFreshAddress failed: %v", err)
	}
	if next == used {
		t.Error("NextFreshAddress returned a RETIRED address — single-use invariant violated")
	}

	retiredCount, err := ki.CountByState(StateRetired)
	if err != nil {
		t.Fatalf("CountByState failed: %v", err)
	}
	if retiredCount != 1 {
		t.Errorf("RETIRED count = %d, want 1", retiredCount)
	}
}
