package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/saogen/qoge-sphincs-wallet/address"
	"github.com/saogen/qoge-sphincs-wallet/keystore"
	slhdsa "github.com/saogen/qoge-sphincs-wallet/signer"
)

// NOTE: These tests exercise the full Symbiont Wallet stack, including the
// signer package (CGo -> liboqs SLH-DSA-SHA2-128f). Each CreateNew call
// pre-generates PreGenPoolSize (20) keypairs, so this suite is slower than
// the address/keystore unit tests but still completes in well under a second
// per wallet on typical hardware.
//
// This file is package-internal (package wallet, not wallet_test) so tests
// can inspect w.index directly to verify state-machine and key-destruction
// behaviour at the lowest level.

// ─── Test helpers ───────────────────────────────────────────────────────────

func newTestWallet(t *testing.T) *Wallet {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "wallet.db")
	seed, err := GenerateMasterSeed()
	if err != nil {
		t.Fatalf("GenerateMasterSeed failed: %v", err)
	}
	w, err := CreateNew(dbPath, seed)
	if err != nil {
		t.Fatalf("CreateNew failed: %v", err)
	}
	t.Cleanup(func() {
		w.Close()
	})
	return w
}

func testFundAddress(w *Wallet, addr string) error {
	_, err := w.ObserveFunding(addr, 1, FundingMinConfirmations)
	return err
}

func testSpendPending(w *Wallet, addr string) error {
	return w.index.MarkSpendPendingAndReserveChange(addr, "", "")
}

func testFreshAddresses(t *testing.T, w *Wallet, n int) []string {
	t.Helper()
	infos, err := w.ListAddresses()
	if err != nil {
		t.Fatal(err)
	}
	addrs := make([]string, 0, n)
	for _, info := range infos {
		if info.State == keystore.StateFresh && !info.Reserved {
			addrs = append(addrs, info.Address)
			if len(addrs) == n {
				return addrs
			}
		}
	}
	t.Fatalf("found %d unreserved FRESH addresses, want %d", len(addrs), n)
	return nil
}

// ─── Master seed ──────────────────────────────────────────────────────────────

func TestGenerateMasterSeedSize(t *testing.T) {
	seed, err := GenerateMasterSeed()
	if err != nil {
		t.Fatalf("GenerateMasterSeed failed: %v", err)
	}
	if len(seed) != 32 {
		t.Errorf("seed length = %d, want 32", len(seed))
	}
}

func TestGenerateMasterSeedIsRandom(t *testing.T) {
	s1, err := GenerateMasterSeed()
	if err != nil {
		t.Fatalf("GenerateMasterSeed failed: %v", err)
	}
	s2, err := GenerateMasterSeed()
	if err != nil {
		t.Fatalf("GenerateMasterSeed failed: %v", err)
	}
	same := true
	for i := range s1 {
		if s1[i] != s2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("two calls to GenerateMasterSeed produced identical seeds")
	}
}

// ─── Wallet initialisation ─────────────────────────────────────────────────────

func TestCreateNewRejectsWrongLengthSeed(t *testing.T) {
	for _, length := range []int{0, 31, 33} {
		dbPath := filepath.Join(t.TempDir(), fmt.Sprintf("wallet-%d.db", length))
		if _, err := CreateNew(dbPath, make([]byte, length)); err == nil {
			t.Fatalf("CreateNew accepted %d-byte seed", length)
		}
		if _, err := os.Stat(dbPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("CreateNew with %d-byte seed created a database: %v", length, err)
		}
	}
}

func TestCreateNewAndOpenExistingSucceedInIntendedCases(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "missing-parent", "wallet.db")
	seed, err := GenerateMasterSeed()
	if err != nil {
		t.Fatal(err)
	}

	w, err := CreateNew(dbPath, append([]byte(nil), seed...))
	if err != nil {
		t.Fatalf("CreateNew failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close after CreateNew failed: %v", err)
	}

	w, err = OpenExisting(dbPath, append([]byte(nil), seed...))
	if err != nil {
		t.Fatalf("OpenExisting failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close after OpenExisting failed: %v", err)
	}
}

func TestCreateNewRejectsExistingWallet(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "wallet.db")
	seed, err := GenerateMasterSeed()
	if err != nil {
		t.Fatal(err)
	}
	w, err := CreateNew(dbPath, append([]byte(nil), seed...))
	if err != nil {
		t.Fatalf("initial CreateNew failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	otherSeed, err := GenerateMasterSeed()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateNew(dbPath, otherSeed); !errors.Is(err, ErrWalletAlreadyExists) {
		t.Fatalf("CreateNew existing error = %v, want ErrWalletAlreadyExists", err)
	}

	// The rejected create must not alter the existing wallet.
	w, err = OpenExisting(dbPath, append([]byte(nil), seed...))
	if err != nil {
		t.Fatalf("existing wallet was altered: %v", err)
	}
	w.Close()
}

func TestOpenExistingRejectsMissingWalletWithoutCreatingIt(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "missing", "wallet.db")
	seed, err := GenerateMasterSeed()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExisting(dbPath, seed); !errors.Is(err, ErrWalletNotFound) {
		t.Fatalf("OpenExisting missing error = %v, want ErrWalletNotFound", err)
	}
	if _, err := os.Stat(dbPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenExisting created or changed missing path: stat error = %v", err)
	}
}

func TestOpenExistingRejectsZeroLengthFileWithoutModifyingIt(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "wallet.db")
	if err := os.WriteFile(dbPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeHash := sha256.Sum256(before)

	seed, err := GenerateMasterSeed()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExisting(dbPath, seed); !errors.Is(err, ErrWalletNotFound) {
		t.Fatalf("OpenExisting zero-length error = %v, want ErrWalletNotFound", err)
	}
	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if afterHash := sha256.Sum256(after); afterHash != beforeHash {
		t.Fatalf("zero-length file changed: before %x, after %x", beforeHash, afterHash)
	}
	if len(after) != 0 {
		t.Fatalf("zero-length file grew to %d bytes", len(after))
	}
}

func TestOpenExistingRejectsWrongSeed(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "wallet.db")
	seed, err := GenerateMasterSeed()
	if err != nil {
		t.Fatal(err)
	}
	w, err := CreateNew(dbPath, append([]byte(nil), seed...))
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	before, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeHash := sha256.Sum256(before)

	wrongSeed, err := GenerateMasterSeed()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExisting(dbPath, wrongSeed); !errors.Is(err, ErrWalletSeedMismatch) {
		t.Fatalf("OpenExisting wrong-seed error = %v, want ErrWalletSeedMismatch", err)
	}
	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if afterHash := sha256.Sum256(after); afterHash != beforeHash {
		t.Fatalf("wrong-seed rejection changed database: before %x, after %x", beforeHash, afterHash)
	}

	w, err = OpenExisting(dbPath, append([]byte(nil), seed...))
	if err != nil {
		t.Fatalf("wrong-seed attempt altered wallet: %v", err)
	}
	w.Close()
}

// TestCreateNewWalletPreGeneratesPool confirms M2.2: on creation, the wallet
// pre-generates PreGenPoolSize FRESH addresses.
func TestCreateNewWalletPreGeneratesPool(t *testing.T) {
	w := newTestWallet(t)

	count, err := w.index.CountByState(keystore.StateFresh)
	if err != nil {
		t.Fatalf("CountByState failed: %v", err)
	}
	if count != PreGenPoolSize {
		t.Errorf("FRESH address count after CreateNew = %d, want %d", count, PreGenPoolSize)
	}
}

// ─── Receive address ─────────────────────────────────────────────────────────

func TestNextReceiveAddressFormat(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := address.ValidateAddress(addr); err != nil {
		t.Errorf("NextReceiveAddress returned invalid address %q: %v", addr, err)
	}
}

func TestNextReceiveAddressDoesNotConsumePool(t *testing.T) {
	w := newTestWallet(t)

	before, _ := w.index.CountByState(keystore.StateFresh)

	// Calling NextReceiveAddress repeatedly WITHOUT ObserveFunding
	// should not change the FRESH count — it's read-only until a payment
	// is actually detected.
	addr1, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	addr2, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if addr1 != addr2 {
		t.Errorf("repeated NextReceiveAddress calls returned different addresses "+
			"(%s vs %s) without an intervening ObserveFunding", addr1, addr2)
	}

	after, _ := w.index.CountByState(keystore.StateFresh)
	if before != after {
		t.Errorf("FRESH count changed from %d to %d without ObserveFunding", before, after)
	}
}

func TestObserveFundingRequiresPositiveBalanceAndDepth(t *testing.T) {
	w := newTestWallet(t)
	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		balance int64
		depth   int
	}{{0, FundingMinConfirmations}, {1, FundingMinConfirmations - 1}} {
		changed, err := w.ObserveFunding(addr, tc.balance, tc.depth)
		if err != nil || changed {
			t.Fatalf("ObserveFunding(%d,%d) = changed %v err %v, want no-op", tc.balance, tc.depth, changed, err)
		}
	}
	changed, err := w.ObserveFunding(addr, 1, FundingMinConfirmations)
	if err != nil || !changed {
		t.Fatalf("ObserveFunding at threshold = changed %v err %v", changed, err)
	}
	rec, _ := w.index.GetRecord(addr)
	if rec.State != keystore.StateFunded {
		t.Fatalf("state = %s, want FUNDED", rec.State)
	}
}

// ─── Payment received ────────────────────────────────────────────────────────

func TestObserveFundingTransitionsFreshToFunded(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, addr); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}
	rec, err := w.index.GetRecord(addr)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if rec.State != keystore.StateFunded {
		t.Errorf("state after ObserveFunding = %s, want FUNDED", rec.State)
	}
}

func TestObserveFundingRejectsAlreadyFunded(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, addr); err != nil {
		t.Fatalf("first ObserveFunding failed: %v", err)
	}
	if err := testFundAddress(w, addr); err == nil {
		t.Error("second ObserveFunding on the same address should fail " +
			"(single-use invariant)")
	}
}

// ─── Signing ──────────────────────────────────────────────────────────────────

func TestSignMessageRequiresFundedState(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}

	// addr is FRESH, not FUNDED — SignMessage must refuse.
	_, _, err = w.SignMessage(addr, []byte("test message"))
	if err == nil {
		t.Fatal("SignMessage on a FRESH address should fail")
	}
}

func TestSignAndVerifyMessage(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, addr); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}
	msg := []byte("Symbiont Wallet M1.5 integration test")
	pubKey, sig, err := w.SignMessage(addr, msg)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	if len(pubKey) != 32 {
		t.Errorf("public key length = %d, want 32", len(pubKey))
	}
	if len(sig) != slhdsa.SignatureSize {
		t.Errorf("signature length %d, want exact %d", len(sig), slhdsa.SignatureSize)
	}

	// The returned public key must correspond to the signing address.
	match, err := address.MatchesPublicKey(addr, pubKey)
	if err != nil {
		t.Fatalf("MatchesPublicKey failed: %v", err)
	}
	if !match {
		t.Error("returned public key does not match the signing address")
	}

	// Verify via the stateless top-level verifier.
	ok, err := VerifySignature(msg, sig, pubKey)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !ok {
		t.Fatal("VerifySignature returned false for a valid signature")
	}
}

func TestConcurrentSigningAllowsOnlyOneSuccess(t *testing.T) {
	w := newTestWallet(t)
	addr, _ := w.NextReceiveAddress()
	if err := testFundAddress(w, addr); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := w.SignMessage(addr, []byte("one spend only"))
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent signatures = %d, want exactly 1", successes)
	}
}

func TestVerifySignatureRejectsTamperedMessage(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, addr); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}

	pubKey, sig, err := w.SignMessage(addr, []byte("original message"))
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	ok, err := VerifySignature([]byte("tampered message"), sig, pubKey)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if ok {
		t.Fatal("VerifySignature returned true for a tampered message")
	}
}

// ─── SignTransaction / change routing (M2.1, M1.6 stub) ─────────────────────────

func TestSignTransactionWithValidChange(t *testing.T) {
	w := newTestWallet(t)

	from, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, from); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}

	// The next fresh address (index+1) becomes the change address.
	change, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress (change) failed: %v", err)
	}
	if change == from {
		t.Fatal("change address must differ from the spending address")
	}

	changeHash, err := address.ToHash(change)
	if err != nil {
		t.Fatalf("address.ToHash failed: %v", err)
	}
	changeScript := append([]byte{0x52, 0x20}, changeHash...) // P2QPK scriptPubKey

	tx := QOGETransaction{
		From:   from,
		To:     "qoge1recipientplaceholder",
		Amount: 1000,
		Change: change,
		Outputs: []SpendOutput{
			{Amount: 900, Script: []byte{0x51}}, // recipient output (OP_1 placeholder)
			{Amount: 100, Script: changeScript}, // change output
		},
		MessageID: []byte("tx-001-payload"),
	}

	signed, err := w.SignTransaction(tx)
	if err != nil {
		t.Fatalf("SignTransaction failed: %v", err)
	}
	if len(signed.PublicKey) != 32 {
		t.Errorf("PublicKey length = %d, want 32", len(signed.PublicKey))
	}
	if len(signed.Signature) > slhdsa.SignatureSize {
		t.Errorf("Signature length %d exceeds max %d", len(signed.Signature), slhdsa.SignatureSize)
	}

	ok, err := VerifySignature(tx.MessageID, signed.Signature, signed.PublicKey)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
	if !ok {
		t.Fatal("signed transaction failed verification")
	}
}

// TestSignTransactionRejectsNonFreshChange is the M2.1 invariant test:
// change MUST route to a FRESH address, never to the spending address
// itself or any other non-FRESH address.
func TestSignTransactionRejectsNonFreshChange(t *testing.T) {
	w := newTestWallet(t)

	from, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, from); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}

	tx := QOGETransaction{
		From:      from,
		To:        "qoge1recipientplaceholder",
		Amount:    1000,
		Change:    from, // INVALID: change == spending address (FUNDED, not FRESH)
		MessageID: []byte("tx-002-payload"),
	}

	_, err = w.SignTransaction(tx)
	if err == nil {
		t.Fatal("SignTransaction should reject change routed to a non-FRESH address")
	}
}

// TestSignTransactionRejectsUnknownChangeAddress confirms that a
// well-formed but unknown QOGE address cannot be used as a change address.
func TestSignTransactionRejectsUnknownChangeAddress(t *testing.T) {
	w := newTestWallet(t)

	from, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, from); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}

	// A syntactically valid QOGE address derived from an arbitrary pubkey,
	// but never generated by this wallet's index.
	dummyPub := make([]byte, 32)
	for i := range dummyPub {
		dummyPub[i] = 0xAA
	}
	unknownAddr, err := address.FromPublicKey(dummyPub)
	if err != nil {
		t.Fatalf("address.FromPublicKey failed: %v", err)
	}

	tx := QOGETransaction{
		From:      from,
		To:        "qoge1recipientplaceholder",
		Amount:    1000,
		Change:    unknownAddr,
		MessageID: []byte("tx-003-payload"),
	}

	_, err = w.SignTransaction(tx)
	if err == nil {
		t.Fatal("SignTransaction should reject a change address not present in this wallet's index")
	}
}

// ─── Confirmation / key destruction (M1.5) ───────────────────────────────────

// TestOnConfirmationFlagsWithoutDestroying is the core M1.5 test for the new
// two-stage model: OnConfirmation at any confirmation depth >= 1 flags the
// address SPENT but does NOT destroy the key. EncSeedBlob must still be present.
func TestOnConfirmationFlagsWithoutDestroying(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, addr); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}

	// Sign once while FUNDED (simulating creation of the spend tx).
	if _, _, err := w.SignMessage(addr, []byte("spend tx")); err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	// Confirm at low depth — should flag SPENT without destroying key.
	if err := w.OnConfirmation(addr, 1); err != nil {
		t.Fatalf("OnConfirmation(1) failed: %v", err)
	}

	rec, err := w.index.GetRecord(addr)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if rec.State != keystore.StateSpent {
		t.Errorf("state after OnConfirmation = %s, want SPENT", rec.State)
	}
	if rec.EncSeedBlob == nil {
		t.Error("EncSeedBlob should still be present after OnConfirmation — key must not be destroyed")
	}
}

// TestOnConfirmationNoOpBelowMinConfirmations verifies that OnConfirmation is a
// no-op (returns nil, leaves address SPEND_PENDING) when confirmations < 1.
func TestOnConfirmationNoOpBelowMinConfirmations(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, addr); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}
	if err := testSpendPending(w, addr); err != nil {
		t.Fatalf("mark SPEND_PENDING: %v", err)
	}

	// Only confirmations < 1 (i.e. 0 or negative) are no-ops.
	for _, confs := range []int{0, -1} {
		if err := w.OnConfirmation(addr, confs); err != nil {
			t.Fatalf("OnConfirmation(%d) returned error, want nil no-op: %v", confs, err)
		}
		rec, err := w.index.GetRecord(addr)
		if err != nil {
			t.Fatalf("GetRecord failed: %v", err)
		}
		if rec.State != keystore.StateSpendPending {
			t.Errorf("confirmations=%d: state = %s, want SPEND_PENDING (not yet confirmed in any block)",
				confs, rec.State)
		}
		if rec.EncSeedBlob == nil {
			t.Errorf("confirmations=%d: EncSeedBlob is nil — key was destroyed prematurely", confs)
		}
	}
}

func TestObserveSpendConfirmationTracksZeroThenOneConfirmation(t *testing.T) {
	w := newTestWallet(t)
	addrs := testFreshAddresses(t, w, 2)
	fromAddr, changeAddr := addrs[0], addrs[1]
	if err := testFundAddress(w, fromAddr); err != nil {
		t.Fatal(err)
	}
	params := makeMinimalSpendParams(t, fromAddr, changeAddr)
	if _, _, err := w.SignP2QPKInput(params); err != nil {
		t.Fatalf("SignP2QPKInput: %v", err)
	}
	rec, err := w.index.GetRecord(fromAddr)
	if err != nil {
		t.Fatal(err)
	}
	if rec.SpendTxID == "" {
		t.Fatal("SPEND_PENDING record has no tracked spend txid")
	}
	if changed, err := w.ObserveSpendConfirmation(fromAddr, "unrelated-txid", 1); changed || !errors.Is(err, ErrSpendTxIDMismatch) {
		t.Fatalf("unrelated tx confirmation = (%v, %v), want (false, ErrSpendTxIDMismatch)", changed, err)
	}

	changed, err := w.ObserveSpendConfirmation(fromAddr, rec.SpendTxID, 0)
	if err != nil {
		t.Fatalf("ObserveSpendConfirmation(0): %v", err)
	}
	if changed {
		t.Fatal("zero-confirmation spend transitioned to SPENT")
	}
	rec, _ = w.index.GetRecord(fromAddr)
	if rec.State != keystore.StateSpendPending {
		t.Fatalf("state at zero confirmations = %s, want SPEND_PENDING", rec.State)
	}

	changed, err = w.ObserveSpendConfirmation(fromAddr, rec.SpendTxID, 1)
	if err != nil {
		t.Fatalf("ObserveSpendConfirmation(1): %v", err)
	}
	if !changed {
		t.Fatal("one-confirmation spend did not transition")
	}
	rec, _ = w.index.GetRecord(fromAddr)
	if rec.State != keystore.StateSpent {
		t.Fatalf("state at one confirmation = %s, want SPENT", rec.State)
	}
}

func TestP2QPKTxIDGolden(t *testing.T) {
	var prev [32]byte
	for i := range prev {
		prev[i] = byte(i)
	}
	params := P2QPKSpendParams{
		NVersion:  2,
		NLockTime: 0,
		Inputs: []SpendInput{{
			TxIDLE: prev, Vout: 1, NSequence: 0xffffffff,
		}},
		Outputs: []SpendOutput{{Amount: 1000, Script: []byte{0x51}}},
	}
	const want = "9cdfdcf2411803e1c6b7cb2bcafd3cbbac08c469aacaad9d9725f9768adc9492"
	if got := p2qpkTxID(params); got != want {
		t.Fatalf("p2qpkTxID = %s, want %s", got, want)
	}
}

func TestOnConfirmationRejectsFreshAddress(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}

	// addr is FRESH, never moved to SPEND_PENDING — OnConfirmation must fail.
	if err := w.OnConfirmation(addr, 1); err == nil {
		t.Fatal("OnConfirmation should fail for a FRESH address")
	}
}

func TestOnConfirmationRejectsFundedAddress(t *testing.T) {
	w := newTestWallet(t)
	addr := testFreshAddresses(t, w, 1)[0]
	if err := testFundAddress(w, addr); err != nil {
		t.Fatal(err)
	}
	if err := w.OnConfirmation(addr, 1); !errors.Is(err, keystore.ErrAddressNotPending) {
		t.Fatalf("OnConfirmation(FUNDED) error = %v, want ErrAddressNotPending", err)
	}
	rec, _ := w.index.GetRecord(addr)
	if rec.State != keystore.StateFunded {
		t.Fatalf("state after rejected confirmation = %s, want FUNDED", rec.State)
	}
}

// TestSignMessageAfterSpendFails confirms that once an address is SPENT,
// SignMessage refuses — the address is no longer FUNDED.
func TestSignMessageAfterSpendFails(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, addr); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}
	if err := testSpendPending(w, addr); err != nil {
		t.Fatalf("mark SPEND_PENDING: %v", err)
	}
	if err := w.OnConfirmation(addr, 1); err != nil {
		t.Fatalf("OnConfirmation failed: %v", err)
	}

	_, _, err = w.SignMessage(addr, []byte("attempted reuse"))
	if err == nil {
		t.Fatal("SignMessage on a SPENT address should fail")
	}
}

// ─── PurgeSpentKey ────────────────────────────────────────────────────────────

// TestPurgeSpentKeyRequiresSpentState confirms that PurgeSpentKey rejects
// addresses that are not in SPENT state (FRESH, FUNDED, SPEND_PENDING, or RETIRED).
func TestPurgeSpentKeyRequiresSpentState(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}

	// FRESH — must reject.
	if err := w.PurgeSpentKey(addr, KeyDestructionMinConfirmations); err == nil {
		t.Fatal("PurgeSpentKey on FRESH address should fail")
	}

	if err := testFundAddress(w, addr); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}

	// FUNDED — must reject.
	if err := w.PurgeSpentKey(addr, KeyDestructionMinConfirmations); err == nil {
		t.Fatal("PurgeSpentKey on FUNDED address should fail")
	}
	if err := testSpendPending(w, addr); err != nil {
		t.Fatalf("mark SPEND_PENDING: %v", err)
	}

	if err := w.OnConfirmation(addr, 1); err != nil {
		t.Fatalf("OnConfirmation failed: %v", err)
	}

	// SPENT — must succeed.
	if err := w.PurgeSpentKey(addr, KeyDestructionMinConfirmations); err != nil {
		t.Fatalf("PurgeSpentKey on SPENT address failed: %v", err)
	}

	rec, err := w.index.GetRecord(addr)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if rec.State != keystore.StateRetired {
		t.Errorf("state after PurgeSpentKey = %s, want RETIRED", rec.State)
	}
	if rec.EncSeedBlob != nil {
		t.Error("EncSeedBlob should be nil after PurgeSpentKey")
	}

	// RETIRED — must reject (already done, idempotent re-call must fail).
	if err := w.PurgeSpentKey(addr, KeyDestructionMinConfirmations); err == nil {
		t.Fatal("PurgeSpentKey on already-RETIRED address should fail")
	}
}

// TestPurgeSpentKeyRequiresMinConfirmations confirms that PurgeSpentKey rejects
// the call when the confirmation depth is below keyDestructionMinConfirmations.
func TestPurgeSpentKeyRequiresMinConfirmations(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, addr); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}
	if err := testSpendPending(w, addr); err != nil {
		t.Fatalf("mark SPEND_PENDING: %v", err)
	}
	if err := w.OnConfirmation(addr, 1); err != nil {
		t.Fatalf("OnConfirmation failed: %v", err)
	}

	// One below the threshold — must reject.
	if err := w.PurgeSpentKey(addr, KeyDestructionMinConfirmations-1); err == nil {
		t.Fatalf("PurgeSpentKey with %d confirmations should fail (threshold %d)",
			KeyDestructionMinConfirmations-1, KeyDestructionMinConfirmations)
	}

	// Address must still be SPENT (key not destroyed).
	rec, err := w.index.GetRecord(addr)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if rec.State != keystore.StateSpent {
		t.Errorf("state after rejected PurgeSpentKey = %s, want SPENT", rec.State)
	}
	if rec.EncSeedBlob == nil {
		t.Error("EncSeedBlob should still be present after rejected PurgeSpentKey")
	}

	// At exactly the threshold — must succeed.
	if err := w.PurgeSpentKey(addr, KeyDestructionMinConfirmations); err != nil {
		t.Fatalf("PurgeSpentKey at threshold failed: %v", err)
	}
}

// ─── ListPurgeEligibleAddresses ───────────────────────────────────────────────

// TestListPurgeEligibleAddressesFiltersCorrectly confirms that only SPENT
// addresses meeting the confirmation threshold are returned, and that FRESH,
// FUNDED, SPEND_PENDING, and RETIRED addresses are excluded.
func TestListPurgeEligibleAddressesFiltersCorrectly(t *testing.T) {
	w := newTestWallet(t)

	// addr1: SPENT, eligible (high confirmations)
	addr1, _ := w.NextReceiveAddress()
	testFundAddress(w, addr1)
	testSpendPending(w, addr1)
	w.OnConfirmation(addr1, 1)

	// addr2: SPENT, NOT eligible (low confirmations — will return 0)
	addr2, _ := w.NextReceiveAddress()
	testFundAddress(w, addr2)
	testSpendPending(w, addr2)
	w.OnConfirmation(addr2, 1)

	// addr3: FUNDED (not yet signed)
	addr3, _ := w.NextReceiveAddress()
	testFundAddress(w, addr3)

	// addr4: FRESH (never touched)
	addr4, _ := w.NextReceiveAddress()
	_ = addr4

	// addr5: RETIRED via PurgeSpentKey
	addr5, _ := w.NextReceiveAddress()
	testFundAddress(w, addr5)
	testSpendPending(w, addr5)
	w.OnConfirmation(addr5, 1)
	w.PurgeSpentKey(addr5, KeyDestructionMinConfirmations)

	eligible, err := w.ListPurgeEligibleAddresses(func(addr string) int {
		if addr == addr1 {
			return KeyDestructionMinConfirmations // eligible
		}
		return 0 // not eligible
	})
	if err != nil {
		t.Fatalf("ListPurgeEligibleAddresses failed: %v", err)
	}

	if len(eligible) != 1 {
		t.Fatalf("expected 1 eligible address, got %d: %v", len(eligible), eligible)
	}
	if eligible[0].Address != addr1 {
		t.Errorf("eligible address = %s, want %s", eligible[0].Address, addr1)
	}
	if eligible[0].Confirmations != KeyDestructionMinConfirmations {
		t.Errorf("eligible confirmations = %d, want %d", eligible[0].Confirmations, KeyDestructionMinConfirmations)
	}
}

// ─── SignP2QPKInput change-output enforcement ─────────────────────────────────

// makeMinimalSpendParams constructs a valid P2QPKSpendParams for signing tests.
// SpentUTXOs[0].Script is the P2QPK scriptPubKey for fromAddr; the change
// output script is the P2QPK scriptPubKey for changeAddr. Sighash fields are
// minimal but structurally correct.
func makeMinimalSpendParams(t *testing.T, fromAddr, changeAddr string) P2QPKSpendParams {
	t.Helper()
	fromHash, err := address.ToHash(fromAddr)
	if err != nil {
		t.Fatalf("makeMinimalSpendParams: ToHash(%s): %v", fromAddr, err)
	}
	fromScript := append([]byte{0x52, 0x20}, fromHash...) // OP_2 PUSH32 <hash>
	changeHash, err := address.ToHash(changeAddr)
	if err != nil {
		t.Fatalf("makeMinimalSpendParams: ToHash(%s): %v", changeAddr, err)
	}
	changeScript := append([]byte{0x52, 0x20}, changeHash...) // OP_2 PUSH32 <hash>
	return P2QPKSpendParams{
		NVersion:  1,
		NLockTime: 0,
		Inputs: []SpendInput{
			{Vout: 0, NSequence: 0xffffffff},
		},
		SpentUTXOs: []SpentUTXO{
			{Amount: 100_000, Script: fromScript},
		},
		Outputs: []SpendOutput{
			{Amount: 99_000, Script: changeScript},
		},
		InputIndex: 0,
		FromAddr:   fromAddr,
		ChangeAddr: changeAddr,
	}
}

// makeMinimalSpendParamsNoChangeOutput is the negative-test variant: the
// SpentUTXO script is the correct P2QPK script for fromAddr, but the single
// output uses OP_1 (not a P2QPK script for changeAddr), so SignP2QPKInput
// must reject with ErrChangeOutputMissing.
func makeMinimalSpendParamsNoChangeOutput(t *testing.T, fromAddr, changeAddr string) P2QPKSpendParams {
	t.Helper()
	fromHash, err := address.ToHash(fromAddr)
	if err != nil {
		t.Fatalf("makeMinimalSpendParamsNoChangeOutput: ToHash(%s): %v", fromAddr, err)
	}
	fromScript := append([]byte{0x52, 0x20}, fromHash...) // OP_2 PUSH32 <hash>
	return P2QPKSpendParams{
		NVersion:  1,
		NLockTime: 0,
		Inputs: []SpendInput{
			{Vout: 0, NSequence: 0xffffffff},
		},
		SpentUTXOs: []SpentUTXO{
			{Amount: 100_000, Script: fromScript},
		},
		Outputs: []SpendOutput{
			{Amount: 99_000, Script: []byte{0x51}}, // OP_1, not P2QPK for changeAddr
		},
		InputIndex: 0,
		FromAddr:   fromAddr,
		ChangeAddr: changeAddr,
	}
}

func TestSignP2QPKInputRequiresFundedSource(t *testing.T) {
	states := []keystore.AddressState{
		keystore.StateFresh,
		keystore.StateSpendPending,
		keystore.StateSpent,
		keystore.StateRetired,
	}
	for _, state := range states {
		t.Run(state.String(), func(t *testing.T) {
			w := newTestWallet(t)
			addrs := testFreshAddresses(t, w, 2)
			fromAddr, changeAddr := addrs[0], addrs[1]
			if state != keystore.StateFresh {
				if err := testFundAddress(w, fromAddr); err != nil {
					t.Fatal(err)
				}
				if err := testSpendPending(w, fromAddr); err != nil {
					t.Fatal(err)
				}
			}
			if state == keystore.StateSpent || state == keystore.StateRetired {
				if err := w.OnConfirmation(fromAddr, 1); err != nil {
					t.Fatal(err)
				}
			}
			if state == keystore.StateRetired {
				if err := w.PurgeSpentKey(fromAddr, KeyDestructionMinConfirmations); err != nil {
					t.Fatal(err)
				}
			}

			params := makeMinimalSpendParams(t, fromAddr, changeAddr)
			_, _, err := w.SignP2QPKInput(params)
			if !errors.Is(err, ErrFromAddressNotFunded) {
				t.Fatalf("SignP2QPKInput source %s error = %v, want ErrFromAddressNotFunded", state, err)
			}
			rec, _ := w.index.GetRecord(fromAddr)
			if rec.State != state {
				t.Fatalf("source state after rejection = %s, want %s", rec.State, state)
			}
		})
	}
}

// TestSignP2QPKInputRejectsNonFreshChange confirms that SignP2QPKInput returns
// an error when the ChangeAddr is not in FRESH state.
func TestSignP2QPKInputRejectsNonFreshChange(t *testing.T) {
	w := newTestWallet(t)

	fromAddr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, fromAddr); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}

	// Use fromAddr itself as change — it is FUNDED, not FRESH.
	params := makeMinimalSpendParams(t, fromAddr, fromAddr)
	_, _, err = w.SignP2QPKInput(params)
	if !errors.Is(err, ErrChangeAddressNotFresh) {
		t.Fatalf("SignP2QPKInput error = %v, want ErrChangeAddressNotFresh", err)
	}
}

func TestSignP2QPKInputDistinguishesReservedChange(t *testing.T) {
	w := newTestWallet(t)
	addrs := testFreshAddresses(t, w, 3)
	reservingSource, reservedChange, fromAddr := addrs[0], addrs[1], addrs[2]
	if err := testFundAddress(w, reservingSource); err != nil {
		t.Fatal(err)
	}
	if err := w.index.MarkSpendPendingAndReserveChange(reservingSource, reservedChange, ""); err != nil {
		t.Fatal(err)
	}
	if err := testFundAddress(w, fromAddr); err != nil {
		t.Fatal(err)
	}

	params := makeMinimalSpendParams(t, fromAddr, reservedChange)
	_, _, err := w.SignP2QPKInput(params)
	if !errors.Is(err, ErrChangeAddressReserved) {
		t.Fatalf("SignP2QPKInput error = %v, want ErrChangeAddressReserved", err)
	}
}

// TestSignP2QPKInputTransitionsChangeAfterSigning confirms that after a
// successful SignP2QPKInput, the change address is reserved FRESH,
// so it cannot be reused as change or receive address on a subsequent tx.
func TestSignP2QPKInputTransitionsChangeAfterSigning(t *testing.T) {
	w := newTestWallet(t)

	fromAddr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, fromAddr); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}

	changeAddr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress (change) failed: %v", err)
	}
	if changeAddr == fromAddr {
		t.Fatal("change address must differ from spending address")
	}

	// Confirm change is FRESH before signing.
	changeRec, err := w.index.GetRecord(changeAddr)
	if err != nil {
		t.Fatalf("GetRecord (change, before) failed: %v", err)
	}
	if changeRec.State != keystore.StateFresh {
		t.Fatalf("change address state before signing = %s, want FRESH", changeRec.State)
	}

	params := makeMinimalSpendParams(t, fromAddr, changeAddr)
	pubKey, sig, err := w.SignP2QPKInput(params)
	if err != nil {
		t.Fatalf("SignP2QPKInput failed: %v", err)
	}
	if len(pubKey) != 32 {
		t.Errorf("pubKey length = %d, want 32", len(pubKey))
	}
	if len(sig) != slhdsa.SignatureSize {
		t.Errorf("sig length = %d, want %d", len(sig), slhdsa.SignatureSize)
	}

	// After signing: change remains FRESH but is reserved.
	changeRec, err = w.index.GetRecord(changeAddr)
	if err != nil {
		t.Fatalf("GetRecord (change, after) failed: %v", err)
	}
	if changeRec.State != keystore.StateFresh || !changeRec.Reserved {
		t.Errorf("change address after signing = state %s reserved %v, want FRESH reserved", changeRec.State, changeRec.Reserved)
	}

	// The source is consumed for signing immediately.
	fromRec, err := w.index.GetRecord(fromAddr)
	if err != nil {
		t.Fatalf("GetRecord (from, after) failed: %v", err)
	}
	if fromRec.State != keystore.StateSpendPending {
		t.Errorf("from address state after signing = %s, want SPEND_PENDING", fromRec.State)
	}
}

func TestReservedChangeBecomesFundedThroughObserveFunding(t *testing.T) {
	w := newTestWallet(t)
	addrs := testFreshAddresses(t, w, 2)
	fromAddr, changeAddr := addrs[0], addrs[1]
	if err := testFundAddress(w, fromAddr); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.SignP2QPKInput(makeMinimalSpendParams(t, fromAddr, changeAddr)); err != nil {
		t.Fatal(err)
	}
	before, _ := w.index.GetRecord(changeAddr)
	if before.State != keystore.StateFresh || !before.Reserved {
		t.Fatalf("precondition: change = state %s reserved %v", before.State, before.Reserved)
	}

	changed, err := w.ObserveFunding(changeAddr, 50_000, FundingMinConfirmations)
	if err != nil || !changed {
		t.Fatalf("ObserveFunding reserved change = changed %v err %v", changed, err)
	}
	after, _ := w.index.GetRecord(changeAddr)
	if after.State != keystore.StateFunded || after.Reserved {
		t.Fatalf("change after ObserveFunding = state %s reserved %v, want FUNDED unreserved", after.State, after.Reserved)
	}
}

func TestConcurrentSignP2QPKInputAllowsOnlyOneSuccess(t *testing.T) {
	w := newTestWallet(t)
	addrs := testFreshAddresses(t, w, 2)
	fromAddr, changeAddr := addrs[0], addrs[1]
	if err := testFundAddress(w, fromAddr); err != nil {
		t.Fatal(err)
	}
	params := makeMinimalSpendParams(t, fromAddr, changeAddr)

	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := w.SignP2QPKInput(params)
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	successes, fundedRejections := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrFromAddressNotFunded):
			fundedRejections++
		default:
			t.Fatalf("unexpected concurrent signing error: %v", err)
		}
	}
	if successes != 1 || fundedRejections != 1 {
		t.Fatalf("results: successes=%d funded rejections=%d, want 1 and 1", successes, fundedRejections)
	}
}

// TestSignP2QPKInputRejectsNoMatchingOutput proves the output-binding check:
// signing must fail when ChangeAddr is validly FRESH but no output script
// in the transaction encodes that address as a P2QPK scriptPubKey.
func TestSignP2QPKInputRejectsNoMatchingOutput(t *testing.T) {
	w := newTestWallet(t)

	fromAddr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, fromAddr); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}
	changeAddr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress (change) failed: %v", err)
	}

	// Params have a valid FRESH changeAddr but the single output uses OP_1
	// (0x51), not the P2QPK script for changeAddr.
	params := makeMinimalSpendParamsNoChangeOutput(t, fromAddr, changeAddr)
	_, _, err = w.SignP2QPKInput(params)
	if err == nil {
		t.Fatal("SignP2QPKInput should reject when no output pays to the change address")
	}

	// Change address must remain FRESH — signing must not have transitioned it.
	rec, err := w.index.GetRecord(changeAddr)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if rec.State != keystore.StateFresh {
		t.Errorf("change address state after rejected sign = %s, want FRESH", rec.State)
	}
}

// TestSignP2QPKInputRejectsMismatchedFromScript confirms that SignP2QPKInput
// rejects params where SpentUTXOs[InputIndex].Script does not match the
// P2QPK scriptPubKey derived from FromAddr.
func TestSignP2QPKInputRejectsMismatchedFromScript(t *testing.T) {
	w := newTestWallet(t)

	fromAddr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, fromAddr); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}
	changeAddr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress (change) failed: %v", err)
	}

	// Build valid params via makeMinimalSpendParams, then overwrite the UTXO
	// script with OP_1 — simulating a caller that passes a mismatched UTXO.
	params := makeMinimalSpendParams(t, fromAddr, changeAddr)
	params.SpentUTXOs[0].Script = []byte{0x51} // wrong: not the P2QPK script for fromAddr

	_, _, err = w.SignP2QPKInput(params)
	if err == nil {
		t.Fatal("SignP2QPKInput should reject when SpentUTXOs[InputIndex].Script does not match FromAddr")
	}
	if !errors.Is(err, ErrFromAddrScriptMismatch) {
		t.Errorf("expected ErrFromAddrScriptMismatch, got: %v", err)
	}

	// fromAddr must still be FUNDED — rejected signing must not advance its state.
	rec, err := w.index.GetRecord(fromAddr)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if rec.State != keystore.StateFunded {
		t.Errorf("fromAddr state after rejected sign = %s, want FUNDED", rec.State)
	}
}

// TestOnConfirmationRefillsPool confirms M2.2 pool refill behaviour:
// after one address is spent, the FRESH pool is topped back up to
// PreGenPoolSize.
func TestOnConfirmationRefillsPool(t *testing.T) {
	w := newTestWallet(t)

	before, err := w.index.CountByState(keystore.StateFresh)
	if err != nil {
		t.Fatalf("CountByState failed: %v", err)
	}
	if before != PreGenPoolSize {
		t.Fatalf("precondition failed: FRESH count = %d, want %d", before, PreGenPoolSize)
	}

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, addr); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}

	// Funding detection immediately refills the available FRESH pool.
	mid, err := w.index.CountByState(keystore.StateFresh)
	if err != nil {
		t.Fatalf("CountByState failed: %v", err)
	}
	if mid != PreGenPoolSize {
		t.Errorf("FRESH count after funding detection = %d, want %d", mid, PreGenPoolSize)
	}
	if err := testSpendPending(w, addr); err != nil {
		t.Fatalf("mark SPEND_PENDING: %v", err)
	}

	if err := w.OnConfirmation(addr, 1); err != nil {
		t.Fatalf("OnConfirmation failed: %v", err)
	}

	after, err := w.index.CountByState(keystore.StateFresh)
	if err != nil {
		t.Fatalf("CountByState failed: %v", err)
	}
	if after != PreGenPoolSize {
		t.Errorf("FRESH count after OnConfirmation (refill) = %d, want %d", after, PreGenPoolSize)
	}
}

// ─── Full lifecycle ─────────────────────────────────────────────────────────────

// TestFullSymbiontLifecycle runs the entire Symbiont Wallet flow end to end:
// receive -> sign -> confirm -> verify retirement -> confirm address never
// reappears as a receive address.
func TestFullSymbiontLifecycle(t *testing.T) {
	w := newTestWallet(t)

	// 1. Get a receive address and simulate an incoming payment.
	receiveAddr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := testFundAddress(w, receiveAddr); err != nil {
		t.Fatalf("ObserveFunding failed: %v", err)
	}

	// 2. Spend: sign a transaction, change to a fresh address.
	changeAddr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress (change) failed: %v", err)
	}
	changeHash, err := address.ToHash(changeAddr)
	if err != nil {
		t.Fatalf("address.ToHash failed: %v", err)
	}
	tx := QOGETransaction{
		From:   receiveAddr,
		To:     "qoge1recipientplaceholder",
		Amount: 5000,
		Change: changeAddr,
		Outputs: []SpendOutput{
			{Amount: 4900, Script: []byte{0x51}},
			{Amount: 100, Script: append([]byte{0x52, 0x20}, changeHash...)},
		},
		MessageID: []byte("full-lifecycle-tx"),
	}
	signed, err := w.SignTransaction(tx)
	if err != nil {
		t.Fatalf("SignTransaction failed: %v", err)
	}
	ok, err := VerifySignature(tx.MessageID, signed.Signature, signed.PublicKey)
	if err != nil || !ok {
		t.Fatalf("transaction signature invalid: ok=%v err=%v", ok, err)
	}

	// 3. Confirm: flags address SPENT (no key destruction yet).
	if err := w.OnConfirmation(receiveAddr, 1); err != nil {
		t.Fatalf("OnConfirmation failed: %v", err)
	}
	rec, err := w.index.GetRecord(receiveAddr)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if rec.State != keystore.StateSpent {
		t.Fatalf("receive address state after OnConfirmation = %s, want SPENT", rec.State)
	}
	if rec.EncSeedBlob == nil {
		t.Fatal("EncSeedBlob should still be present after OnConfirmation (key not yet destroyed)")
	}

	// 3b. Explicitly purge the key once deeply confirmed.
	if err := w.PurgeSpentKey(receiveAddr, KeyDestructionMinConfirmations); err != nil {
		t.Fatalf("PurgeSpentKey failed: %v", err)
	}
	rec, err = w.index.GetRecord(receiveAddr)
	if err != nil {
		t.Fatalf("GetRecord (after purge) failed: %v", err)
	}
	if rec.State != keystore.StateRetired || rec.EncSeedBlob != nil {
		t.Fatalf("receive address not properly retired after PurgeSpentKey: state=%s, encSeed=%v",
			rec.State, rec.EncSeedBlob != nil)
	}

	// 4. The spent/retired address must never be handed out again.
	for i := 0; i < PreGenPoolSize*2; i++ {
		addr, err := w.NextReceiveAddress()
		if err != nil {
			t.Fatalf("NextReceiveAddress failed: %v", err)
		}
		if addr == receiveAddr {
			t.Fatal("spent address was returned by NextReceiveAddress — single-use invariant violated")
		}
		// Use it up so the loop advances to the next FRESH address.
		if err := testFundAddress(w, addr); err != nil {
			t.Fatalf("ObserveFunding failed: %v", err)
		}
		if err := testSpendPending(w, addr); err != nil {
			t.Fatalf("mark SPEND_PENDING: %v", err)
		}
		if err := w.OnConfirmation(addr, 1); err != nil {
			t.Fatalf("OnConfirmation failed: %v", err)
		}
	}
}

// TestP2QPKSighashCrossValidationVector pins computeP2QPKSighash against the
// independently-verified reference value from SIP-QOGE-PQC-02a §6 Open Item 2.
//
// Source transaction: BIP341 keyPathSpending[0]
// (src/test/data/bip341_wallet_vectors.json in qogecoin/qogecoin).
// Intermediate hashes and final sighash were computed in Phase C (Python),
// cross-validated against BIP341 TapSighash, and independently recomputed
// by GPT-5.5 Thinking (20 June 2026). All three agree on 8a17f83e...
//
// This is a pure-function test — no wallet DB, no CGo, no key material.
func TestP2QPKSighashCrossValidationVector(t *testing.T) {
	hx := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("bad hex in test data %q: %v", s, err)
		}
		return b
	}
	txLE := func(s string) [32]byte {
		b := hx(s)
		if len(b) != 32 {
			t.Fatalf("txid hex %q decoded to %d bytes, want 32", s, len(b))
		}
		var arr [32]byte
		copy(arr[:], b)
		return arr
	}

	// BIP341 keyPathSpending[0]: 9 inputs, 9 spent UTXOs, 2 outputs.
	// nVersion=2, nLockTime=500000000, in_pos=0 (signing input 0).
	params := P2QPKSpendParams{
		NVersion:  2,
		NLockTime: 500_000_000,
		Inputs: []SpendInput{
			{TxIDLE: txLE("7de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c"), Vout: 1, NSequence: 0x00000000},
			{TxIDLE: txLE("d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd99"), Vout: 0, NSequence: 0xffffffff},
			{TxIDLE: txLE("f8e1f583384333689228c5d28eac13366be082dc57441760d957275419a41842"), Vout: 0, NSequence: 0xffffffff},
			{TxIDLE: txLE("f0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b"), Vout: 1, NSequence: 0xfffffffe},
			{TxIDLE: txLE("aa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c"), Vout: 0, NSequence: 0xfffffffe},
			{TxIDLE: txLE("956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050"), Vout: 0, NSequence: 0x00000000},
			{TxIDLE: txLE("e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94"), Vout: 1, NSequence: 0x00000000},
			{TxIDLE: txLE("e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf"), Vout: 0, NSequence: 0xffffffff},
			{TxIDLE: txLE("a778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af1"), Vout: 1, NSequence: 0xffffffff},
		},
		SpentUTXOs: []SpentUTXO{
			{Amount: 420_000_000, Script: hx("512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343")},
			{Amount: 462_000_000, Script: hx("5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3")},
			{Amount: 294_000_000, Script: hx("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac")},
			{Amount: 504_000_000, Script: hx("5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e")},
			{Amount: 630_000_000, Script: hx("512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605")},
			{Amount: 378_000_000, Script: hx("00147dd65592d0ab2fe0d0257d571abf032cd9db93dc")},
			{Amount: 672_000_000, Script: hx("512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831")},
			{Amount: 546_000_000, Script: hx("5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5")},
			{Amount: 588_000_000, Script: hx("512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220")},
		},
		Outputs: []SpendOutput{
			{Amount: 1_000_000_000, Script: hx("76a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac")},
			{Amount: 3_410_000_000, Script: hx("ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b")},
		},
		InputIndex: 0,
		FromAddr:   "", // not accessed by computeP2QPKSighash
	}

	got, err := computeP2QPKSighash(params)
	if err != nil {
		t.Fatalf("computeP2QPKSighash: %v", err)
	}

	const want = "8a17f83ed68457d5469f4bbcfc68ddaeaa70739522c1b6fb76685ba7b2008c38"
	if gotHex := hex.EncodeToString(got); gotHex != want {
		t.Fatalf("P2QPKSighash mismatch:\n  got:  %s\n  want: %s\n  (SIP-QOGE-PQC-02a §6 Open Item 2 reference value)",
			gotHex, want)
	}
}

// ─── M1.3 deterministic keygen ───────────────────────────────────────────────

// TestDeriveAddressDeterministic confirms that the same master seed always
// produces the same first address across two independent wallet instances.
// This is the end-to-end check of M1.3: master seed → HKDF 48-byte child seed
// → NewSignerFromSeed → same public key → same QOGE address.
func TestDeriveAddressDeterministic(t *testing.T) {
	masterSeed := make([]byte, 32)
	for i := range masterSeed {
		masterSeed[i] = byte(i + 1)
	}

	// First wallet instance.
	dbPath1 := filepath.Join(t.TempDir(), "wallet1.db")
	w1, err := CreateNew(dbPath1, append([]byte(nil), masterSeed...))
	if err != nil {
		t.Fatalf("CreateNew (w1): %v", err)
	}
	addr1, err := w1.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress (w1): %v", err)
	}
	w1.Close()

	// Second wallet instance with the same seed.
	dbPath2 := filepath.Join(t.TempDir(), "wallet2.db")
	w2, err := CreateNew(dbPath2, append([]byte(nil), masterSeed...))
	if err != nil {
		t.Fatalf("CreateNew (w2): %v", err)
	}
	addr2, err := w2.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress (w2): %v", err)
	}
	w2.Close()

	if addr1 != addr2 {
		t.Errorf("deriveAddress not deterministic:\n  wallet1: %s\n  wallet2: %s", addr1, addr2)
	}
	t.Logf("deterministic address for seed [1..32] at index 0: %s", addr1)
}

// ─── ListAddresses ────────────────────────────────────────────────────────────

// TestListAddresses_EmptyWallet confirms that a freshly opened wallet returns
// only FRESH pre-generated addresses (the PreGenPoolSize pool), with no
// FUNDED/SPEND_PENDING/SPENT/RETIRED entries.
func TestListAddresses_EmptyWallet(t *testing.T) {
	w := newTestWallet(t)
	infos, err := w.ListAddresses()
	if err != nil {
		t.Fatalf("ListAddresses: %v", err)
	}
	if len(infos) != PreGenPoolSize {
		t.Fatalf("len(ListAddresses) = %d, want %d (PreGenPoolSize)", len(infos), PreGenPoolSize)
	}
	for i, info := range infos {
		if info.State != keystore.StateFresh {
			t.Errorf("infos[%d].State = %s, want FRESH", i, info.State)
		}
		if info.Address == "" {
			t.Errorf("infos[%d].Address is empty", i)
		}
		if i > 0 && infos[i].Index <= infos[i-1].Index {
			t.Errorf("infos not sorted by index ascending: infos[%d].Index=%d <= infos[%d].Index=%d",
				i, infos[i].Index, i-1, infos[i-1].Index)
		}
	}
}

// TestListAddresses_StateTransitions confirms that after generating addresses
// and transitioning some through ObserveFunding and OnConfirmation, the
// list accurately reflects each address's current state.
//
// NextReceiveAddress is a peek — it always returns the lowest-index FRESH
// address. To obtain three distinct addresses we must advance each one out
// of FRESH before requesting the next.
func TestListAddresses_StateTransitions(t *testing.T) {
	w := newTestWallet(t)

	// addr0: peek, then advance to FUNDED.
	addr0, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress 0: %v", err)
	}
	if err := testFundAddress(w, addr0); err != nil {
		t.Fatalf("ObserveFunding addr0: %v", err)
	}

	// addr1: peek (now the next FRESH), then advance through FUNDED and SPEND_PENDING to SPENT.
	addr1, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress 1: %v", err)
	}
	if err := testFundAddress(w, addr1); err != nil {
		t.Fatalf("ObserveFunding addr1: %v", err)
	}
	if err := testSpendPending(w, addr1); err != nil {
		t.Fatalf("mark SPEND_PENDING addr1: %v", err)
	}
	if err := w.OnConfirmation(addr1, 1); err != nil {
		t.Fatalf("OnConfirmation addr1: %v", err)
	}

	// addr2: peek (next FRESH after addr1 was advanced); leave it FRESH.
	addr2, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress 2: %v", err)
	}
	_ = addr2

	infos, err := w.ListAddresses()
	if err != nil {
		t.Fatalf("ListAddresses: %v", err)
	}

	// Build a map from address string to AddressInfo for easy lookup.
	byAddr := make(map[string]AddressInfo)
	for _, info := range infos {
		byAddr[info.Address] = info
	}

	if got := byAddr[addr0].State; got != keystore.StateFunded {
		t.Errorf("addr0 state = %s, want FUNDED", got)
	}
	if got := byAddr[addr1].State; got != keystore.StateSpent {
		t.Errorf("addr1 state = %s, want SPENT", got)
	}
	if got := byAddr[addr2].State; got != keystore.StateFresh {
		t.Errorf("addr2 state = %s, want FRESH", got)
	}
}

// TestListAddresses_IncludesRetired confirms that RETIRED addresses (after key
// purge) remain visible in the list — the address string and state are
// retained in the DB permanently; only the private key is zeroed.
func TestListAddresses_IncludesRetired(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress: %v", err)
	}
	if err := testFundAddress(w, addr); err != nil {
		t.Fatalf("ObserveFunding: %v", err)
	}
	if err := testSpendPending(w, addr); err != nil {
		t.Fatalf("mark SPEND_PENDING: %v", err)
	}
	if err := w.OnConfirmation(addr, 1); err != nil {
		t.Fatalf("OnConfirmation: %v", err)
	}
	// 101 confirmations required for key destruction.
	if err := w.PurgeSpentKey(addr, 101); err != nil {
		t.Fatalf("PurgeSpentKey: %v", err)
	}

	infos, err := w.ListAddresses()
	if err != nil {
		t.Fatalf("ListAddresses: %v", err)
	}
	var found bool
	for _, info := range infos {
		if info.Address == addr {
			found = true
			if info.State != keystore.StateRetired {
				t.Errorf("retired address state = %s, want RETIRED", info.State)
			}
		}
	}
	if !found {
		t.Errorf("retired address %s not found in ListAddresses — RETIRED must be included", addr)
	}
}

// ── Fix 3: no-change signing path ────────────────────────────────────────────

// makeNoChangeSpendParams builds valid P2QPKSpendParams with ChangeAddr == ""
// and exactly one output (the recipient), modelling an exact-spend transaction
// where the UTXO covers send + fee with zero remainder.
func makeNoChangeSpendParams(t *testing.T, fromAddr, toAddr string) P2QPKSpendParams {
	t.Helper()
	fromHash, err := address.ToHash(fromAddr)
	if err != nil {
		t.Fatalf("makeNoChangeSpendParams: ToHash(%s): %v", fromAddr, err)
	}
	fromScript := append([]byte{0x52, 0x20}, fromHash...)
	toHash, err := address.ToHash(toAddr)
	if err != nil {
		t.Fatalf("makeNoChangeSpendParams: ToHash(%s): %v", toAddr, err)
	}
	toScript := append([]byte{0x52, 0x20}, toHash...)
	return P2QPKSpendParams{
		NVersion:  2,
		NLockTime: 0,
		Inputs:    []SpendInput{{Vout: 0, NSequence: 0xffffffff}},
		SpentUTXOs: []SpentUTXO{
			{Amount: 100_010_000, Script: fromScript}, // send 100_000_000 + fee 10_000
		},
		Outputs:    []SpendOutput{{Amount: 100_000_000, Script: toScript}},
		InputIndex: 0,
		FromAddr:   fromAddr,
		ChangeAddr: "", // exact spend — no change
	}
}

// TestSignP2QPKInputNoChange confirms that SignP2QPKInput accepts ChangeAddr == ""
// for an exact-spend transaction (zero change remainder), produces a valid
// signature, and does NOT transition any address beyond the from address.
func TestSignP2QPKInputNoChange(t *testing.T) {
	w := newTestWallet(t)

	fromAddr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress: %v", err)
	}
	if err := testFundAddress(w, fromAddr); err != nil {
		t.Fatalf("ObserveFunding: %v", err)
	}

	// Use a second address as the recipient — it stays FRESH (it's not consumed).
	toAddr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress (to): %v", err)
	}

	freshBefore, err := w.index.CountByState(keystore.StateFresh)
	if err != nil {
		t.Fatalf("CountByState FRESH: %v", err)
	}

	params := makeNoChangeSpendParams(t, fromAddr, toAddr)
	pubKey, sig, err := w.SignP2QPKInput(params)
	if err != nil {
		t.Fatalf("SignP2QPKInput (no change): %v", err)
	}
	if len(pubKey) != 32 {
		t.Errorf("pubKey len = %d, want 32", len(pubKey))
	}
	if len(sig) != 17088 {
		t.Errorf("sig len = %d, want 17088", len(sig))
	}

	// fromAddr moves to SPEND_PENDING after signing.
	rec, err := w.index.GetRecord(fromAddr)
	if err != nil {
		t.Fatalf("GetRecord fromAddr: %v", err)
	}
	if rec.State != keystore.StateSpendPending {
		t.Errorf("fromAddr state = %s after no-change sign, want SPEND_PENDING", rec.State)
	}

	// Only the source should be SPEND_PENDING (there is no change reservation).
	spendPendingCount, err := w.index.CountByState(keystore.StateSpendPending)
	if err != nil {
		t.Fatalf("CountByState SPEND_PENDING: %v", err)
	}
	if spendPendingCount != 1 {
		t.Errorf("SPEND_PENDING count = %d after no-change sign, want 1 (only fromAddr)", spendPendingCount)
	}

	// FRESH count must be unchanged — no change address was consumed.
	freshAfter, err := w.index.CountByState(keystore.StateFresh)
	if err != nil {
		t.Fatalf("CountByState FRESH: %v", err)
	}
	if freshAfter != freshBefore {
		t.Errorf("FRESH count changed from %d to %d during no-change sign", freshBefore, freshAfter)
	}
}

// TestSignP2QPKInputNoChangeRejectsMultipleOutputs confirms that SignP2QPKInput
// rejects a no-change transaction that has more than one output.
func TestSignP2QPKInputNoChangeRejectsMultipleOutputs(t *testing.T) {
	w := newTestWallet(t)

	fromAddr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress: %v", err)
	}
	if err := testFundAddress(w, fromAddr); err != nil {
		t.Fatalf("ObserveFunding: %v", err)
	}
	toAddr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress (to): %v", err)
	}

	params := makeNoChangeSpendParams(t, fromAddr, toAddr)
	// Add a spurious second output — must be rejected.
	toHash, _ := address.ToHash(toAddr)
	params.Outputs = append(params.Outputs, SpendOutput{
		Amount: 1_000,
		Script: append([]byte{0x52, 0x20}, toHash...),
	})

	_, _, err = w.SignP2QPKInput(params)
	if err == nil {
		t.Fatal("expected error for no-change tx with 2 outputs, got nil")
	}
}
