package wallet

import (
	"path/filepath"
	"testing"

	"github.com/saogen/qoge-sphincs-wallet/address"
	"github.com/saogen/qoge-sphincs-wallet/keystore"
	"github.com/saogen/qoge-sphincs-wallet/signer"
)

// NOTE: These tests exercise the full Symbiont Wallet stack, including the
// signer package (CGo -> liboqs SLH-DSA-SHA2-128f). Each call to New()
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
	w, err := New(dbPath, seed)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	t.Cleanup(func() {
		w.Close()
	})
	return w
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

// TestNewWalletPreGeneratesPool confirms M2.2: on Open, the wallet
// pre-generates PreGenPoolSize FRESH addresses.
func TestNewWalletPreGeneratesPool(t *testing.T) {
	w := newTestWallet(t)

	count, err := w.index.CountByState(keystore.StateFresh)
	if err != nil {
		t.Fatalf("CountByState failed: %v", err)
	}
	if count != PreGenPoolSize {
		t.Errorf("FRESH address count after New() = %d, want %d", count, PreGenPoolSize)
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

	// Calling NextReceiveAddress repeatedly WITHOUT MarkPaymentReceived
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
			"(%s vs %s) without an intervening MarkPaymentReceived", addr1, addr2)
	}

	after, _ := w.index.CountByState(keystore.StateFresh)
	if before != after {
		t.Errorf("FRESH count changed from %d to %d without MarkPaymentReceived", before, after)
	}
}

// ─── Payment received ────────────────────────────────────────────────────────

func TestMarkPaymentReceivedTransitionsState(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := w.MarkPaymentReceived(addr); err != nil {
		t.Fatalf("MarkPaymentReceived failed: %v", err)
	}

	rec, err := w.index.GetRecord(addr)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if rec.State != keystore.StatePending {
		t.Errorf("state after MarkPaymentReceived = %s, want PENDING", rec.State)
	}
}

func TestMarkPaymentReceivedTwiceFails(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := w.MarkPaymentReceived(addr); err != nil {
		t.Fatalf("first MarkPaymentReceived failed: %v", err)
	}
	if err := w.MarkPaymentReceived(addr); err == nil {
		t.Error("second MarkPaymentReceived on the same address should fail " +
			"(single-use invariant)")
	}
}

// ─── Signing ──────────────────────────────────────────────────────────────────

func TestSignMessageRequiresPendingState(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}

	// addr is FRESH, not PENDING — SignMessage must refuse.
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
	if err := w.MarkPaymentReceived(addr); err != nil {
		t.Fatalf("MarkPaymentReceived failed: %v", err)
	}

	msg := []byte("Symbiont Wallet M1.5 integration test")
	pubKey, sig, err := w.SignMessage(addr, msg)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	if len(pubKey) != 32 {
		t.Errorf("public key length = %d, want 32", len(pubKey))
	}
	if len(sig) > slhdsa.SignatureSize {
		t.Errorf("signature length %d exceeds max %d", len(sig), slhdsa.SignatureSize)
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

func TestVerifySignatureRejectsTamperedMessage(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := w.MarkPaymentReceived(addr); err != nil {
		t.Fatalf("MarkPaymentReceived failed: %v", err)
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
	if err := w.MarkPaymentReceived(from); err != nil {
		t.Fatalf("MarkPaymentReceived failed: %v", err)
	}

	// The next fresh address (index+1) becomes the change address.
	change, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress (change) failed: %v", err)
	}
	if change == from {
		t.Fatal("change address must differ from the spending address")
	}

	tx := QOGETransaction{
		From:      from,
		To:        "qoge1recipientplaceholder",
		Amount:    1000,
		Change:    change,
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
	if err := w.MarkPaymentReceived(from); err != nil {
		t.Fatalf("MarkPaymentReceived failed: %v", err)
	}

	tx := QOGETransaction{
		From:      from,
		To:        "qoge1recipientplaceholder",
		Amount:    1000,
		Change:    from, // INVALID: change == spending address (now PENDING, not FRESH)
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
	if err := w.MarkPaymentReceived(from); err != nil {
		t.Fatalf("MarkPaymentReceived failed: %v", err)
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

// TestOnConfirmationRetiresAndZeroesKey is the core M1.5 test: after
// confirmation, the address must be RETIRED and its encrypted seed blob
// must be gone.
func TestOnConfirmationRetiresAndZeroesKey(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := w.MarkPaymentReceived(addr); err != nil {
		t.Fatalf("MarkPaymentReceived failed: %v", err)
	}

	// Sign once while PENDING (simulating broadcasting the spend tx).
	if _, _, err := w.SignMessage(addr, []byte("spend tx")); err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	if err := w.OnConfirmation(addr); err != nil {
		t.Fatalf("OnConfirmation failed: %v", err)
	}

	rec, err := w.index.GetRecord(addr)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if rec.State != keystore.StateRetired {
		t.Errorf("state after OnConfirmation = %s, want RETIRED", rec.State)
	}
	if rec.EncSeedBlob != nil {
		t.Error("EncSeedBlob should be nil after OnConfirmation — key must be destroyed")
	}
}

func TestOnConfirmationFailsForNonPendingAddress(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}

	// addr is FRESH, never marked PENDING — OnConfirmation must fail.
	if err := w.OnConfirmation(addr); err == nil {
		t.Fatal("OnConfirmation should fail for a non-PENDING address")
	}
}

// TestSignMessageAfterRetirementFails confirms that once an address is
// RETIRED, its key is truly gone — SignMessage cannot resurrect it.
func TestSignMessageAfterRetirementFails(t *testing.T) {
	w := newTestWallet(t)

	addr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress failed: %v", err)
	}
	if err := w.MarkPaymentReceived(addr); err != nil {
		t.Fatalf("MarkPaymentReceived failed: %v", err)
	}
	if err := w.OnConfirmation(addr); err != nil {
		t.Fatalf("OnConfirmation failed: %v", err)
	}

	_, _, err = w.SignMessage(addr, []byte("attempted reuse"))
	if err == nil {
		t.Fatal("SignMessage on a RETIRED address should fail")
	}
}

// TestOnConfirmationRefillsPool confirms M2.2 pool refill behaviour:
// after one address is retired, the FRESH pool is topped back up to
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
	if err := w.MarkPaymentReceived(addr); err != nil {
		t.Fatalf("MarkPaymentReceived failed: %v", err)
	}

	// Pool should have dropped by 1 (one address now PENDING, not FRESH).
	mid, err := w.index.CountByState(keystore.StateFresh)
	if err != nil {
		t.Fatalf("CountByState failed: %v", err)
	}
	if mid != PreGenPoolSize-1 {
		t.Errorf("FRESH count after MarkPaymentReceived = %d, want %d", mid, PreGenPoolSize-1)
	}

	if err := w.OnConfirmation(addr); err != nil {
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
	if err := w.MarkPaymentReceived(receiveAddr); err != nil {
		t.Fatalf("MarkPaymentReceived failed: %v", err)
	}

	// 2. Spend: sign a transaction, change to a fresh address.
	changeAddr, err := w.NextReceiveAddress()
	if err != nil {
		t.Fatalf("NextReceiveAddress (change) failed: %v", err)
	}
	tx := QOGETransaction{
		From:      receiveAddr,
		To:        "qoge1recipientplaceholder",
		Amount:    5000,
		Change:    changeAddr,
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

	// 3. Confirm: key destroyed, address retired.
	if err := w.OnConfirmation(receiveAddr); err != nil {
		t.Fatalf("OnConfirmation failed: %v", err)
	}
	rec, err := w.index.GetRecord(receiveAddr)
	if err != nil {
		t.Fatalf("GetRecord failed: %v", err)
	}
	if rec.State != keystore.StateRetired || rec.EncSeedBlob != nil {
		t.Fatalf("receive address not properly retired: state=%s, encSeed=%v",
			rec.State, rec.EncSeedBlob != nil)
	}

	// 4. The retired address must never be handed out again.
	for i := 0; i < PreGenPoolSize*2; i++ {
		addr, err := w.NextReceiveAddress()
		if err != nil {
			t.Fatalf("NextReceiveAddress failed: %v", err)
		}
		if addr == receiveAddr {
			t.Fatal("retired address was returned by NextReceiveAddress — single-use invariant violated")
		}
		// Use it up so the loop advances to the next FRESH address.
		if err := w.MarkPaymentReceived(addr); err != nil {
			t.Fatalf("MarkPaymentReceived failed: %v", err)
		}
		if err := w.OnConfirmation(addr); err != nil {
			t.Fatalf("OnConfirmation failed: %v", err)
		}
	}
}
