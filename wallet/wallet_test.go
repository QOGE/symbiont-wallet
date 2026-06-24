package wallet

import (
	"encoding/hex"
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
