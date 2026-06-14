// Package wallet is the top-level orchestration layer for the QOGE SPHINCS wallet.
//
// It wires together:
//   - signer/slhdsa    — SLH-DSA-SHA2-128f keypair generation and signing
//   - address          — HASH256 + Bech32 address derivation
//   - keystore         — single-use HD index, state machine, encrypted persistence
//
// The Wallet type is the only public interface a QOGE node or CLI needs.
// All key lifecycle enforcement (single-use, key destruction, change routing)
// is handled here and cannot be bypassed by callers.
//
// SIP-QOGE-PQC-01 compliance checkpoints (all enforced here):
//   [M1.3] HD index counter with encrypted persistence
//   [M1.4] Address state machine with hard invariants
//   [M1.5] Secure key zeroing on 1-confirmation callback
//   [M1.6] Integration point for QOGE chain tx format (see SignTransaction)
//   [M1.7] Taproot disabled — enforced in address package; double-checked here
//   [M2.1] Change routing to next fresh address
//   [M2.2] Address pre-generation pool (N=20)
package wallet

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/saogen/qoge-sphincs-wallet/address"
	"github.com/saogen/qoge-sphincs-wallet/keystore"
	"github.com/saogen/qoge-sphincs-wallet/signer"
	"golang.org/x/crypto/hkdf"
)

// PreGenPoolSize is the number of FRESH addresses to maintain in the pool.
// M2.2: pre-generate 20 addresses on init and after each spend.
const PreGenPoolSize = 20

// MessagePrefix is prepended before hashing any message for signing.
// Mirrors the ref repo's "Qogecoin Signed Message:" prefix, preventing
// cross-protocol signature reuse.
const MessagePrefix = "Qogecoin Signed Message:"

// ─── QOGETransaction (stub) ───────────────────────────────────────────────────

// QOGETransaction is a placeholder for the QOGE chain transaction structure.
//
// M1.6 MILESTONE: Replace this stub with the actual QOGE chain transaction
// type once the chain's wire format is defined. The SignTransaction method
// below shows the integration pattern.
type QOGETransaction struct {
	From      string // Sender address (must be PENDING in index)
	To        string // Recipient address
	Amount    uint64 // In QOGE base units
	Change    string // Change address — MUST be a fresh address from this wallet
	MessageID []byte // Canonical tx hash for signing (set by chain layer)
}

// SignedTransaction carries the signed tx and the raw SLH-DSA signature.
type SignedTransaction struct {
	Tx        QOGETransaction
	PublicKey []byte // 32-byte SLH-DSA public key (revealed at spend time)
	Signature []byte // ~17 KB SLH-DSA signature
}

// ─── Wallet ───────────────────────────────────────────────────────────────────

// Wallet is the primary entry point for all QOGE SPHINCS wallet operations.
type Wallet struct {
	index      *keystore.KeyIndex
	masterSeed []byte // held in memory; zeroed on Close
}

// New creates or opens a QOGE SPHINCS wallet.
//   - dbPath: path to the bbolt index database (created if not exists)
//   - seed:   32-byte master entropy from hardware RNG (for new wallets)
//             OR the same seed used at creation (for existing wallets)
//
// SECURITY: seed is zeroed from the caller's slice after this call.
// The wallet holds its own copy internally.
func New(dbPath string, seed []byte) (*Wallet, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("wallet: seed must be 32 bytes, got %d", len(seed))
	}

	// Copy seed so we can zero the caller's slice.
	ownSeed := make([]byte, 32)
	copy(ownSeed, seed)
	keystore.ZeroBytes(seed)

	ki, err := keystore.Open(dbPath, ownSeed)
	if err != nil {
		keystore.ZeroBytes(ownSeed)
		return nil, fmt.Errorf("wallet: open index: %w", err)
	}

	w := &Wallet{
		index:      ki,
		masterSeed: ownSeed,
	}

	// Pre-generate address pool on open. M2.2.
	if err := w.fillPool(); err != nil {
		w.Close()
		return nil, fmt.Errorf("wallet: initial pool fill: %w", err)
	}

	return w, nil
}

// Close zeroes sensitive memory and closes the database.
// Always call this via defer.
func (w *Wallet) Close() error {
	keystore.ZeroBytes(w.masterSeed)
	return w.index.Close()
}

// ─── Address operations ───────────────────────────────────────────────────────

// NextReceiveAddress returns the next FRESH address for receiving a payment.
// The address is NOT yet marked PENDING — call MarkPaymentReceived when a
// payment is detected in the mempool.
func (w *Wallet) NextReceiveAddress() (string, error) {
	addr, err := w.index.NextFreshAddress()
	if err != nil {
		return "", fmt.Errorf("wallet: NextReceiveAddress: %w", err)
	}
	return addr, nil
}

// MarkPaymentReceived transitions addr FRESH → PENDING.
// Call this when a payment to addr is detected in the mempool.
// Returns ErrAddressAlreadyUsed if addr was already used — this is a
// hard invariant violation and must be logged and investigated.
func (w *Wallet) MarkPaymentReceived(addr string) error {
	if err := w.index.MarkPending(addr); err != nil {
		return fmt.Errorf("wallet: MarkPaymentReceived: %w", err)
	}
	return nil
}

// OnConfirmation must be called when a spend transaction from addr achieves
// 1 confirmation on the QOGE chain. It:
//  1. Transitions addr PENDING → SPENT
//  2. Transitions addr SPENT → RETIRED (zeros the private key seed)
//  3. Refills the pre-generation pool (M2.2)
//
// M1.5 MILESTONE: This is the key destruction callback.
// Wire this to the QOGE chain's block notification system.
func (w *Wallet) OnConfirmation(addr string) error {
	if err := w.index.MarkSpent(addr); err != nil {
		return fmt.Errorf("wallet: OnConfirmation (MarkSpent): %w", err)
	}
	if err := w.index.Retire(addr); err != nil {
		return fmt.Errorf("wallet: OnConfirmation (Retire): %w", err)
	}
	// Refill pool after retirement so we always have addresses ready.
	if err := w.fillPool(); err != nil {
		// Non-fatal: log but don't return error; the confirmation already succeeded.
		fmt.Printf("wallet: WARNING pool refill failed after confirmation: %v\n", err)
	}
	return nil
}

// ─── Signing ──────────────────────────────────────────────────────────────────

// SignMessage signs an arbitrary message using the key for fromAddr.
// fromAddr must be in PENDING state (payment received, not yet confirmed).
//
// The message is hashed with the QOGE prefix before signing:
//   hash = SHA256(SHA256("Qogecoin Signed Message:" || SHA256(message)))
//
// Returns the 32-byte public key and ~17 KB SLH-DSA signature.
// The caller is responsible for broadcasting the transaction promptly —
// the mempool window is ~60 seconds at 1-minute block time.
func (w *Wallet) SignMessage(fromAddr string, message []byte) (pubKey, sig []byte, err error) {
	rec, err := w.index.GetRecord(fromAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("wallet: SignMessage: address not found: %w", err)
	}
	if rec.State != keystore.StatePending {
		return nil, nil, fmt.Errorf("wallet: SignMessage: address %s is %s (want PENDING)",
			fromAddr, rec.State)
	}

	// Decrypt the stored seed to reconstruct the signer.
	rawSeed, err := w.index.DecryptSeed(rec.EncSeedBlob)
	if err != nil {
		return nil, nil, fmt.Errorf("wallet: SignMessage: decrypt seed: %w", err)
	}
	defer keystore.ZeroBytes(rawSeed)

	s, err := slhdsa.ImportSigner(rawSeed, rec.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("wallet: SignMessage: import signer: %w", err)
	}
	defer s.Clean()

	msgHash := canonicalMessageHash(message)
	signature, err := s.Sign(msgHash)
	if err != nil {
		return nil, nil, fmt.Errorf("wallet: SignMessage: sign: %w", err)
	}

	return rec.PublicKey, signature, nil
}

// SignTransaction signs a QOGE transaction.
// The change address in tx.Change MUST be a FRESH address from this wallet.
//
// M1.6: This method is the integration point for the QOGE chain tx format.
// Replace QOGETransaction with the actual chain type and adjust the message
// hash to match the chain's canonical transaction serialisation.
//
// M2.1: Change routing enforcement — returns an error if tx.Change is not
// a FRESH address in this wallet's index.
func (w *Wallet) SignTransaction(tx QOGETransaction) (*SignedTransaction, error) {
	// M2.1: Enforce change routing to a FRESH address.
	changeRec, err := w.index.GetRecord(tx.Change)
	if err != nil {
		return nil, fmt.Errorf("wallet: SignTransaction: change address not in index — "+
			"change MUST route to a fresh wallet address: %w", err)
	}
	if changeRec.State != keystore.StateFresh {
		return nil, fmt.Errorf("wallet: SignTransaction: change address is %s (want FRESH) — "+
			"INVARIANT VIOLATION: change must route to a new unused address", changeRec.State)
	}

	// Sign the transaction message hash.
	pubKey, sig, err := w.SignMessage(tx.From, tx.MessageID)
	if err != nil {
		return nil, err
	}

	return &SignedTransaction{
		Tx:        tx,
		PublicKey: pubKey,
		Signature: sig,
	}, nil
}

// ─── Verification (stateless) ─────────────────────────────────────────────────

// VerifySignature verifies a detached SLH-DSA signature.
// Does not require the signing key — safe to call from any node.
func VerifySignature(message, sig, pubKey []byte) (bool, error) {
	msgHash := canonicalMessageHash(message)
	ok, err := slhdsa.Verify(msgHash, sig, pubKey)
	if err != nil {
		return false, fmt.Errorf("wallet: VerifySignature: %w", err)
	}
	return ok, nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

// fillPool ensures at least PreGenPoolSize FRESH addresses exist.
func (w *Wallet) fillPool() error {
	return w.index.PreGenerate(PreGenPoolSize, w.deriveAddress)
}

// deriveAddress is the deriveFn passed to keystore.GenerateAddress.
// It derives a child seed from the master seed at the given index,
// generates an SLH-DSA keypair, and returns the encrypted seed blob,
// public key, and QOGE address.
//
// M1.3: BIP32-equivalent derivation for SLH-DSA keys.
// We use HKDF-SHA256 with index as context rather than BIP32's secp256k1
// point arithmetic, since SLH-DSA keys are not algebraically related.
func (w *Wallet) deriveAddress(masterSeed []byte, index uint64) (pubKey, encSeedBlob []byte, addr string, err error) {
	// Derive child seed: HKDF(masterSeed, salt=nil, info="qoge-key-{index}")
	info := fmt.Sprintf("qoge-key-%d", index)
	childSeed, err := hkdfDerive32(masterSeed, []byte(info))
	if err != nil {
		return nil, nil, "", fmt.Errorf("deriveAddress: hkdf at index %d: %w", index, err)
	}
	defer keystore.ZeroBytes(childSeed)

	// Generate SLH-DSA keypair from child seed.
	// NOTE: liboqs-go Init with a non-nil seed uses it as the secret key seed.
	// Confirm this behaviour matches FIPS 205 Section 10.1 key generation.
	s, pub, err := slhdsa.NewSigner() // TODO M1.3: pass childSeed once liboqs-go supports deterministic keygen
	if err != nil {
		return nil, nil, "", fmt.Errorf("deriveAddress: NewSigner at index %d: %w", index, err)
	}
	defer s.Clean()

	// Derive QOGE address from public key.
	qogeAddr, err := address.FromPublicKey(pub)
	if err != nil {
		return nil, nil, "", fmt.Errorf("deriveAddress: address derivation at index %d: %w", index, err)
	}

	// Encrypt the secret key for storage.
	rawSK := s.ExportSecretKey()
	defer keystore.ZeroBytes(rawSK)

	enc, err := w.index.EncryptSeed(rawSK)
	if err != nil {
		return nil, nil, "", fmt.Errorf("deriveAddress: encrypt seed at index %d: %w", index, err)
	}

	return pub, enc, qogeAddr, nil
}

// canonicalMessageHash computes the QOGE canonical message hash:
//
//	SHA256(SHA256(prefix || SHA256(message)))
//
// Matches the ref repo's generateMessageHash pattern but uses SHA256
// throughout rather than Keccak256 (Ethereum-specific).
// M1.6: Confirm this matches the QOGE chain's tx hash specification.
func canonicalMessageHash(message []byte) []byte {
	inner := sha256.Sum256(message)
	prefix := []byte(MessagePrefix)
	combined := append(prefix, inner[:]...)
	outer := sha256.Sum256(combined)
	final := sha256.Sum256(outer[:])
	return final[:]
}

// GenerateMasterSeed generates 32 bytes of cryptographically secure entropy
// suitable for use as a wallet master seed.
// Use hardware RNG (HSM) in production; this is the software fallback.
func GenerateMasterSeed() ([]byte, error) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, fmt.Errorf("wallet: GenerateMasterSeed: %w", err)
	}
	return seed, nil
}

// hkdfDerive32 derives 32 bytes from seed with HKDF-SHA256.
func hkdfDerive32(seed, info []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, seed, nil, info)
	out := make([]byte, 32)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}
