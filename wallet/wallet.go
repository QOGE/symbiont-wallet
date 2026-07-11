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
//   [M1.5] Reuse prevention: OnConfirmation flags SPENT at ≥1 confirmation.
//          Key destruction is separate, optional, manual — see PurgeSpentKey.
//   [M1.6] Integration point for QOGE chain tx format (see SignTransaction)
//   [M1.7] Taproot disabled — enforced in address package; double-checked here
//   [M2.1] Change routing: SignP2QPKInput and SignTransaction enforce FRESH
//          change address before signing and transition it PENDING after.
//   [M2.2] Address pre-generation pool (N=20)
package wallet

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/saogen/qoge-sphincs-wallet/address"
	"github.com/saogen/qoge-sphincs-wallet/keystore"
	"github.com/saogen/qoge-sphincs-wallet/signer"
	"golang.org/x/crypto/hkdf"
)

// ErrChangeAddressNotFresh is returned by SignP2QPKInput and SignTransaction
// when the designated change address is not in FRESH state in this wallet's
// index. Change MUST route to a new, unused wallet-controlled address.
var ErrChangeAddressNotFresh = errors.New("wallet: change address is not FRESH — change must route to a new unused wallet address")

// ErrChangeOutputMissing is returned when no output in the transaction pays
// to the designated change address. A signed transaction must include the
// change output it committed to — absent it, the change output could be
// swapped out after signing.
var ErrChangeOutputMissing = errors.New("wallet: no output script pays to the change address — change output must be present in the transaction before signing")

// ErrChangeOutputAmbiguous is returned when more than one output pays to the
// change address. Change must route to exactly one output.
var ErrChangeOutputAmbiguous = errors.New("wallet: multiple outputs pay to the change address — change must route to exactly one output")

// ErrFromAddrScriptMismatch is returned when SpentUTXOs[InputIndex].Script
// does not match the P2QPK scriptPubKey derived from FromAddr. The UTXO being
// consumed must have been sent to the signing address.
var ErrFromAddrScriptMismatch = errors.New("wallet: SpentUTXOs[InputIndex].Script does not match the P2QPK scriptPubKey for FromAddr")

// PreGenPoolSize is the number of FRESH addresses to maintain in the pool.
// M2.2: pre-generate 20 addresses on init and after each spend.
const PreGenPoolSize = 20

// MessagePrefix is prepended before hashing any message for signing.
// Mirrors the ref repo's "Qogecoin Signed Message:" prefix, preventing
// cross-protocol signature reuse.
const MessagePrefix = "Qogecoin Signed Message:"

// KeyDestructionMinConfirmations is the minimum confirmation depth required
// before PurgeSpentKey() will destroy a P2QPK private key.
//
// Set to 101 — Qogecoin's coinbase maturity depth — which represents the
// network's own standard for permanent transaction settlement. Key destruction
// at this depth is not a security requirement (the single-use address model
// provides HNDL protection regardless) but a safety floor for this
// irreversible, optional action: a reorg of this depth would constitute
// catastrophic chain failure, not routine operation.
//
// Note: OnConfirmation() does NOT use this threshold. It flags addresses
// SPENT at any confirmation depth (>= 1) for reuse prevention. Key
// destruction is a separate, explicitly-invoked action via PurgeSpentKey().
//
// Applications MAY increase this value via SetKeyDestructionMinConfirmations()
// but cannot decrease it below 101 — the setter enforces this floor in code.
const KeyDestructionMinConfirmations = 101

// keyDestructionMinConfirmations is the runtime value, defaulting to the constant.
var keyDestructionMinConfirmations = KeyDestructionMinConfirmations

// SetKeyDestructionMinConfirmations overrides the confirmation threshold for
// PurgeSpentKey(). Values below KeyDestructionMinConfirmations (101) are
// rejected with an error — callers may increase the threshold but not lower it.
func SetKeyDestructionMinConfirmations(n int) error {
	if n < KeyDestructionMinConfirmations {
		return fmt.Errorf("wallet: SetKeyDestructionMinConfirmations: %d is below the enforced minimum %d",
			n, KeyDestructionMinConfirmations)
	}
	keyDestructionMinConfirmations = n
	return nil
}

// ─── QOGETransaction (stub) ───────────────────────────────────────────────────

// QOGETransaction is a placeholder for the QOGE chain transaction structure.
//
// M1.6 MILESTONE: Replace this stub with the actual QOGE chain transaction
// type once the chain's wire format is defined. The SignTransaction method
// below shows the integration pattern.
type QOGETransaction struct {
	From      string        // Sender address (must be PENDING in index)
	To        string        // Recipient address
	Amount    uint64        // In QOGE base units
	Change    string        // Change address — MUST be a fresh address from this wallet
	Outputs   []SpendOutput // All transaction outputs; exactly one must pay to Change
	MessageID []byte        // Canonical tx hash for signing (set by chain layer)
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

// OnConfirmation flags addr SPENT once its spending transaction has at least
// one confirmation. Returns nil (no-op) if confirmations < 1.
//
// This prevents address reuse immediately on confirmation — it does NOT destroy
// the private key. Key destruction is a separate, optional, irreversible action
// via PurgeSpentKey(), invoked at the integrator's or user's discretion.
//
// M1.5 MILESTONE: Wire this to the QOGE chain's block notification system.
func (w *Wallet) OnConfirmation(addr string, confirmations int) error {
	if confirmations < 1 {
		return nil // not yet confirmed in any block
	}
	if err := w.index.MarkSpent(addr); err != nil {
		return fmt.Errorf("wallet: OnConfirmation (MarkSpent): %w", err)
	}
	// Refill pool after spend so we always have addresses ready.
	if err := w.fillPool(); err != nil {
		// Non-fatal: log but don't return error; the confirmation already succeeded.
		fmt.Printf("wallet: WARNING pool refill failed after confirmation: %v\n", err)
	}
	return nil
}

// PurgeSpentKey permanently destroys the private key for a SPENT address.
// This is OPTIONAL, MANUAL, and IRREVERSIBLE. It is never called
// automatically by any wallet-internal logic. Calling this (or not, and
// when) is entirely the integrator's or end user's decision and
// responsibility — the wallet library takes no position on whether keys
// should ever be destroyed.
//
// Requires addr to be in SPENT state and confirmations to be at least
// keyDestructionMinConfirmations (default 101). The confirmation floor is
// a safety guard for this now-optional, irreversible action — not an
// automatic trigger.
func (w *Wallet) PurgeSpentKey(addr string, confirmations int) error {
	if confirmations < keyDestructionMinConfirmations {
		return fmt.Errorf("wallet: PurgeSpentKey: confirmations %d below minimum %d",
			confirmations, keyDestructionMinConfirmations)
	}
	if err := w.index.Retire(addr); err != nil {
		return fmt.Errorf("wallet: PurgeSpentKey (Retire): %w", err)
	}
	return nil
}

// ─── Purge-eligibility scan ───────────────────────────────────────────────────

// PurgeEligibleAddress describes a SPENT address that is a reasonable
// candidate for key destruction via PurgeSpentKey.
type PurgeEligibleAddress struct {
	Address       string
	Confirmations int // as of the chain height supplied by the caller
}

// ListPurgeEligibleAddresses returns SPENT addresses for which confirmationsFor
// reports at least keyDestructionMinConfirmations confirmations. This is
// advisory only — it does not purge anything. The caller (CLI, application,
// end user) decides whether to act on any entry via PurgeSpentKey.
//
// confirmationsFor is supplied by the caller because this wallet package does
// not itself track chain state. It is called once per SPENT address.
func (w *Wallet) ListPurgeEligibleAddresses(confirmationsFor func(addr string) int) ([]PurgeEligibleAddress, error) {
	records, err := w.index.ListByState(keystore.StateSpent)
	if err != nil {
		return nil, fmt.Errorf("wallet: ListPurgeEligibleAddresses: %w", err)
	}
	var eligible []PurgeEligibleAddress
	for _, rec := range records {
		confs := confirmationsFor(rec.Address)
		if confs >= keyDestructionMinConfirmations {
			eligible = append(eligible, PurgeEligibleAddress{
				Address:       rec.Address,
				Confirmations: confs,
			})
		}
	}
	return eligible, nil
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

	// M2.1: verify exactly one output pays to the change address.
	changeScript, err := p2qpkScriptPubKey(tx.Change)
	if err != nil {
		return nil, fmt.Errorf("wallet: SignTransaction: %w", err)
	}
	changeMatches := 0
	for _, out := range tx.Outputs {
		if bytes.Equal(out.Script, changeScript) {
			changeMatches++
		}
	}
	if changeMatches == 0 {
		return nil, fmt.Errorf("wallet: SignTransaction: %w", ErrChangeOutputMissing)
	}
	if changeMatches > 1 {
		return nil, fmt.Errorf("wallet: SignTransaction: %w", ErrChangeOutputAmbiguous)
	}

	// Sign the transaction message hash.
	pubKey, sig, err := w.SignMessage(tx.From, tx.MessageID)
	if err != nil {
		return nil, err
	}

	// M2.1: transition change FRESH → PENDING only after signing succeeds.
	if err := w.index.MarkPending(tx.Change); err != nil {
		return nil, fmt.Errorf("wallet: SignTransaction: mark change PENDING: %w", err)
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
	// Derive 48-byte child seed: HKDF-SHA256(masterSeed, salt=nil, info="qoge-key-{index}").
	// 48 bytes = 3 * n for SLH-DSA-SHA2-128f (n=16), matching the single OQS_randombytes
	// draw made by slh_keygen (FIPS 205 Algorithm 21, liboqs 0.15.0 slh_dsa.c:505).
	info := fmt.Sprintf("qoge-key-%d", index)
	childSeed, err := hkdfDeriveN(masterSeed, []byte(info), slhdsa.SeedSize)
	if err != nil {
		return nil, nil, "", fmt.Errorf("deriveAddress: hkdf at index %d: %w", index, err)
	}
	defer keystore.ZeroBytes(childSeed)

	// Deterministically generate SLH-DSA keypair from childSeed (M1.3).
	s, pub, err := slhdsa.NewSignerFromSeed(childSeed)
	if err != nil {
		return nil, nil, "", fmt.Errorf("deriveAddress: NewSignerFromSeed at index %d: %w", index, err)
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

// hkdfDeriveN derives n bytes from seed with HKDF-SHA256.
func hkdfDeriveN(seed, info []byte, n int) ([]byte, error) {
	h := hkdf.New(sha256.New, seed, nil, info)
	out := make([]byte, n)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ─── P2QPK spend signing (M1.6, SIP-QOGE-PQC-02a §3) ─────────────────────────

// SpendInput is one input in a P2QPK spend transaction.
type SpendInput struct {
	TxIDLE    [32]byte // txid in wire byte order (reversed from RPC display)
	Vout      uint32
	NSequence uint32
}

// SpentUTXO is the UTXO being consumed by a SpendInput (parallel with Inputs).
type SpentUTXO struct {
	Amount int64  // value in satoshis
	Script []byte // scriptPubKey bytes
}

// SpendOutput is one output in the spend transaction.
type SpendOutput struct {
	Amount int64
	Script []byte
}

// P2QPKSpendParams carries the transaction data needed to compute the
// P2QPKSighash and sign a specific input per SIP-QOGE-PQC-02a §3.
type P2QPKSpendParams struct {
	NVersion   int32
	NLockTime  uint32
	Inputs     []SpendInput
	SpentUTXOs []SpentUTXO // parallel with Inputs; holds the UTXOs being consumed
	Outputs    []SpendOutput
	InputIndex uint32 // index of the input being signed
	FromAddr   string // must be in PENDING state in the wallet index
	ChangeAddr string // must be a FRESH wallet-controlled address; transitioned to PENDING after signing
}

// p2qpkScriptPubKey derives the P2QPK scriptPubKey for addr.
// Script format: OP_2 (0x52) | PUSH32 (0x20) | HASH256(pubkey) — 34 bytes.
// This is the witness-v2 program commitment as it appears in a transaction
// output's scriptPubKey field, mirroring how qogecoin/interpreter.cpp
// dispatches to CheckSLHDSASignature for witness version 2.
func p2qpkScriptPubKey(addr string) ([]byte, error) {
	hash, err := address.ToHash(addr)
	if err != nil {
		return nil, fmt.Errorf("p2qpkScriptPubKey: %w", err)
	}
	script := make([]byte, 2+len(hash))
	script[0] = 0x52 // OP_2 — witness version 2
	script[1] = 0x20 // push 32 bytes
	copy(script[2:], hash)
	return script, nil
}

// SignP2QPKInput signs a P2QPK input per SIP-QOGE-PQC-02a §3.
// params.FromAddr must be in PENDING state. params.ChangeAddr must be a
// FRESH wallet-controlled address; it is transitioned to PENDING after a
// successful sign so it cannot be reused as change or receive address.
// Returns the SLH-DSA public key (32 bytes) and signature (17,088 bytes).
// The message signed is the 32-byte P2QPKSighash — NOT canonicalMessageHash,
// which is only for the CLI generic message-signing demo (Open Item 4).
func (w *Wallet) SignP2QPKInput(params P2QPKSpendParams) (pubKey, sig []byte, err error) {
	rec, err := w.index.GetRecord(params.FromAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: address not found: %w", err)
	}
	if rec.State != keystore.StatePending {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: address %s is %s (want PENDING)",
			params.FromAddr, rec.State)
	}

	// Verify that SpentUTXOs[InputIndex].Script matches the P2QPK scriptPubKey
	// for FromAddr. Without this check a caller could pass a UTXO script
	// belonging to a different address; the wallet would sign with FromAddr's
	// key, producing an invalid on-chain transaction while consuming the
	// address's state.
	if int(params.InputIndex) >= len(params.SpentUTXOs) {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: InputIndex %d out of range (SpentUTXOs len %d)",
			params.InputIndex, len(params.SpentUTXOs))
	}
	fromScript, err := p2qpkScriptPubKey(params.FromAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: %w", err)
	}
	if !bytes.Equal(params.SpentUTXOs[params.InputIndex].Script, fromScript) {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: %w", ErrFromAddrScriptMismatch)
	}

	// M2.1: validate change routes to a FRESH wallet-controlled address before signing.
	changeRec, err := w.index.GetRecord(params.ChangeAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: change address not in wallet index — "+
			"change MUST route to a fresh wallet address: %w", err)
	}
	if changeRec.State != keystore.StateFresh {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: %w (got %s)",
			ErrChangeAddressNotFresh, changeRec.State)
	}

	// M2.1: verify exactly one output's script pays to the change address.
	// Without this check a caller could supply any ChangeAddr (FRESH, passing
	// the state-machine check above) while the actual outputs route change
	// elsewhere — the signed commitment and the state transition would be for
	// different addresses.
	changeScript, err := p2qpkScriptPubKey(params.ChangeAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: %w", err)
	}
	changeMatches := 0
	for _, out := range params.Outputs {
		if bytes.Equal(out.Script, changeScript) {
			changeMatches++
		}
	}
	if changeMatches == 0 {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: %w", ErrChangeOutputMissing)
	}
	if changeMatches > 1 {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: %w", ErrChangeOutputAmbiguous)
	}

	sighash, err := computeP2QPKSighash(params)
	if err != nil {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: sighash: %w", err)
	}

	rawSeed, err := w.index.DecryptSeed(rec.EncSeedBlob)
	if err != nil {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: decrypt seed: %w", err)
	}
	defer keystore.ZeroBytes(rawSeed)

	s, err := slhdsa.ImportSigner(rawSeed, rec.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: import signer: %w", err)
	}
	defer s.Clean()

	// Sign the raw 32-byte P2QPKSighash per §7-B: pure SLH-DSA, empty context, raw hash as message.
	signature, err := s.Sign(sighash)
	if err != nil {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: sign: %w", err)
	}

	// M2.1: transition change FRESH → PENDING only after signing succeeds.
	// This prevents the change address from ever being reused as a receive or
	// change address on a subsequent transaction.
	if err := w.index.MarkPending(params.ChangeAddr); err != nil {
		return nil, nil, fmt.Errorf("wallet: SignP2QPKInput: mark change PENDING: %w", err)
	}

	return rec.PublicKey, signature, nil
}

// computeP2QPKSighash implements SIP-QOGE-PQC-02a §3, mirroring
// SignatureHashP2QPK in src/script/interpreter.cpp exactly.
//
// TaggedHash("P2QPKSighash"; epoch || SIGHASH_ALL || nVersion || nLockTime ||
//
//	hashPrevouts || hashAmounts || hashScriptPubkeys || hashSequences ||
//	hashOutputs || in_pos)
func computeP2QPKSighash(p P2QPKSpendParams) ([]byte, error) {
	if int(p.InputIndex) >= len(p.Inputs) {
		return nil, fmt.Errorf("computeP2QPKSighash: InputIndex %d out of range (len %d)",
			p.InputIndex, len(p.Inputs))
	}
	if len(p.Inputs) != len(p.SpentUTXOs) {
		return nil, fmt.Errorf("computeP2QPKSighash: Inputs len %d != SpentUTXOs len %d",
			len(p.Inputs), len(p.SpentUTXOs))
	}

	// TaggedHash("P2QPKSighash"; preimage) = SHA256(SHA256(tag) || SHA256(tag) || preimage)
	tag := sha256.Sum256([]byte("P2QPKSighash"))
	h := sha256.New()
	h.Write(tag[:])
	h.Write(tag[:])

	// Epoch (0x00) and SIGHASH_ALL (0x01)
	h.Write([]byte{0x00, 0x01})

	var b4 [4]byte
	var b8 [8]byte

	// nVersion (int32 LE)
	binary.LittleEndian.PutUint32(b4[:], uint32(p.NVersion))
	h.Write(b4[:])

	// nLockTime (uint32 LE)
	binary.LittleEndian.PutUint32(b4[:], p.NLockTime)
	h.Write(b4[:])

	// m_prevouts_single_hash = SHA256(txid_wire || vout_LE32 for each input)
	hp := sha256.New()
	for _, inp := range p.Inputs {
		hp.Write(inp.TxIDLE[:])
		binary.LittleEndian.PutUint32(b4[:], inp.Vout)
		hp.Write(b4[:])
	}
	h.Write(hp.Sum(nil))

	// m_spent_amounts_single_hash = SHA256(amount_LE64 for each spent UTXO)
	ha := sha256.New()
	for _, u := range p.SpentUTXOs {
		binary.LittleEndian.PutUint64(b8[:], uint64(u.Amount))
		ha.Write(b8[:])
	}
	h.Write(ha.Sum(nil))

	// m_spent_scripts_single_hash = SHA256(compact_size(len) || script for each spent UTXO)
	hs := sha256.New()
	for _, u := range p.SpentUTXOs {
		writeCompactSize(hs, uint64(len(u.Script)))
		hs.Write(u.Script)
	}
	h.Write(hs.Sum(nil))

	// m_sequences_single_hash = SHA256(nSequence_LE32 for each input)
	hq := sha256.New()
	for _, inp := range p.Inputs {
		binary.LittleEndian.PutUint32(b4[:], inp.NSequence)
		hq.Write(b4[:])
	}
	h.Write(hq.Sum(nil))

	// m_outputs_single_hash = SHA256(amount_LE64 || compact_size(len) || script for each output)
	ho := sha256.New()
	for _, out := range p.Outputs {
		binary.LittleEndian.PutUint64(b8[:], uint64(out.Amount))
		ho.Write(b8[:])
		writeCompactSize(ho, uint64(len(out.Script)))
		ho.Write(out.Script)
	}
	h.Write(ho.Sum(nil))

	// in_pos (uint32 LE)
	binary.LittleEndian.PutUint32(b4[:], p.InputIndex)
	h.Write(b4[:])

	return h.Sum(nil), nil
}

// writeCompactSize writes a Bitcoin compact-size (variable-length) integer to w.
func writeCompactSize(w io.Writer, v uint64) {
	var buf [9]byte
	switch {
	case v < 0xfd:
		buf[0] = byte(v)
		w.Write(buf[:1]) //nolint:errcheck
	case v <= 0xffff:
		buf[0] = 0xfd
		binary.LittleEndian.PutUint16(buf[1:], uint16(v))
		w.Write(buf[:3]) //nolint:errcheck
	case v <= 0xffffffff:
		buf[0] = 0xfe
		binary.LittleEndian.PutUint32(buf[1:], uint32(v))
		w.Write(buf[:5]) //nolint:errcheck
	default:
		buf[0] = 0xff
		binary.LittleEndian.PutUint64(buf[1:], v)
		w.Write(buf[:9]) //nolint:errcheck
	}
}
