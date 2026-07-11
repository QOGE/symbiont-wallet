package slhdsa

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// TestAlgorithmEnabled confirms that liboqs reports SLH_DSA_PURE_SHA2_128F
// as both supported and enabled in this build. This is the core M1.1 check:
// if this fails, AlgorithmName does not match what liboqs exposes.
func TestAlgorithmEnabled(t *testing.T) {
	if !oqs.IsSigSupported(AlgorithmName) {
		t.Fatalf("algorithm %q is not SUPPORTED by liboqs — check the constant "+
			"against `grep OQS_SIG_alg /usr/local/include/oqs/sig.h`", AlgorithmName)
	}
	if !oqs.IsSigEnabled(AlgorithmName) {
		t.Fatalf("algorithm %q is supported but NOT ENABLED — check liboqs build flags "+
			"(OQS_DIST_BUILD=ON should enable all supported sigs)", AlgorithmName)
	}
	t.Logf("liboqs confirms %q is supported and enabled", AlgorithmName)
}

// TestKeyGenerationSizes confirms the actual sizes liboqs reports match
// the constants declared in this package (PublicKeySize, SecretKeySize).
// SIP-QOGE-PQC-01 §4.2 specifies 32 / 64 bytes for SLH-DSA-SHA2-128f.
func TestKeyGenerationSizes(t *testing.T) {
	s, pub, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer s.Clean()

	if len(pub) != PublicKeySize {
		t.Errorf("public key size = %d, want %d", len(pub), PublicKeySize)
	}

	sk := s.ExportSecretKey()
	if len(sk) != SecretKeySize {
		t.Errorf("secret key size = %d, want %d", len(sk), SecretKeySize)
	}

	t.Logf("Public key: %d bytes, Secret key: %d bytes", len(pub), len(sk))
}

// TestSignVerifyRoundTrip is the core M1.1 milestone test:
// generate a keypair, sign a message, verify the signature, and confirm
// signature size matches FIPS 205's SLH-DSA-SHA2-128f spec (~17088 bytes).
func TestSignVerifyRoundTrip(t *testing.T) {
	s, pub, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer s.Clean()

	// Simulate canonicalMessageHash from wallet package: SHA256 digest.
	msg := []byte("SIP-QOGE-PQC-01 M1.1 validation message")
	digest := sha256.Sum256(msg)

	sig, err := s.Sign(digest[:])
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	t.Logf("Signature length: %d bytes (expect exactly %d for SLH-DSA-SHA2-128f)", len(sig), SignatureSize)
	if len(sig) != SignatureSize {
		t.Errorf("signature length %d != expected %d (SLH-DSA-SHA2-128f always produces a fixed-length output)", len(sig), SignatureSize)
	}

	ok, err := Verify(digest[:], sig, pub)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatal("Verify returned false for a valid signature — CRITICAL FAILURE")
	}
	t.Log("Signature verified successfully")
}

// TestVerifyRejectsTamperedMessage confirms that a signature does not
// validate against a different message — basic sanity check that we're
// not accidentally accepting everything.
func TestVerifyRejectsTamperedMessage(t *testing.T) {
	s, pub, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer s.Clean()

	original := sha256.Sum256([]byte("original message"))
	tampered := sha256.Sum256([]byte("tampered message"))

	sig, err := s.Sign(original[:])
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	ok, err := Verify(tampered[:], sig, pub)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if ok {
		t.Fatal("Verify returned true for a tampered message — CRITICAL FAILURE")
	}
	t.Log("Tampered message correctly rejected")
}

// TestVerifyRejectsWrongPublicKey confirms that a signature does not
// validate against a different keypair's public key.
func TestVerifyRejectsWrongPublicKey(t *testing.T) {
	s1, _, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner (s1) failed: %v", err)
	}
	defer s1.Clean()

	s2, pub2, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner (s2) failed: %v", err)
	}
	defer s2.Clean()

	digest := sha256.Sum256([]byte("message signed by s1"))
	sig, err := s1.Sign(digest[:])
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	ok, err := Verify(digest[:], sig, pub2)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if ok {
		t.Fatal("Verify returned true for the wrong public key — CRITICAL FAILURE")
	}
	t.Log("Wrong public key correctly rejected")
}

// TestImportSignerRoundTrip confirms ExportSecretKey + ImportSigner
// reconstructs a working signer — required for wallet.SignMessage,
// which decrypts a stored seed and reconstructs the signer per-transaction.
func TestImportSignerRoundTrip(t *testing.T) {
	s1, pub, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	sk := make([]byte, len(s1.ExportSecretKey()))
	copy(sk, s1.ExportSecretKey())
	s1.Clean()

	s2, err := ImportSigner(sk, pub)
	if err != nil {
		t.Fatalf("ImportSigner failed: %v", err)
	}
	defer s2.Clean()

	digest := sha256.Sum256([]byte("message signed after import"))
	sig, err := s2.Sign(digest[:])
	if err != nil {
		t.Fatalf("Sign after import failed: %v", err)
	}

	ok, err := Verify(digest[:], sig, pub)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatal("Signature from imported signer did not verify — CRITICAL FAILURE")
	}
	t.Log("Import/export round-trip successful")
}

// TestSignaturesAreNotIdentical is a basic sanity check that SLH-DSA
// signing includes randomization (it does, per FIPS 205) — two signatures
// of the same message with the same key should differ.
func TestSignaturesAreNotIdentical(t *testing.T) {
	s, pub, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	defer s.Clean()

	digest := sha256.Sum256([]byte("repeated message"))

	sig1, err := s.Sign(digest[:])
	if err != nil {
		t.Fatalf("Sign (1) failed: %v", err)
	}
	sig2, err := s.Sign(digest[:])
	if err != nil {
		t.Fatalf("Sign (2) failed: %v", err)
	}

	if bytes.Equal(sig1, sig2) {
		t.Log("WARNING: two signatures of the same message were identical " +
			"(not necessarily an error for deterministic variants, but worth noting)")
	} else {
		t.Log("Signatures are randomized across calls, as expected")
	}

	// Both must still verify regardless.
	ok1, _ := Verify(digest[:], sig1, pub)
	ok2, _ := Verify(digest[:], sig2, pub)
	if !ok1 || !ok2 {
		t.Fatal("one of the repeated signatures failed to verify")
	}
}

// TestNewSignerFromSeedDeterministic confirms that the same 48-byte seed always
// produces the same public key across two consecutive calls.
func TestNewSignerFromSeedDeterministic(t *testing.T) {
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1) // 0x01 .. 0x30
	}

	s1, pub1, err := NewSignerFromSeed(seed)
	if err != nil {
		t.Fatalf("first NewSignerFromSeed failed: %v", err)
	}
	defer s1.Clean()

	s2, pub2, err := NewSignerFromSeed(seed)
	if err != nil {
		t.Fatalf("second NewSignerFromSeed failed: %v", err)
	}
	defer s2.Clean()

	if !bytes.Equal(pub1, pub2) {
		t.Errorf("same seed produced different public keys:\n  call1: %x\n  call2: %x", pub1, pub2)
	}
	t.Logf("deterministic keygen confirmed; pub: %x", pub1)
}

// knownAnswerPub is the expected 32-byte SLH-DSA-SHA2-128f public key for the
// seed [0x01..0x30] (48 bytes). Pinned on 2026-07-11 against liboqs 0.15.0.
// If this test fails, keygen output has changed — any seed-based key recovery
// would silently produce wrong keys, which is a catastrophic wallet bug.
//
// Sanity check: first 16 bytes are PK.seed = seed[32..47] = 0x21..0x30, per
// FIPS 205 §5.1 public key layout. Last 16 bytes are the computed PK.root.
var knownAnswerPub = []byte{
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	0xa3, 0x35, 0x6a, 0x12, 0x83, 0xac, 0x92, 0xdc,
	0xae, 0x6a, 0x36, 0x96, 0x0a, 0xce, 0x26, 0x00,
}

// TestNewSignerFromSeedKnownAnswer is the mandatory known-answer test for M1.3.
// It pins the public key produced by a specific seed and fails if future
// liboqs/HKDF changes alter the output without an explicit re-pin.
func TestNewSignerFromSeedKnownAnswer(t *testing.T) {
	seed := make([]byte, SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1) // 0x01 .. 0x30
	}

	s, gotPub, err := NewSignerFromSeed(seed)
	if err != nil {
		t.Fatalf("NewSignerFromSeed: %v", err)
	}
	defer s.Clean()

	t.Logf("VECTOR (pin this): %x", gotPub)

	if len(knownAnswerPub) == 0 {
		t.Skip("KAT vector not yet pinned — read the VECTOR line above and set knownAnswerPub")
	}
	if !bytes.Equal(gotPub, knownAnswerPub) {
		t.Errorf("deterministic keygen output changed — wallet seeds will produce wrong keys:\n  got  %x\n  want %x", gotPub, knownAnswerPub)
	}
}

// TestNewSignerFromSeedConcurrent runs NewSignerFromSeed from multiple goroutines
// with distinct seeds and confirms each goroutine gets the key its own seed should
// produce. This exercises the rngMu protection against the global OQS RNG being
// hijacked across concurrent deterministic keygens.
func TestNewSignerFromSeedConcurrent(t *testing.T) {
	const n = 8

	// Compute reference public keys sequentially first.
	seeds := make([][]byte, n)
	refPubs := make([][]byte, n)
	for i := range seeds {
		seeds[i] = make([]byte, SeedSize)
		for j := range seeds[i] {
			seeds[i][j] = byte(i*SeedSize + j + 1)
		}
		s, pub, err := NewSignerFromSeed(seeds[i])
		if err != nil {
			t.Fatalf("reference keygen %d: %v", i, err)
		}
		refPubs[i] = make([]byte, len(pub))
		copy(refPubs[i], pub)
		s.Clean()
	}

	// Run concurrently.
	type result struct {
		pub []byte
		err error
	}
	results := make([]result, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s, pub, err := NewSignerFromSeed(seeds[idx])
			if err != nil {
				results[idx].err = err
				return
			}
			results[idx].pub = make([]byte, len(pub))
			copy(results[idx].pub, pub)
			s.Clean()
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if results[i].err != nil {
			t.Errorf("goroutine %d: %v", i, results[i].err)
			continue
		}
		if !bytes.Equal(results[i].pub, refPubs[i]) {
			t.Errorf("goroutine %d: public key corrupted by concurrent keygens\n  got  %x\n  want %x", i, results[i].pub, refPubs[i])
		}
	}
}

// TestNewSignerFromSeedVsSignRace exercises keygen and signing concurrently
// to confirm rngMu prevents the deterministic-keygen custom callback from
// corrupting a concurrent signing operation (and vice versa).
// Run with -race to catch any data race not covered by the mutex.
func TestNewSignerFromSeedVsSignRace(t *testing.T) {
	// An existing signer used for signing in the concurrent goroutine.
	signerSeed := make([]byte, SeedSize)
	for i := range signerSeed {
		signerSeed[i] = 0xAA
	}
	existingSigner, existingPub, err := NewSignerFromSeed(signerSeed)
	if err != nil {
		t.Fatalf("setup signer: %v", err)
	}
	defer existingSigner.Clean()

	// Reference public key for the keygen seed used in the concurrent goroutine.
	keygenSeed := make([]byte, SeedSize)
	for i := range keygenSeed {
		keygenSeed[i] = 0xBB
	}
	refSigner, refPub, err := NewSignerFromSeed(keygenSeed)
	if err != nil {
		t.Fatalf("reference keygen: %v", err)
	}
	refSigner.Clean()

	msg := sha256.Sum256([]byte("concurrent sign test message"))

	const iters = 10
	var wg sync.WaitGroup
	keygenErrs := make([]error, iters)
	keygenPubs := make([][]byte, iters)
	signErrs := make([]error, iters)

	for i := 0; i < iters; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			s, gotPub, err := NewSignerFromSeed(keygenSeed)
			if err != nil {
				keygenErrs[idx] = err
				return
			}
			keygenPubs[idx] = make([]byte, len(gotPub))
			copy(keygenPubs[idx], gotPub)
			s.Clean()
		}(i)
		go func(idx int) {
			defer wg.Done()
			sig, err := existingSigner.Sign(msg[:])
			if err != nil {
				signErrs[idx] = fmt.Errorf("Sign: %w", err)
				return
			}
			ok, verifyErr := Verify(msg[:], sig, existingPub)
			if verifyErr != nil {
				signErrs[idx] = fmt.Errorf("Verify: %w", verifyErr)
				return
			}
			if !ok {
				signErrs[idx] = fmt.Errorf("signature corrupted by concurrent keygen (Verify returned false)")
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < iters; i++ {
		if keygenErrs[i] != nil {
			t.Errorf("keygen iter %d: %v", i, keygenErrs[i])
		} else if keygenPubs[i] != nil && !bytes.Equal(keygenPubs[i], refPub) {
			t.Errorf("keygen iter %d: public key corrupted by concurrent Sign\n  got  %x\n  want %x", i, keygenPubs[i], refPub)
		}
		if signErrs[i] != nil {
			t.Errorf("sign iter %d: %v", i, signErrs[i])
		}
	}
}
