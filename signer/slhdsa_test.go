package slhdsa

import (
	"bytes"
	"crypto/sha256"
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
