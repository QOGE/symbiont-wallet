// Package slhdsa wraps liboqs-go for SLH-DSA-SHA2-128f (FIPS 205).
//
// M1.1 TARGET: This file replaces the ref repo's inline oqs.Signature usage
// which targeted "SPHINCS+-SHA2-128s-simple" (NIST Round 3).
//
// FIPS 205 algorithm name: "SLH_DSA_PURE_SHA2_128F"
// When liboqs-go is updated to expose the final FIPS 205 parameter sets,
// change AlgorithmName below to the published constant. Everything else
// in this file is algorithm-agnostic.
//
// DO NOT use the Round 3 name "SPHINCS+-SHA2-128s-simple" in production.
// The "s" (small) variant has ~7 KB sigs but is slower; "f" (fast) has
// ~17 KB sigs. For QOGE gate transactions the "f" variant is preferred.
// Change AlgorithmName to the "s" variant only if block-size pressure
// requires it — see SIP-QOGE-PQC-01 Section 4.2.
package slhdsa

import (
	"fmt"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// AlgorithmName is the liboqs algorithm identifier for SLH-DSA-SHA2-128f.
//
// MILESTONE M1.1: Verify this string against the FIPS 205 final release of
// liboqs-go. The Round 3 name was "SPHINCS+-SHA2-128s-simple".
// FIPS 205 renames the algorithm family; confirm the exact string in:
//   liboqs/src/sig/sphincs/sig_sphincs.c  (look for FIPS_205 build flag)
const AlgorithmName = "SLH_DSA_PURE_SHA2_128F"

// PublicKeySize is the SLH-DSA-SHA2-128f public key size in bytes.
// FIPS 205, Table 2: n=16, PK = 2*n = 32 bytes.
const PublicKeySize = 32

// SecretKeySize is the SLH-DSA-SHA2-128f secret key size in bytes.
// FIPS 205, Table 2: SK = 4*n = 64 bytes (seed representation).
const SecretKeySize = 64

// SignatureSize is the SLH-DSA-SHA2-128f signature size in bytes.
// FIPS 205, Table 2 (fast variant): ~17,088 bytes.
const SignatureSize = 17088

// Signer wraps a single liboqs signing context.
// Create with NewSigner() or ImportSigner(). Always defer Signer.Clean().
type Signer struct {
	sig    oqs.Signature
	pubKey []byte
}

// NewSigner initialises liboqs and generates a fresh SLH-DSA keypair.
// Returns the Signer and the raw 32-byte public key.
// The caller is responsible for calling signer.Clean() when done.
func NewSigner() (*Signer, []byte, error) {
	s := &Signer{}
	if err := s.sig.Init(AlgorithmName, nil); err != nil {
		return nil, nil, fmt.Errorf("slhdsa: Init failed: %w", err)
	}
	pub, err := s.sig.GenerateKeyPair()
	if err != nil {
		s.sig.Clean()
		return nil, nil, fmt.Errorf("slhdsa: GenerateKeyPair failed: %w", err)
	}
	s.pubKey = pub
	return s, pub, nil
}

// ImportSigner restores a signing context from a raw secret key seed.
// pubKey must be the 32-byte public key that corresponds to secretKey.
// The caller is responsible for zeroing secretKey after this call
// (use keystore.ZeroBytes).
func ImportSigner(secretKey, pubKey []byte) (*Signer, error) {
	if len(secretKey) != SecretKeySize {
		return nil, fmt.Errorf("slhdsa: invalid secret key length %d (want %d)",
			len(secretKey), SecretKeySize)
	}
	if len(pubKey) != PublicKeySize {
		return nil, fmt.Errorf("slhdsa: invalid public key length %d (want %d)",
			len(pubKey), PublicKeySize)
	}
	s := &Signer{}
	if err := s.sig.Init(AlgorithmName, secretKey); err != nil {
		return nil, fmt.Errorf("slhdsa: Init from secret key failed: %w", err)
	}
	s.pubKey = pubKey
	return s, nil
}

// Sign signs msg and returns the raw SLH-DSA signature (~17 KB).
// msg should be a pre-hashed message digest, not raw cleartext.
// Use crypto/message.Hash() to produce a canonical QOGE message hash.
func (s *Signer) Sign(msg []byte) ([]byte, error) {
	sig, err := s.sig.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("slhdsa: Sign failed: %w", err)
	}
	return sig, nil
}

// PublicKey returns the signer's 32-byte public key.
func (s *Signer) PublicKey() []byte {
	return s.pubKey
}

// ExportSecretKey returns the raw secret key bytes for encrypted storage.
// SECURITY: Zero the returned slice immediately after storing it.
// Use keystore.ZeroBytes(sk) after the store operation.
func (s *Signer) ExportSecretKey() []byte {
	return s.sig.ExportSecretKey()
}

// Clean securely releases the liboqs signing context.
// Always call this (via defer) when the Signer is no longer needed.
func (s *Signer) Clean() {
	s.sig.Clean()
}

// Verify verifies a detached SLH-DSA signature.
// Does not require a Signer instance — safe to call from any goroutine.
func Verify(msg, signature, pubKey []byte) (bool, error) {
	v := oqs.Signature{}
	defer v.Clean()
	if err := v.Init(AlgorithmName, nil); err != nil {
		return false, fmt.Errorf("slhdsa: Verify Init failed: %w", err)
	}
	ok, err := v.Verify(msg, signature, pubKey)
	if err != nil {
		return false, fmt.Errorf("slhdsa: Verify failed: %w", err)
	}
	return ok, nil
}
