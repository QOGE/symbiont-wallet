package address

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcutil/bech32"
)

// ─── BIP173/BIP350 canonical checksum vectors ─────────────────────────────────
//
// These are the FIRST test vectors listed in BIP173 and BIP350 respectively
// — "a12uel5l" (BIP173, Bech32) and "a1lqfn3a" (BIP350, Bech32m). BIP350
// deliberately chose "a1lqfn3a" as the Bech32m analogue of BIP173's
// "a12uel5l" (same hrp "a", empty data payload, just a checksum), making
// this pair a widely-reproduced minimal cross-check of the two constants.
//
// These vectors test bech32m.go's checksum algorithm against EXTERNAL
// ground truth, independent of this package's address-specific logic
// (encode/decode round-trip tests below are self-consistent but cannot,
// by themselves, catch a transcription error in the polymod generator
// array or the BIP350 constant).

func TestBIP173CanonicalChecksumVector(t *testing.T) {
	hrp, data, constant, err := decodeGeneric("a12uel5l")
	if err != nil {
		t.Fatalf("decodeGeneric(a12uel5l) failed: %v", err)
	}
	if hrp != "a" {
		t.Errorf("hrp = %q, want %q", hrp, "a")
	}
	if len(data) != 0 {
		t.Errorf("data length = %d, want 0 (empty payload)", len(data))
	}
	if constant != bech32Const {
		t.Errorf("constant = 0x%x, want bech32Const (0x%x)", constant, bech32Const)
	}
}

func TestBIP350CanonicalChecksumVector(t *testing.T) {
	hrp, data, constant, err := decodeGeneric("a1lqfn3a")
	if err != nil {
		t.Fatalf("decodeGeneric(a1lqfn3a) failed: %v", err)
	}
	if hrp != "a" {
		t.Errorf("hrp = %q, want %q", hrp, "a")
	}
	if len(data) != 0 {
		t.Errorf("data length = %d, want 0 (empty payload)", len(data))
	}
	if constant != bech32mConst {
		t.Errorf("constant = 0x%x, want bech32mConst (0x%x)", constant, bech32mConst)
	}
}

// TestEncodeMatchesCanonicalVectors confirms encodeGeneric produces exactly
// the canonical strings for empty payloads — i.e. encode is the true
// inverse of decode for these external vectors, not just self-consistent.
func TestEncodeMatchesCanonicalVectors(t *testing.T) {
	got, err := encodeGeneric("a", []byte{}, bech32Const)
	if err != nil {
		t.Fatalf("encodeGeneric (bech32) failed: %v", err)
	}
	if got != "a12uel5l" {
		t.Errorf("encodeGeneric(a, [], bech32Const) = %q, want %q", got, "a12uel5l")
	}

	got, err = encodeGeneric("a", []byte{}, bech32mConst)
	if err != nil {
		t.Fatalf("encodeGeneric (bech32m) failed: %v", err)
	}
	if got != "a1lqfn3a" {
		t.Errorf("encodeGeneric(a, [], bech32mConst) = %q, want %q", got, "a1lqfn3a")
	}
}

// TestCrossConstantRejected confirms that a string encoded with one
// constant fails verifyChecksum under the other — i.e. the two checksums
// are genuinely different, not coincidentally compatible.
func TestCrossConstantRejected(t *testing.T) {
	// "a12uel5l" is valid Bech32 (constant=1). It must NOT also report as
	// Bech32m — decodeGeneric returns whichever constant actually matches,
	// so this just re-confirms it's exactly bech32Const, not bech32mConst.
	_, _, constant, err := decodeGeneric("a12uel5l")
	if err != nil {
		t.Fatalf("decodeGeneric failed: %v", err)
	}
	if constant == bech32mConst {
		t.Error("a12uel5l (Bech32) was reported as matching the Bech32m constant")
	}

	_, _, constant, err = decodeGeneric("a1lqfn3a")
	if err != nil {
		t.Fatalf("decodeGeneric failed: %v", err)
	}
	if constant == bech32Const {
		t.Error("a1lqfn3a (Bech32m) was reported as matching the Bech32 constant")
	}
}

// ─── hash256 ────────────────────────────────────────────────────────────────

var mockPubKey32 = make([]byte, 32) // 32 zero bytes

// expectedHash256OfZerosHex is SHA256(SHA256(32 zero bytes)), verified in
// the prior version of this test suite (M1.2).
const expectedHash256OfZerosHex = "2b32db6c2c0a6235fb1397e8225ea85e0f0e6e8c7b126d0016ccbde0e667151e"

func TestHash256Vector(t *testing.T) {
	result := hash256(mockPubKey32)
	got := hex.EncodeToString(result)
	if got != expectedHash256OfZerosHex {
		t.Errorf("hash256 vector mismatch:\n  got  %s\n  want %s", got, expectedHash256OfZerosHex)
	}
}

// ─── Address derivation (P2QPK, witver=2, Bech32m) ────────────────────────────

func TestFromPublicKeyProducesBqPrefix(t *testing.T) {
	addr, err := FromPublicKey(mockPubKey32)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}
	if !strings.HasPrefix(addr, "bq1") {
		t.Errorf("address should start with 'bq1', got: %s", addr)
	}
	// charset[2] == 'z' (charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l", index 2).
	// witver=2 is the first 5-bit data value, so it should encode as 'z'
	// immediately after the '1' separator.
	if !strings.HasPrefix(addr, "bq1z") {
		t.Errorf("address should start with 'bq1z' (witness version 2 = charset[2] = 'z'), got: %s", addr)
	}
	t.Logf("Derived address: %s", addr)
}

func TestFromPublicKeyRoundTrip(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i) // 0x00..0x1f
	}
	addr, err := FromPublicKey(pub)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}
	decoded, err := ToHash(addr)
	if err != nil {
		t.Fatalf("ToHash failed: %v", err)
	}
	expected := hash256(pub)
	if !bytes.Equal(decoded, expected) {
		t.Errorf("round-trip mismatch:\n  got  %x\n  want %x", decoded, expected)
	}
}

func TestMatchesPublicKey(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = 0xAB
	}
	addr, err := FromPublicKey(pub)
	if err != nil {
		t.Fatalf("FromPublicKey: %v", err)
	}

	ok, err := MatchesPublicKey(addr, pub)
	if err != nil || !ok {
		t.Errorf("MatchesPublicKey should return true for correct key, got ok=%v err=%v", ok, err)
	}

	wrong := make([]byte, 32)
	ok, err = MatchesPublicKey(addr, wrong)
	if err != nil || ok {
		t.Errorf("MatchesPublicKey should return false for wrong key, got ok=%v err=%v", ok, err)
	}
}

func TestInvalidPublicKeyLength(t *testing.T) {
	_, err := FromPublicKey([]byte{0x01, 0x02}) // too short
	if err != ErrInvalidPublicKeyLength {
		t.Errorf("expected ErrInvalidPublicKeyLength, got: %v", err)
	}
}

func TestValidateAddressRejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"notanaddress",
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", // real Bitcoin address, wrong HRP
		"bq1invalidchecksum",
	}
	for _, c := range cases {
		if err := ValidateAddress(c); err == nil {
			t.Errorf("ValidateAddress(%q) should have failed", c)
		}
	}
}

// ─── Taproot rejection (witver=1) ──────────────────────────────────────────────
//
// Replaces the previous string-heuristic test with a real construction:
// build a witver=1 (Taproot-shaped) "bq" address using our own encode
// machinery (so the checksum is genuinely valid for witver=1/Bech32m), and
// confirm decode() identifies it as Taproot via the witness-version byte —
// not via any string pattern.

func TestTaprootRejected(t *testing.T) {
	hash := hash256(mockPubKey32) // any valid 32-byte program

	converted, err := bech32ConvertBits8to5(hash)
	if err != nil {
		t.Fatalf("ConvertBits failed: %v", err)
	}
	payload := append([]byte{1}, converted...) // witver = 1 (Taproot)

	taprootLikeAddr, err := encodeGeneric(HRP, payload, constantForWitnessVersion(1))
	if err != nil {
		t.Fatalf("encodeGeneric failed: %v", err)
	}
	t.Logf("Constructed witver=1 address: %s", taprootLikeAddr)

	_, err = ToHash(taprootLikeAddr)
	if err != ErrTaprootDetected {
		t.Errorf("decode of witver=1 address: got %v, want ErrTaprootDetected", err)
	}
}

// TestBIP350ConstantMismatchRejected confirms the BIP350 binding rule: a
// witver=2 payload encoded with the WRONG checksum constant (bech32Const,
// i.e. plain Bech32, which is only valid for witver=0) must be rejected,
// even though the witness version itself (2) is otherwise correct.
func TestBIP350ConstantMismatchRejected(t *testing.T) {
	hash := hash256(mockPubKey32)
	converted, err := bech32ConvertBits8to5(hash)
	if err != nil {
		t.Fatalf("ConvertBits failed: %v", err)
	}
	payload := append([]byte{WitnessVersion}, converted...) // witver = 2

	// Deliberately use bech32Const (wrong for witver=2 per BIP350).
	wrongAddr, err := encodeGeneric(HRP, payload, bech32Const)
	if err != nil {
		t.Fatalf("encodeGeneric failed: %v", err)
	}
	t.Logf("Constructed witver=2 address with WRONG (Bech32) constant: %s", wrongAddr)

	_, err = ToHash(wrongAddr)
	if err == nil {
		t.Error("decode should reject witver=2 payload encoded with the Bech32 (not Bech32m) constant")
	}
	if err == ErrTaprootDetected {
		t.Error("BIP350 constant-mismatch error should not be reported as ErrTaprootDetected")
	}
}

// TestWrongWitnessVersionRejected confirms that witver values other than
// 1 (Taproot, handled separately above) and 2 (this package's
// WitnessVersion) are rejected — e.g. witver=0 (P2WPKH/P2WSH) or witver=3.
func TestWrongWitnessVersionRejected(t *testing.T) {
	hash := hash256(mockPubKey32)
	converted, err := bech32ConvertBits8to5(hash)
	if err != nil {
		t.Fatalf("ConvertBits failed: %v", err)
	}

	for _, witver := range []byte{0, 3} {
		payload := append([]byte{witver}, converted...)
		addr, err := encodeGeneric(HRP, payload, constantForWitnessVersion(int(witver)))
		if err != nil {
			t.Fatalf("encodeGeneric failed for witver=%d: %v", witver, err)
		}
		if err := ValidateAddress(addr); err == nil {
			t.Errorf("ValidateAddress should reject witver=%d address: %s", witver, addr)
		}
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// bech32ConvertBits8to5 wraps bech32.ConvertBits(data, 8, 5, true) for test
// construction of payloads, matching encode()'s internal use of the same
// (exported, BIP350-unaffected) function from the project's existing
// btcutil dependency.
func bech32ConvertBits8to5(data []byte) ([]byte, error) {
	return bech32.ConvertBits(data, 8, 5, true)
}

// BenchmarkFromPublicKey measures address derivation throughput.
func BenchmarkFromPublicKey(b *testing.B) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = FromPublicKey(pub)
	}
}
