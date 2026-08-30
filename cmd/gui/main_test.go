package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateSeedHexProducesRandom32ByteSeeds(t *testing.T) {
	first, err := generateSeedHex()
	if err != nil {
		t.Fatalf("generateSeedHex first call: %v", err)
	}
	second, err := generateSeedHex()
	if err != nil {
		t.Fatalf("generateSeedHex second call: %v", err)
	}
	for name, value := range map[string]string{"first": first, "second": second} {
		if len(value) != 64 {
			t.Fatalf("%s generated seed has %d hex chars, want 64", name, len(value))
		}
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatalf("%s generated seed is not valid hex: %v", name, err)
		}
		if len(decoded) != 32 {
			t.Fatalf("%s generated seed has %d bytes, want 32", name, len(decoded))
		}
	}
	if first == second {
		t.Fatal("two crypto/rand seed generations unexpectedly matched")
	}
}

func TestDecodeSeedHexAcceptsGeneratedAndManualValues(t *testing.T) {
	generated, err := generateSeedHex()
	if err != nil {
		t.Fatal(err)
	}
	manual := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	for name, value := range map[string]string{"generated": generated, "manual": manual} {
		seed, err := decodeSeedHex(value)
		if err != nil {
			t.Fatalf("%s seed rejected: %v", name, err)
		}
		if len(seed) != 32 {
			t.Fatalf("%s decoded length = %d, want 32", name, len(seed))
		}
	}
}

func TestDecodeSeedHexRejectsMalformedAndWrongLength(t *testing.T) {
	for name, value := range map[string]string{
		"malformed": "not-hex",
		"too short": "00",
		"31 bytes":  strings.Repeat("00", 31),
		"33 bytes":  strings.Repeat("00", 33),
		"empty":     "",
	} {
		t.Run(name, func(t *testing.T) {
			if seed, err := decodeSeedHex(value); err == nil {
				t.Fatalf("decodeSeedHex(%q) returned %x, want error", value, seed)
			}
		})
	}
}

func TestDecodeCreateSeedHexRequiresBackupAcknowledgment(t *testing.T) {
	seedHex := strings.Repeat("01", 32)
	if seed, err := decodeCreateSeedHex(seedHex, false); err == nil {
		t.Fatalf("unacknowledged create returned %x, want error", seed)
	}
	seed, err := decodeCreateSeedHex(seedHex, true)
	if err != nil {
		t.Fatalf("acknowledged create seed rejected: %v", err)
	}
	if len(seed) != 32 {
		t.Fatalf("acknowledged create seed length = %d, want 32", len(seed))
	}
}
