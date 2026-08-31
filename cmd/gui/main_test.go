package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fynetest "fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/saogen/qoge-sphincs-wallet/internal/rpcclient"
	"github.com/saogen/qoge-sphincs-wallet/keystore"
	"github.com/saogen/qoge-sphincs-wallet/wallet"
)

func TestReadRPCCookie(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".cookie")
	wantPassword := strings.Repeat("a5", 32)
	if err := os.WriteFile(path, []byte(rpcCookieUsername+":"+wantPassword), 0o600); err != nil {
		t.Fatal(err)
	}

	cookie, found, err := readRPCCookie(path)
	if err != nil {
		t.Fatalf("readRPCCookie: %v", err)
	}
	if !found {
		t.Fatal("readRPCCookie reported a valid synthetic cookie missing")
	}
	if cookie.username != rpcCookieUsername || cookie.password != wantPassword {
		t.Fatalf("cookie = {%q, %q}, want {%q, %q}", cookie.username, cookie.password, rpcCookieUsername, wantPassword)
	}
}

func TestReadRPCCookieRejectsMalformedContents(t *testing.T) {
	for name, contents := range map[string]string{
		"wrong username": "user:" + strings.Repeat("a5", 32),
		"short password": rpcCookieUsername + ":a5",
		"non-hex":        rpcCookieUsername + ":" + strings.Repeat("zz", 32),
		"missing colon":  rpcCookieUsername + strings.Repeat("a5", 32),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".cookie")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, found, err := readRPCCookie(path); err == nil || found {
				t.Fatalf("readRPCCookie malformed result: found=%v err=%v, want false/error", found, err)
			}
		})
	}
}

func TestMissingRPCCookieLeavesConnectionUnchanged(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), ".cookie")
	if _, found, err := readRPCCookie(missingPath); err != nil || found {
		t.Fatalf("missing cookie: found=%v err=%v, want false/nil", found, err)
	}

	existing := rpcclient.New("remote.example:1234", "user", "password")
	connectCalled := false
	got, connected := tryLocalRPCConnection(missingPath, existing,
		func(endpoint, username, password string) (*rpcclient.Client, error) {
			connectCalled = true
			return rpcclient.New(endpoint, username, password), nil
		})
	if connected {
		t.Fatal("missing cookie reported an automatic connection")
	}
	if connectCalled {
		t.Fatal("connector called for a missing cookie")
	}
	if got != existing {
		t.Fatal("missing cookie changed the existing connection")
	}
}

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

func TestFilterAddressInfos(t *testing.T) {
	infos := []wallet.AddressInfo{
		{Address: "fresh", State: keystore.StateFresh},
		{Address: "funded", State: keystore.StateFunded},
		{Address: "pending", State: keystore.StateSpendPending},
		{Address: "spent", State: keystore.StateSpent},
		{Address: "retired", State: keystore.StateRetired},
	}

	visible, hidden := filterAddressInfos(infos, false)
	if hidden != 2 {
		t.Fatalf("hidden by default = %d, want 2", hidden)
	}
	want := []string{"fresh", "funded", "pending"}
	if len(visible) != len(want) {
		t.Fatalf("visible by default = %d, want %d", len(visible), len(want))
	}
	for i, addr := range want {
		if visible[i].Address != addr {
			t.Fatalf("visible[%d] = %q, want %q", i, visible[i].Address, addr)
		}
	}

	visible, hidden = filterAddressInfos(infos, true)
	if hidden != 0 || len(visible) != len(infos) {
		t.Fatalf("show all returned %d visible, %d hidden; want %d visible, 0 hidden", len(visible), hidden, len(infos))
	}
}

func TestShowSpentRetiredCheckboxTapTogglesFilter(t *testing.T) {
	infos := []wallet.AddressInfo{
		{State: keystore.StateFresh},
		{State: keystore.StateSpent},
		{State: keystore.StateRetired},
	}
	visibleCount, hiddenCount := 0, 0
	check := widget.NewCheck("Show spent/retired addresses", func(show bool) {
		visible, hidden := filterAddressInfos(infos, show)
		visibleCount, hiddenCount = len(visible), hidden
	})

	fynetest.Tap(check)
	if visibleCount != 3 || hiddenCount != 0 {
		t.Fatalf("after enable tap: visible=%d hidden=%d, want 3/0", visibleCount, hiddenCount)
	}
	fynetest.Tap(check)
	if visibleCount != 1 || hiddenCount != 2 {
		t.Fatalf("after disable tap: visible=%d hidden=%d, want 1/2", visibleCount, hiddenCount)
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
