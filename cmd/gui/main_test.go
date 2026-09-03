package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	fynetest "fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/btcsuite/btcutil/base58"

	qogeaddress "github.com/saogen/qoge-sphincs-wallet/address"
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

func TestRPCFooterStatusUpdates(t *testing.T) {
	status := widget.NewLabel("initial")

	updateRPCStatus(status, "remote.example:18332", nil)
	if status.Text != "Connected to remote.example:18332" {
		t.Fatalf("successful connect status = %q", status.Text)
	}

	updateRPCStatus(status, "", errors.New("node unreachable"))
	if status.Text != "Not connected — node unreachable" {
		t.Fatalf("failed connect status = %q", status.Text)
	}

	path := filepath.Join(t.TempDir(), ".cookie")
	if err := os.WriteFile(path, []byte(rpcCookieUsername+":"+strings.Repeat("a5", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	var current *rpcclient.Client
	current, connected := tryLocalRPCConnection(path, current,
		func(endpoint, username, password string) (*rpcclient.Client, error) {
			return rpcclient.New(endpoint, username, password), nil
		})
	if !connected || current == nil {
		t.Fatal("synthetic auto-connect did not succeed")
	}
	updateRPCStatus(status, localMainnetRPCEndpoint, nil)
	if status.Text != "Connected to 127.0.0.1:8332" {
		t.Fatalf("auto-connect status = %q", status.Text)
	}
}

func TestResolveSendDestinationKeepsWalletAndExternalModesSeparate(t *testing.T) {
	walletAddr, err := qogeaddress.FromPublicKey(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	externalAddr := base58.CheckEncode(bytes.Repeat([]byte{0x24}, 20), qogeaddress.MainnetPubKeyHashPrefix)

	addr, destination, err := resolveSendDestination(false, walletAddr, externalAddr)
	if err != nil {
		t.Fatalf("wallet mode: %v", err)
	}
	if addr != walletAddr || destination.Type != qogeaddress.DestinationP2QPK {
		t.Fatalf("wallet mode resolved %q/%s, want wallet P2QPK", addr, destination.Type)
	}

	addr, destination, err = resolveSendDestination(true, walletAddr, externalAddr)
	if err != nil {
		t.Fatalf("external mode: %v", err)
	}
	if addr != externalAddr || destination.Type != qogeaddress.DestinationP2PKH {
		t.Fatalf("external mode resolved %q/%s, want external P2PKH", addr, destination.Type)
	}

	tampered := externalAddr[:len(externalAddr)-1] + "1"
	if _, _, err := resolveSendDestination(true, walletAddr, tampered); err == nil {
		t.Fatal("external mode accepted a checksum-tampered address")
	}
	if _, _, err := resolveSendDestination(false, "", externalAddr); err == nil {
		t.Fatal("wallet mode fell back to the populated external field")
	}
	if _, _, err := resolveSendDestination(true, walletAddr, ""); err == nil {
		t.Fatal("external mode fell back to the selected wallet address")
	}
}

func TestMainTabsPutWalletFirstAndGateWalletDependentTabs(t *testing.T) {
	walletTab := container.NewTabItem("Wallet", widget.NewLabel("wallet"))
	addressesTab := container.NewTabItem("My Addresses", widget.NewLabel("addresses"))
	sendTab := container.NewTabItem("Send", widget.NewLabel("send"))
	networkTab := container.NewTabItem("Network", widget.NewLabel("network"))

	tabs := newMainTabs(walletTab, addressesTab, sendTab, networkTab)
	wantOrder := []string{"Wallet", "My Addresses", "Send", "Network"}
	if len(tabs.Items) != len(wantOrder) {
		t.Fatalf("tab count = %d, want %d", len(tabs.Items), len(wantOrder))
	}
	for i, want := range wantOrder {
		if tabs.Items[i].Text != want {
			t.Fatalf("tab %d = %q, want %q", i, tabs.Items[i].Text, want)
		}
	}
	if walletTab.Disabled() || networkTab.Disabled() {
		t.Fatal("Wallet and Network must be available before a wallet is loaded")
	}
	for _, item := range []*container.TabItem{addressesTab, sendTab} {
		if !item.Disabled() {
			t.Fatalf("%s tab enabled before wallet load", item.Text)
		}
		tabs.EnableItem(item)
		if item.Disabled() {
			t.Fatalf("%s tab remained disabled after wallet load", item.Text)
		}
	}
}

func TestMainTabsHeadlessClickGating(t *testing.T) {
	fynetest.NewApp()
	defer fynetest.NewApp()

	walletTab := container.NewTabItem("Wallet", widget.NewLabel("wallet"))
	addressesTab := container.NewTabItem("My Addresses", widget.NewLabel("addresses"))
	sendTab := container.NewTabItem("Send", widget.NewLabel("send"))
	networkTab := container.NewTabItem("Network", widget.NewLabel("network"))
	tabs := newMainTabs(walletTab, addressesTab, sendTab, networkTab)
	w := fynetest.NewWindow(tabs)
	defer w.Close()
	w.SetPadded(false)
	w.Resize(fyne.NewSize(620, 120))

	fynetest.TapCanvas(w.Canvas(), fyne.NewPos(130, 10))
	if tabs.Selected() != walletTab {
		t.Fatalf("clicking disabled My Addresses selected %q, want Wallet", tabs.Selected().Text)
	}
	fynetest.TapCanvas(w.Canvas(), fyne.NewPos(300, 10))
	if tabs.Selected() != networkTab {
		t.Fatalf("clicking enabled Network selected %q, want Network", tabs.Selected().Text)
	}
}

func TestEqualWidthButtonsMatchWidest(t *testing.T) {
	fynetest.NewApp()
	defer fynetest.NewApp()

	createBtn := widget.NewButton("Create New Wallet", nil)
	generateBtn := widget.NewButton("Generate New Seed", nil)
	wrapped := equalWidthButtons(createBtn, generateBtn)
	if len(wrapped) != 2 {
		t.Fatalf("wrapped count = %d, want 2", len(wrapped))
	}
	if wrapped[0].MinSize().Width != wrapped[1].MinSize().Width {
		t.Fatalf("button widths %v vs %v", wrapped[0].MinSize().Width, wrapped[1].MinSize().Width)
	}
	want := createBtn.MinSize().Width
	if generateBtn.MinSize().Width > want {
		want = generateBtn.MinSize().Width
	}
	if wrapped[0].MinSize().Width != want {
		t.Fatalf("fixed width = %v, want %v", wrapped[0].MinSize().Width, want)
	}
}

func TestBroadcastGateRequiresAllowedCurrentTransaction(t *testing.T) {
	button := widget.NewButton("Broadcast", nil)
	var gate broadcastGate

	gate.Reset(button)
	if !button.Disabled() || gate.Allows("tx-a") {
		t.Fatal("broadcast available before mempool approval")
	}

	gate.RecordMempoolResult("tx-a", false, button)
	if !button.Disabled() || gate.Allows("tx-a") {
		t.Fatal("rejected mempool test enabled broadcast")
	}

	gate.RecordMempoolResult("tx-a", true, button)
	if button.Disabled() || !gate.Allows("tx-a") {
		t.Fatal("allowed mempool test did not enable the approved transaction")
	}
	if gate.Allows("tx-b") {
		t.Fatal("approval for tx-a authorized a different signed transaction")
	}

	gate.Reset(button) // Preview/re-sign starts a new transaction cycle.
	if !button.Disabled() || gate.Allows("tx-a") || gate.Allows("tx-b") {
		t.Fatal("new preview/sign cycle did not clear broadcast approval")
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
