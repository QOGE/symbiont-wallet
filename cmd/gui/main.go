// cmd/gui/main.go — Fyne GUI for Symbiont Wallet
//
// Three tabs:
//   - Receive:   explicitly open or create a wallet and generate a fresh P2QPK address.
//   - Addresses: list every address with its lifecycle state and optional on-chain balance.
//   - Send:      build, preview, sign, and display a raw P2QPK spend transaction.
//     broadcast is manual (copy hex → qogecoin-cli sendrawtransaction).
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/saogen/qoge-sphincs-wallet/internal/rpcclient"
	"github.com/saogen/qoge-sphincs-wallet/internal/txbuilder"
	"github.com/saogen/qoge-sphincs-wallet/keystore"
	"github.com/saogen/qoge-sphincs-wallet/wallet"
)

const (
	localMainnetRPCEndpoint = "127.0.0.1:8332"
	localRPCProbeTimeout    = 2 * time.Second
	rpcCookieUsername       = "__cookie__"
)

type rpcCookie struct {
	username string
	password string
}

// defaultRPCCookiePath is Qogecoin's standard mainnet cookie location.
// Nodes using a custom datadir or -rpccookiefile remain available through the
// manual connection controls.
func defaultRPCCookiePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".qogecoin", ".cookie")
}

// readRPCCookie reads the exact credential format emitted by qogecoind:
// __cookie__:<64 hex characters>. A missing file is an ordinary, silent miss.
func readRPCCookie(path string) (rpcCookie, bool, error) {
	if path == "" {
		return rpcCookie{}, false, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return rpcCookie{}, false, nil
	}
	if err != nil {
		return rpcCookie{}, false, fmt.Errorf("read RPC cookie: %w", err)
	}

	value := strings.TrimSuffix(string(raw), "\n")
	value = strings.TrimSuffix(value, "\r")
	user, password, ok := strings.Cut(value, ":")
	if !ok || user != rpcCookieUsername || len(password) != 64 {
		return rpcCookie{}, false, fmt.Errorf("invalid RPC cookie format")
	}
	decoded, err := hex.DecodeString(password)
	if err != nil || len(decoded) != 32 {
		return rpcCookie{}, false, fmt.Errorf("invalid RPC cookie password")
	}
	keystore.ZeroBytes(decoded)
	return rpcCookie{username: user, password: password}, true, nil
}

type localRPCConnector func(endpoint, username, password string) (*rpcclient.Client, error)

func updateRPCStatus(label *widget.Label, endpoint string, err error) {
	if err != nil {
		label.SetText(fmt.Sprintf("Not connected — %v", err))
		return
	}
	if endpoint == "" {
		label.SetText("Not connected")
		return
	}
	label.SetText(fmt.Sprintf("Connected to %s", endpoint))
}

// tryLocalRPCConnection preserves current on every miss or failure. Automatic
// discovery is deliberately silent; only a successful connection is reported
// to the GUI by the caller.
func tryLocalRPCConnection(cookiePath string, current *rpcclient.Client, connect localRPCConnector) (*rpcclient.Client, bool) {
	cookie, found, err := readRPCCookie(cookiePath)
	if err != nil || !found {
		return current, false
	}
	candidate, err := connect(localMainnetRPCEndpoint, cookie.username, cookie.password)
	if err != nil {
		return current, false
	}
	return candidate, true
}

// walletDBPath returns the absolute path to the wallet database.
// Using os.UserHomeDir() prevents silent mismatches when the GUI is
// launched from different working directories.
func walletDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "qoge_wallet.db"
	}
	return filepath.Join(home, "symbiont-wallet", "qoge_wallet.db")
}

func generateSeedHex() (string, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return "", fmt.Errorf("generate seed with crypto/rand: %w", err)
	}
	defer keystore.ZeroBytes(seed)
	return hex.EncodeToString(seed), nil
}

func decodeSeedHex(seedHex string) ([]byte, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != 32 {
		return nil, fmt.Errorf("seed must be exactly 32 bytes, hex-encoded (64 hex chars)")
	}
	return seed, nil
}

func decodeCreateSeedHex(seedHex string, backupConfirmed bool) ([]byte, error) {
	seed, err := decodeSeedHex(seedHex)
	if err != nil {
		return nil, err
	}
	if !backupConfirmed {
		keystore.ZeroBytes(seed)
		return nil, fmt.Errorf("confirm that you have saved the seed before creating the wallet")
	}
	return seed, nil
}

func filterAddressInfos(infos []wallet.AddressInfo, showSpentRetired bool) (visible []wallet.AddressInfo, hidden int) {
	visible = make([]wallet.AddressInfo, 0, len(infos))
	for _, info := range infos {
		historical := info.State == keystore.StateSpent || info.State == keystore.StateRetired
		if historical && !showSpentRetired {
			hidden++
			continue
		}
		visible = append(visible, info)
	}
	return visible, hidden
}

func newMainTabs(walletTab, receiveTab, networkTab, addressesTab, sendTab *container.TabItem) *container.AppTabs {
	tabs := container.NewAppTabs(walletTab, receiveTab, networkTab, addressesTab, sendTab)
	tabs.DisableItem(receiveTab)
	tabs.DisableItem(addressesTab)
	tabs.DisableItem(sendTab)
	return tabs
}

func main() {
	a := app.NewWithID("io.qoge.symbiont-wallet")
	w := a.NewWindow("Symbiont Wallet")
	w.Resize(fyne.NewSize(620, 640))

	var wlt *wallet.Wallet
	var rpc *rpcclient.Client
	var tabs *container.AppTabs
	var receiveTab, addressesTab, sendTab *container.TabItem
	var rpcFooterStatus *widget.Label

	// ── Wallet and Receive tabs ────────────────────────────────────────────────────────

	walletStatus := widget.NewLabel("No wallet open.")
	walletStatus.Wrapping = fyne.TextWrapWord

	addrDisplay := widget.NewEntry()
	addrDisplay.Disable()

	seedEntry := widget.NewPasswordEntry()
	seedEntry.SetPlaceHolder("32-byte seed, hex-encoded (64 hex chars)")

	generatedSeedDisplay := widget.NewEntry()
	generatedSeedDisplay.Disable()
	generatedSeedDisplay.TextStyle = fyne.TextStyle{Monospace: true}

	backupWarning := widget.NewLabel(
		"SAVE THIS SEED NOW — THIS IS THE ONLY COPY. If it is lost, funds sent " +
			"to this wallet could become permanently unrecoverable.",
	)
	backupWarning.Wrapping = fyne.TextWrapWord
	backupWarning.TextStyle = fyne.TextStyle{Bold: true}

	seedSavedCheck := widget.NewCheck("I have saved this seed securely", nil)
	copySeedBtn := widget.NewButton("Copy Generated Seed", func() {
		if generatedSeedDisplay.Text != "" {
			w.Clipboard().SetContent(generatedSeedDisplay.Text)
			walletStatus.SetText("Generated seed copied. Save it securely before creating the wallet.")
		}
	})
	backupPanel := container.NewVBox(
		widget.NewSeparator(),
		backupWarning,
		generatedSeedDisplay,
		copySeedBtn,
	)
	backupPanel.Hide()

	seedEntry.OnChanged = func(seedHex string) {
		seedSavedCheck.SetChecked(false)
		if generatedSeedDisplay.Text != "" && seedHex != generatedSeedDisplay.Text {
			generatedSeedDisplay.SetText("")
			backupPanel.Hide()
		}
	}

	generateBtn := widget.NewButton("Generate New Seed", func() {
		seedHex, err := generateSeedHex()
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		seedEntry.SetText(seedHex)
		generatedSeedDisplay.SetText(seedHex)
		seedSavedCheck.SetChecked(false)
		backupPanel.Show()
		walletStatus.SetText("New seed generated. Save the displayed seed and acknowledge the backup before creating the wallet.")
	})

	loadWallet := func(create bool) {
		var seed []byte
		var err error
		if create {
			seed, err = decodeCreateSeedHex(seedEntry.Text, seedSavedCheck.Checked)
		} else {
			seed, err = decodeSeedHex(seedEntry.Text)
		}
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		if wlt != nil {
			wlt.Close()
			wlt = nil
		}
		var newWallet *wallet.Wallet
		if create {
			newWallet, err = wallet.CreateNew(walletDBPath(), seed)
		} else {
			newWallet, err = wallet.OpenExisting(walletDBPath(), seed)
		}
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		wlt = newWallet
		if tabs != nil {
			tabs.EnableItem(receiveTab)
			tabs.EnableItem(addressesTab)
			tabs.EnableItem(sendTab)
		}
		if create {
			walletStatus.SetText("New wallet created.")
		} else {
			walletStatus.SetText("Existing wallet opened.")
		}

		var connected bool
		rpc, connected = tryLocalRPCConnection(defaultRPCCookiePath(), rpc, func(endpoint, username, password string) (*rpcclient.Client, error) {
			candidate := rpcclient.New(endpoint, username, password)
			ctx, cancel := context.WithTimeout(context.Background(), localRPCProbeTimeout)
			defer cancel()
			if err := candidate.Ping(ctx); err != nil {
				return nil, err
			}
			return candidate, nil
		})
		if connected && rpcFooterStatus != nil {
			updateRPCStatus(rpcFooterStatus, localMainnetRPCEndpoint, nil)
		}
	}

	openBtn := widget.NewButton("Open Existing Wallet", func() {
		loadWallet(false)
	})
	createBtn := widget.NewButton("Create New Wallet", func() {
		loadWallet(true)
	})

	newAddrBtn := widget.NewButton("Generate New Address", func() {
		if wlt == nil {
			dialog.ShowError(fmt.Errorf("open a wallet first"), w)
			return
		}
		addr, err := wlt.NextReceiveAddress()
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		addrDisplay.SetText(addr)
	})

	concentrationWarning := widget.NewLabel(
		"For technical safety, avoid holding more than 5,000,000 QOGE in a " +
			"single address. Very large single-address balances can affect how this " +
			"wallet processes transactions. Consider spreading large holdings across " +
			"multiple addresses instead.",
	)
	concentrationWarning.Wrapping = fyne.TextWrapWord

	copyAddrBtn := widget.NewButton("Copy Address", func() {
		addr := addrDisplay.Text
		if addr == "" {
			return
		}
		w.Clipboard().SetContent(addr)
	})

	walletTab := container.NewTabItem("Wallet",
		container.NewVBox(
			widget.NewLabel("Seed (hex, 64 chars):"),
			seedEntry,
			generateBtn,
			backupPanel,
			seedSavedCheck,
			openBtn,
			createBtn,
			widget.NewSeparator(),
			walletStatus,
		),
	)

	receiveTab = container.NewTabItem("Receive",
		container.NewVBox(
			newAddrBtn,
			widget.NewLabel("Your P2QPK address:"),
			addrDisplay,
			copyAddrBtn,
			widget.NewSeparator(),
			concentrationWarning,
		),
	)

	// ── Addresses tab ──────────────────────────────────────────────────────

	addrListBox := container.NewVBox()
	addrListScroll := container.NewVScroll(addrListBox)
	addrListScroll.SetMinSize(fyne.NewSize(0, 220))

	addrStatusLabel := widget.NewLabel("Open a wallet, then press Refresh.")
	addrStatusLabel.Wrapping = fyne.TextWrapWord

	type addressRenderState struct {
		infos                  []wallet.AddressInfo
		balances               map[string]int64
		balanceErr             string
		fundedDetected         int
		spentDetected          int
		pendingTxNotFound      int
		pendingTxIndexRequired int
		pendingTxUntracked     int
		nodeConnected          bool
	}
	var lastAddressRender addressRenderState
	var hasAddressSnapshot bool
	var showSpentRetired bool

	renderAddressList := func() {
		if !hasAddressSnapshot {
			return
		}
		visible, hidden := filterAddressInfos(lastAddressRender.infos, showSpentRetired)
		addrListBox.RemoveAll()
		if len(visible) == 0 {
			addrListBox.Add(widget.NewLabel("(no visible addresses)"))
		}
		var overThresholdCount int
		for _, info := range visible {
			addr := info.Address
			stateLabel := info.State.String()
			if info.Reserved {
				stateLabel = "FRESH/RESERVED"
			}
			var line string
			if lastAddressRender.balances != nil {
				sats := lastAddressRender.balances[addr]
				if rpcclient.ExceedsConcentrationThreshold(sats) {
					overThresholdCount++
					line = fmt.Sprintf("[!] #%-3d  %-13s %-14s  %s",
						info.Index, stateLabel, rpcclient.FormatQOGE(sats)+" QOGE", addr)
				} else {
					line = fmt.Sprintf("    #%-3d  %-13s %-14s  %s",
						info.Index, stateLabel, rpcclient.FormatQOGE(sats)+" QOGE", addr)
				}
			} else {
				line = fmt.Sprintf("#%-3d  %-13s %s", info.Index, stateLabel, addr)
			}
			lbl := widget.NewLabel(line)
			lbl.TextStyle = fyne.TextStyle{Monospace: true}
			copyBtn := widget.NewButton("Copy", func() {
				w.Clipboard().SetContent(addr)
				addrStatusLabel.SetText("Address copied to clipboard.")
			})
			addrListBox.Add(container.NewBorder(nil, nil, nil, copyBtn, lbl))
		}
		addrListBox.Refresh()

		summary := fmt.Sprintf("%d address(es)", len(lastAddressRender.infos))
		if hidden > 0 {
			summary += fmt.Sprintf(" (%d spent/retired hidden)", hidden)
		}
		if lastAddressRender.balanceErr != "" {
			summary += " — " + lastAddressRender.balanceErr
		} else if lastAddressRender.balances != nil {
			if overThresholdCount > 0 {
				summary += fmt.Sprintf(" — [!] %d visible address(es) exceed the recommended single-address limit", overThresholdCount)
			} else {
				summary += " — balances from node"
			}
			if lastAddressRender.fundedDetected > 0 {
				summary += fmt.Sprintf(" — %d address(es) auto-detected as FUNDED", lastAddressRender.fundedDetected)
			}
			if lastAddressRender.spentDetected > 0 {
				summary += fmt.Sprintf(" — %d address(es) auto-detected as SPENT", lastAddressRender.spentDetected)
			}
			if lastAddressRender.pendingTxNotFound > 0 {
				summary += fmt.Sprintf(" — %d pending transaction(s) not yet broadcast or not known to the node", lastAddressRender.pendingTxNotFound)
			}
			if lastAddressRender.pendingTxIndexRequired > 0 {
				summary += fmt.Sprintf(" — %d pending transaction(s) require qogecoind -txindex for confirmed-chain lookup", lastAddressRender.pendingTxIndexRequired)
			}
			if lastAddressRender.pendingTxUntracked > 0 {
				summary += fmt.Sprintf(" — %d legacy/untracked SPEND_PENDING address(es) require manual confirmation", lastAddressRender.pendingTxUntracked)
			}
		} else if !lastAddressRender.nodeConnected {
			summary += " — no node connected, state only"
		}
		addrStatusLabel.SetText(summary)
	}

	showSpentRetiredCheck := widget.NewCheck("Show spent/retired addresses", func(show bool) {
		showSpentRetired = show
		renderAddressList()
	})

	rpcEndpoint := widget.NewEntry()
	rpcEndpoint.SetPlaceHolder("host:port  (e.g. 127.0.0.1:8332)")
	rpcUser := widget.NewEntry()
	rpcUser.SetPlaceHolder("RPC username")
	rpcPass := widget.NewPasswordEntry()
	rpcPass.SetPlaceHolder("RPC password")

	rpcFooterStatus = widget.NewLabel("Not connected")
	rpcFooterStatus.Wrapping = fyne.TextWrapWord

	connectBtn := widget.NewButton("Connect to Node", func() {
		ep := rpcEndpoint.Text
		user := rpcUser.Text
		pass := rpcPass.Text
		if ep == "" {
			rpc = nil
			updateRPCStatus(rpcFooterStatus, "", nil)
			return
		}
		c := rpcclient.New(ep, user, pass)
		if err := c.Ping(context.Background()); err != nil {
			rpc = nil
			updateRPCStatus(rpcFooterStatus, "", fmt.Errorf("node unreachable: %w", err))
			return
		}
		rpc = c
		updateRPCStatus(rpcFooterStatus, ep, nil)
	})

	networkTab := container.NewTabItem("Network",
		container.NewVBox(
			widget.NewLabel("Node RPC connection:"),
			rpcEndpoint,
			rpcUser,
			rpcPass,
			connectBtn,
			widget.NewLabel("Local cookie authentication is attempted automatically when a wallet is opened or created."),
		),
	)

	refreshBtn := widget.NewButton("Refresh", func() {
		if wlt == nil {
			addrStatusLabel.SetText("Open a wallet first.")
			return
		}
		infos, err := wlt.ListAddresses()
		if err != nil {
			addrStatusLabel.SetText(fmt.Sprintf("Error: %v", err))
			return
		}

		var balances map[string]int64
		var balanceErr string
		var fundedDetected int
		var spentDetected int
		var pendingTxNotFound int
		var pendingTxIndexRequired int
		var pendingTxUntracked int
		if rpc != nil && len(infos) > 0 {
			descs := make([]string, len(infos))
			addrs := make([]string, len(infos))
			for i, info := range infos {
				descs[i] = "addr(" + info.Address + ")"
				addrs[i] = info.Address
			}
			result, err := rpc.ScanTxOutSet(context.Background(), descs)
			if err != nil {
				balanceErr = fmt.Sprintf("Balance lookup failed: %v", err)
			} else {
				balances, err = rpcclient.AggregateBalances(result, addrs)
				if err != nil {
					balanceErr = fmt.Sprintf("Balance aggregation error: %v", err)
					balances = nil
				} else {
					freshAddrs := make([]string, 0)
					for _, info := range infos {
						if info.State == keystore.StateFresh {
							freshAddrs = append(freshAddrs, info.Address)
						}
					}
					funding, fundingErr := rpcclient.AnalyzeFunding(result, freshAddrs)
					if fundingErr != nil {
						balanceErr = fmt.Sprintf("Funding analysis error: %v", fundingErr)
					} else {
						for _, addr := range freshAddrs {
							fs := funding[addr]
							changed, observeErr := wlt.ObserveFunding(addr, fs.BalanceSats, fs.Confirmations)
							if observeErr != nil {
								balanceErr = fmt.Sprintf("Funding state update failed: %v", observeErr)
								break
							}
							if changed {
								fundedDetected++
							}
						}
						if fundedDetected > 0 && balanceErr == "" {
							infos, err = wlt.ListAddresses()
							if err != nil {
								balanceErr = fmt.Sprintf("Address reload failed: %v", err)
							}
							for _, info := range infos {
								if _, ok := balances[info.Address]; !ok {
									balances[info.Address] = 0
								}
							}
						}
					}
				}
			}
		}

		if rpc != nil {
			for _, info := range infos {
				if info.State != keystore.StateSpendPending {
					continue
				}
				if info.SpendTxID == "" {
					pendingTxUntracked++
					continue
				}
				confirmations, found, confirmErr := rpc.TransactionConfirmations(context.Background(), info.SpendTxID)
				if confirmErr != nil {
					if errors.Is(confirmErr, rpcclient.ErrTxIndexRequired) {
						pendingTxIndexRequired++
						continue
					}
					if balanceErr == "" {
						balanceErr = fmt.Sprintf("Spend confirmation lookup failed: %v", confirmErr)
					}
					continue
				}
				if !found {
					pendingTxNotFound++
					continue
				}
				changed, confirmErr := wlt.ObserveSpendConfirmation(info.Address, info.SpendTxID, confirmations)
				if confirmErr != nil {
					if balanceErr == "" {
						balanceErr = fmt.Sprintf("Spend state update failed: %v", confirmErr)
					}
					continue
				}
				if changed {
					spentDetected++
				}
			}
			if spentDetected > 0 {
				infos, err = wlt.ListAddresses()
				if err != nil && balanceErr == "" {
					balanceErr = fmt.Sprintf("Address reload after spend confirmation failed: %v", err)
				}
			}
		}

		lastAddressRender = addressRenderState{
			infos:                  infos,
			balances:               balances,
			balanceErr:             balanceErr,
			fundedDetected:         fundedDetected,
			spentDetected:          spentDetected,
			pendingTxNotFound:      pendingTxNotFound,
			pendingTxIndexRequired: pendingTxIndexRequired,
			pendingTxUntracked:     pendingTxUntracked,
			nodeConnected:          rpc != nil,
		}
		hasAddressSnapshot = true
		renderAddressList()
	})

	addressesTab = container.NewTabItem("Addresses",
		container.NewVBox(
			refreshBtn,
			showSpentRetiredCheck,
			addrListScroll,
			widget.NewSeparator(),
			addrStatusLabel,
		),
	)

	// ── Send tab ───────────────────────────────────────────────────────────
	//
	// Flow:
	//   1. Select From address (must be FUNDED)
	//   2. Select To address (must be FRESH — wallet-controlled)
	//   3. Enter amount in QOGE
	//   4. Click "Preview" → fetches UTXO, computes change, shows confirm dialog
	//   5. Click "Sign" in dialog → signs, serializes BIP144, displays raw hex
	//   6. Broadcast manually: qogecoin-cli sendrawtransaction <hex>
	//
	// Refresh automatically marks the source SPENT after its tracked transaction
	// reaches one on-chain confirmation.

	sendFromSelect := widget.NewSelect(nil, nil)
	sendFromSelect.PlaceHolder = "(no FUNDED addresses — refresh after 20 confirmations)"

	sendToSelect := widget.NewSelect(nil, nil)
	sendToSelect.PlaceHolder = "(no FRESH addresses)"

	amountEntry := widget.NewEntry()
	amountEntry.SetPlaceHolder("e.g. 1 or 0.5")

	sendStatusLabel := widget.NewLabel("")
	sendStatusLabel.Wrapping = fyne.TextWrapWord

	// signedTxHex holds the complete hex of the last signed transaction in
	// memory. It is never rendered directly into a text widget — only a short
	// preview is shown on screen to avoid freezing the GUI with 34,528 chars.
	var signedTxHex string

	rawHexPreviewLabel := widget.NewLabel("(no signed transaction yet)")
	rawHexPreviewLabel.TextStyle = fyne.TextStyle{Monospace: true}

	copyTxHexBtn := widget.NewButton("Copy Full Transaction Hex", func() {
		if signedTxHex == "" {
			sendStatusLabel.SetText("No signed transaction — preview and sign first.")
			return
		}
		w.Clipboard().SetContent(signedTxHex)
		sendStatusLabel.SetText("Full transaction hex copied to clipboard.")
	})

	testMempoolBtn := widget.NewButton("Test in Mempool (testmempoolaccept)", func() {
		if signedTxHex == "" {
			sendStatusLabel.SetText("No signed transaction — preview and sign first.")
			return
		}
		if rpc == nil {
			sendStatusLabel.SetText("No node connected — connect from the Addresses tab first.")
			return
		}
		result, err := rpc.TestMempoolAccept(context.Background(), signedTxHex)
		if err != nil {
			sendStatusLabel.SetText(fmt.Sprintf("testmempoolaccept RPC error: %v", err))
			return
		}
		if result.Allowed {
			sendStatusLabel.SetText(fmt.Sprintf(
				"testmempoolaccept: ALLOWED  vsize=%d  fee=%g QOGE", result.VSize, result.Fees.Base))
		} else {
			sendStatusLabel.SetText(fmt.Sprintf(
				"testmempoolaccept: REJECTED  reason: %s", result.RejectReason))
		}
	})

	// populateSendDropdowns refreshes the From/To dropdowns from the current
	// wallet state. Called each time the Preview button is clicked so the
	// lists stay accurate.
	populateSendDropdowns := func() {
		if wlt == nil {
			return
		}
		infos, err := wlt.ListAddresses()
		if err != nil {
			return
		}
		var funded, fresh []string
		for _, info := range infos {
			switch info.State {
			case keystore.StateFunded:
				funded = append(funded, info.Address)
			case keystore.StateFresh:
				if !info.Reserved {
					fresh = append(fresh, info.Address)
				}
			}
		}
		sendFromSelect.Options = funded
		if len(funded) == 0 {
			sendFromSelect.PlaceHolder = "(no FUNDED addresses — refresh after 20 confirmations)"
			sendFromSelect.Selected = ""
		}
		sendFromSelect.Refresh()

		sendToSelect.Options = fresh
		if len(fresh) == 0 {
			sendToSelect.PlaceHolder = "(no FRESH addresses)"
			sendToSelect.Selected = ""
		}
		sendToSelect.Refresh()
	}

	previewBtn := widget.NewButton("Preview Transaction", func() {
		if wlt == nil {
			sendStatusLabel.SetText("Open a wallet first.")
			return
		}
		if rpc == nil {
			sendStatusLabel.SetText("Node RPC required to fetch UTXO — connect from the Addresses tab.")
			return
		}

		populateSendDropdowns()

		fromAddr := sendFromSelect.Selected
		if fromAddr == "" {
			sendStatusLabel.SetText("Select a From address (FUNDED).")
			return
		}
		toAddr := sendToSelect.Selected
		if toAddr == "" {
			sendStatusLabel.SetText("Select a To address (FRESH).")
			return
		}

		sendSats, err := txbuilder.QOGEToSatoshis(amountEntry.Text)
		if err != nil {
			sendStatusLabel.SetText(fmt.Sprintf("Invalid amount: %v", err))
			return
		}
		if sendSats <= 0 {
			sendStatusLabel.SetText("Amount must be positive.")
			return
		}

		sendStatusLabel.SetText("Fetching UTXO from node...")

		// Fetch the live UTXO for the From address.
		scanResult, err := rpc.ScanTxOutSet(context.Background(), []string{"addr(" + fromAddr + ")"})
		if err != nil {
			sendStatusLabel.SetText(fmt.Sprintf("scantxoutset error: %v", err))
			return
		}
		if len(scanResult.Unspents) == 0 {
			sendStatusLabel.SetText("No UTXOs found for From address — has the payment confirmed on-chain?")
			return
		}
		if len(scanResult.Unspents) > 1 {
			sendStatusLabel.SetText(fmt.Sprintf(
				"WARNING: %d UTXOs for From address — this tool handles exactly one. Select a different address or split manually.",
				len(scanResult.Unspents)))
			return
		}
		utxo := scanResult.Unspents[0]

		// Fix 1: convert UTXO amount via string decimal parsing, not float64
		// multiplication. FloatQOGEToSatoshis goes through fmt.Sprintf("%.8f")
		// and integer arithmetic — no float64 satoshi arithmetic in the signing path.
		utxoSats, err := rpcclient.FloatQOGEToSatoshis(utxo.Amount)
		if err != nil {
			sendStatusLabel.SetText(fmt.Sprintf("UTXO amount conversion error: %v", err))
			return
		}

		feeSats := txbuilder.FixedFeeSats
		changeSats, err := txbuilder.CalcChange(utxoSats, sendSats, feeSats)
		if err != nil {
			sendStatusLabel.SetText(err.Error())
			return
		}

		// Fix 2: decode the RPC-returned scriptPubKey bytes now, so the wallet's
		// ErrFromAddrScriptMismatch check runs against real on-chain data, not a
		// value re-derived from fromAddr (which would always match and make the
		// check a tautology).
		fromScriptBytes, err := hex.DecodeString(utxo.ScriptPubKey)
		if err != nil {
			sendStatusLabel.SetText(fmt.Sprintf("UTXO scriptPubKey decode error: %v", err))
			return
		}

		// Fix 3: zero-change path — peek changeAddr only when there is actual
		// change to route. When changeSats == 0 the UTXO exactly covers send+fee;
		// building a zero-value change output is non-standard and wastes an address.
		var changeAddr string
		if changeSats > 0 {
			changeAddr, err = wlt.NextReceiveAddress()
			if err != nil {
				sendStatusLabel.SetText(fmt.Sprintf("Cannot select change address: %v", err))
				return
			}
			if changeAddr == toAddr {
				sendStatusLabel.SetText(
					"Change address conflicts with To address — both would be the lowest-index FRESH address.\n" +
						"Generate more addresses (Receive tab) or pick a different To address.")
				return
			}
		}

		// Build the preview text shown in the confirm dialog.
		var changeLines string
		if changeSats > 0 {
			changeLines = fmt.Sprintf("Change:    %s QOGE  (%d sat)\n  → to:   %s\n\n",
				rpcclient.FormatQOGE(changeSats), changeSats, changeAddr)
		} else {
			changeLines = "Change:    none (exact spend — no change output)\n\n"
		}
		previewText := fmt.Sprintf(
			"From:      %s\n\n"+
				"To:        %s\n\n"+
				"Amount:    %s QOGE  (%d sat)\n"+
				"Fee:       0.00010000 QOGE  (%d sat)  [fixed]\n"+
				"%s"+
				"UTXO:      %s:%d  (%s QOGE)\n\n"+
				"⚠  This will irreversibly spend real mainnet QOGE.\n"+
				"   The signed transaction will NOT be broadcast automatically.\n"+
				"   You must broadcast it manually via:\n"+
				"     qogecoin-cli sendrawtransaction <hex>",
			fromAddr,
			toAddr,
			rpcclient.FormatQOGE(sendSats), sendSats,
			feeSats,
			changeLines,
			utxo.Txid, utxo.Vout, rpcclient.FormatQOGE(utxoSats),
		)

		content := widget.NewLabel(previewText)
		content.TextStyle = fyne.TextStyle{Monospace: true}
		content.Wrapping = fyne.TextWrapBreak

		scrolledContent := container.NewVScroll(content)
		scrolledContent.SetMinSize(fyne.NewSize(540, 280))

		sendStatusLabel.SetText("Preview ready — confirm to sign.")

		dialog.ShowCustomConfirm(
			"Confirm Transaction",
			"Sign", "Cancel",
			scrolledContent,
			func(ok bool) {
				if !ok {
					sendStatusLabel.SetText("Cancelled.")
					return
				}

				sendStatusLabel.SetText("Signing…")

				txidLE, err := txbuilder.TxIDLEFromHex(utxo.Txid)
				if err != nil {
					sendStatusLabel.SetText(fmt.Sprintf("txid conversion error: %v", err))
					return
				}

				toScript, err := txbuilder.P2QPKScript(toAddr)
				if err != nil {
					sendStatusLabel.SetText(fmt.Sprintf("to script error: %v", err))
					return
				}

				// Build outputs and params depending on whether there is change.
				spendOutputs := []wallet.SpendOutput{{Amount: sendSats, Script: toScript}}
				txOutputs := []txbuilder.TxOutput{{Amount: sendSats, Script: toScript}}

				if changeSats > 0 {
					changeScript, err := txbuilder.P2QPKScript(changeAddr)
					if err != nil {
						sendStatusLabel.SetText(fmt.Sprintf("change script error: %v", err))
						return
					}
					spendOutputs = append(spendOutputs, wallet.SpendOutput{Amount: changeSats, Script: changeScript})
					txOutputs = append(txOutputs, txbuilder.TxOutput{Amount: changeSats, Script: changeScript})
				}

				params := wallet.P2QPKSpendParams{
					NVersion:  2,
					NLockTime: 0,
					Inputs:    []wallet.SpendInput{{TxIDLE: txidLE, Vout: utxo.Vout, NSequence: 0xFFFFFFFF}},
					// Fix 2: use the actual on-chain scriptPubKey from scantxoutset,
					// not a value re-derived from fromAddr, so the wallet's script
					// consistency check runs against real fetched data.
					SpentUTXOs: []wallet.SpentUTXO{{Amount: utxoSats, Script: fromScriptBytes}},
					Outputs:    spendOutputs,
					InputIndex: 0,
					FromAddr:   fromAddr,
					ChangeAddr: changeAddr, // "" when changeSats == 0 (no-change tx)
				}

				pubKey, sig, err := wlt.SignP2QPKInput(params)
				if err != nil {
					sendStatusLabel.SetText(fmt.Sprintf("SignP2QPKInput error: %v", err))
					return
				}

				signed := txbuilder.SignedP2QPKTx{
					NVersion:  params.NVersion,
					NLockTime: params.NLockTime,
					Inputs:    []txbuilder.TxInput{{TxIDLE: txidLE, Vout: utxo.Vout, NSequence: 0xFFFFFFFF}},
					Outputs:   txOutputs,
					Sig:       sig,
					PubKey:    pubKey,
				}

				raw, err := txbuilder.SerializeBIP144(signed)
				if err != nil {
					sendStatusLabel.SetText(fmt.Sprintf("serialization error: %v", err))
					return
				}

				signedTxHex = hex.EncodeToString(raw)
				// Show a short preview — never render the full 34,528-char string
				// into a widget (confirmed cause of GUI freeze on real P2QPK tx).
				preview := fmt.Sprintf("%d bytes  /  %d hex chars\n%s…\n…%s",
					len(raw), len(signedTxHex),
					signedTxHex[:64],
					signedTxHex[len(signedTxHex)-64:])
				rawHexPreviewLabel.SetText(preview)

				statusMsg := fmt.Sprintf("Signed — %d bytes raw tx (%d bytes hex).\n"+
					"From address is now SPEND_PENDING until Refresh detects at least 1 on-chain confirmation.\n",
					len(raw), len(raw)*2)
				if changeSats > 0 {
					statusMsg += fmt.Sprintf("Change address %s is reserved until its balance reaches %d confirmations.\n", changeAddr, wallet.FundingMinConfirmations)
				}
				statusMsg += "Broadcast manually: qogecoin-cli sendrawtransaction <hex>"
				sendStatusLabel.SetText(statusMsg)
			},
			w,
		)
	})

	refreshSendBtn := widget.NewButton("Refresh Address Lists", func() {
		if wlt == nil {
			sendStatusLabel.SetText("Open a wallet first.")
			return
		}
		populateSendDropdowns()
		sendStatusLabel.SetText("Address lists refreshed.")
	})

	sendTab = container.NewTabItem("Send",
		container.NewVBox(
			widget.NewLabel("From address (FUNDED — confirmed and spendable):"),
			sendFromSelect,
			widget.NewLabel("To address (FRESH — wallet-controlled recipient):"),
			sendToSelect,
			widget.NewLabel("Amount (QOGE):"),
			amountEntry,
			widget.NewLabel("Fee: 0.0001 QOGE (fixed)"),
			refreshSendBtn,
			previewBtn,
			widget.NewSeparator(),
			widget.NewLabel("Signed transaction hex (broadcast manually):"),
			rawHexPreviewLabel,
			copyTxHexBtn,
			testMempoolBtn,
			widget.NewSeparator(),
			sendStatusLabel,
		),
	)

	// ── Window layout ──────────────────────────────────────────────────────

	tabs = newMainTabs(walletTab, receiveTab, networkTab, addressesTab, sendTab)
	footer := container.NewVBox(widget.NewSeparator(), rpcFooterStatus)
	w.SetContent(container.NewBorder(nil, footer, nil, nil, tabs))

	w.SetCloseIntercept(func() {
		if wlt != nil {
			wlt.Close()
		}
		w.Close()
	})

	w.ShowAndRun()
}
