// cmd/gui/main.go — Fyne GUI for Symbiont Wallet
//
// Four tabs: Wallet lifecycle, My Addresses generation/state tracking, Send
// transaction construction, and Network RPC setup.
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
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	qogeaddress "github.com/saogen/qoge-sphincs-wallet/address"
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

const (
	recipientModeWallet   = "Wallet address"
	recipientModeExternal = "External address"
)

func resolveSendDestination(external bool, walletAddress, externalAddress string) (string, qogeaddress.Destination, error) {
	addr := walletAddress
	if external {
		addr = externalAddress
	}
	if addr == "" {
		if external {
			return "", qogeaddress.Destination{}, fmt.Errorf("enter an external destination address")
		}
		return "", qogeaddress.Destination{}, fmt.Errorf("select a wallet-owned FRESH destination address")
	}
	destination, err := qogeaddress.DecodeMainnetDestination(addr)
	if err != nil {
		return "", qogeaddress.Destination{}, err
	}
	if !external && destination.Type != qogeaddress.DestinationP2QPK {
		return "", qogeaddress.Destination{}, fmt.Errorf("wallet-owned destination is %s, want P2QPK", destination.Type)
	}
	return addr, destination, nil
}

func formatSendFromOption(address string, balanceSats int64, balanceKnown bool) string {
	if !balanceKnown {
		return address + "  —  balance unavailable"
	}
	return fmt.Sprintf("%s  —  %s QOGE", address, rpcclient.FormatQOGE(balanceSats))
}

func resolveSendFromOption(selected string, optionAddresses map[string]string) (string, bool) {
	address, ok := optionAddresses[selected]
	return address, ok && address != ""
}

type broadcastGate struct {
	approvedHex string
}

func (g *broadcastGate) Reset(button *widget.Button) {
	g.approvedHex = ""
	button.Disable()
}

func (g *broadcastGate) RecordMempoolResult(rawHex string, allowed bool, button *widget.Button) {
	g.Reset(button)
	if allowed && rawHex != "" {
		g.approvedHex = rawHex
		button.Enable()
	}
}

func (g *broadcastGate) Allows(rawHex string) bool {
	return rawHex != "" && g.approvedHex == rawHex
}

type signedBroadcastContext struct {
	rawHex          string
	destination     string
	destinationType qogeaddress.DestinationType
	amountSats      int64
}

func newMainTabs(walletTab, addressesTab, sendTab, networkTab *container.TabItem) *container.AppTabs {
	tabs := container.NewAppTabs(walletTab, addressesTab, sendTab, networkTab)
	tabs.DisableItem(addressesTab)
	tabs.DisableItem(sendTab)
	return tabs
}

func pageIntro(text string) *widget.Label {
	label := widget.NewLabel(text)
	label.Wrapping = fyne.TextWrapWord
	return label
}

func scrollPage(objects ...fyne.CanvasObject) fyne.CanvasObject {
	return container.NewVScroll(container.NewVBox(objects...))
}

func equalWidthButtons(buttons ...*widget.Button) []fyne.CanvasObject {
	var width, height float32
	for _, button := range buttons {
		size := button.MinSize()
		if size.Width > width {
			width = size.Width
		}
		if size.Height > height {
			height = size.Height
		}
	}
	wrapped := make([]fyne.CanvasObject, len(buttons))
	for i, button := range buttons {
		wrapped[i] = container.NewGridWrap(fyne.NewSize(width, height), button)
	}
	return wrapped
}

func main() {
	a := app.NewWithID("io.qoge.symbiont-wallet")
	a.Settings().SetTheme(NewQogeTheme())
	w := a.NewWindow("Symbiont Wallet")
	w.Resize(fyne.NewSize(1100, 860))

	var wlt *wallet.Wallet
	var rpc *rpcclient.Client
	var tabs *container.AppTabs
	var addressesTab, sendTab *container.TabItem
	var rpcFooterStatus *widget.Label
	var addressesNavBtn, sendNavBtn *widget.Button

	// ── Wallet tab ──────────────────────────────────────────────────────────────

	walletStatus := widget.NewLabel("No wallet open.")
	walletStatus.Wrapping = fyne.TextWrapWord

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
	backupWarning.Importance = widget.DangerImportance

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
		container.NewCenter(copySeedBtn),
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
			tabs.EnableItem(addressesTab)
			tabs.EnableItem(sendTab)
		}
		if addressesNavBtn != nil {
			addressesNavBtn.Enable()
		}
		if sendNavBtn != nil {
			sendNavBtn.Enable()
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
	openBtn.Importance = widget.HighImportance
	createBtn := widget.NewButton("Create New Wallet", func() {
		loadWallet(true)
	})
	walletActionBtns := equalWidthButtons(createBtn, generateBtn)

	concentrationWarning := widget.NewLabel(
		"For technical safety, avoid holding more than 5,000,000 QOGE in a " +
			"single address. Very large single-address balances can affect how this " +
			"wallet processes transactions. Consider spreading large holdings across " +
			"multiple addresses instead.",
	)
	concentrationWarning.Wrapping = fyne.TextWrapWord

	walletTab := container.NewTabItem("Wallet",
		scrollPage(
			pageTitle("Wallet"),
			pageIntro("Open an existing wallet or create a new one from a 32-byte hex seed."),
			widget.NewLabel("Seed (hex, 64 chars):"),
			seedEntry,
			container.NewCenter(openBtn),
			widget.NewLabel(""),
			backupPanel,
			container.NewHBox(walletActionBtns[0]),
			container.NewHBox(walletActionBtns[1], seedSavedCheck),
			widget.NewSeparator(),
			walletStatus,
		),
	)

	// ── My Addresses tab ──────────────────────────────────────────────────────

	addrListBox := container.New(layout.NewCustomPaddedVBoxLayout(addressListSpacing))
	addrListThemed := container.NewThemeOverride(addrListBox, qogeAddressListTheme{Theme: NewQogeTheme()})
	addrListScroll := container.NewVScroll(addrListThemed)
	addrListScroll.SetMinSize(fyne.NewSize(0, 120))

	addrStatusLabel := widget.NewLabel("Press Refresh to see your addresses.")
	addrStatusLabel.Wrapping = fyne.TextWrapWord
	spendableSummary, spendableCard := newSummaryCard("Spendable", "FUNDED", QGStateFunded)
	pendingSummary, pendingCard := newSummaryCard("Pending", "SPEND_PENDING", QGStatePending)
	addressCountSummary, addressCountCard := newSummaryCard("Addresses", "Total", QGStateFresh)
	addressSummaryCards := container.NewGridWithColumns(3, spendableCard, pendingCard, addressCountCard)

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
		addressCountSummary.SetText(fmt.Sprintf("%d", len(lastAddressRender.infos)))
		if lastAddressRender.balances == nil {
			spendableSummary.SetText("—")
			pendingSummary.SetText("—")
		} else {
			var spendableSats, pendingSats int64
			for _, info := range lastAddressRender.infos {
				sats := lastAddressRender.balances[info.Address]
				switch info.State {
				case keystore.StateFunded:
					spendableSats += sats
				case keystore.StateSpendPending:
					pendingSats += sats
				}
			}
			spendableSummary.SetText(rpcclient.FormatQOGE(spendableSats) + " QOGE")
			pendingSummary.SetText(rpcclient.FormatQOGE(pendingSats) + " QOGE")
		}

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

			balanceText := "—"
			if lastAddressRender.balances != nil {
				sats := lastAddressRender.balances[addr]
				balanceText = rpcclient.FormatQOGE(sats)
				if rpcclient.ExceedsConcentrationThreshold(sats) {
					overThresholdCount++
				}
			}

			stateColor := QGStateFresh
			switch info.State {
			case keystore.StateFunded:
				stateColor = QGStateFunded
			case keystore.StateSpendPending:
				stateColor = QGStatePending
			case keystore.StateSpent:
				stateColor = QGStateSpent
			case keystore.StateRetired:
				stateColor = QGStateRetired
			}
			chipBackground := canvas.NewRectangle(QGStateTint(stateColor))
			chipBackground.CornerRadius = 8
			chipLabel := canvas.NewText(stateLabel, stateColor)
			chipLabel.TextSize = addressListTextSize
			chipLabel.FontSource = fontSpaceMonoRegular
			chip := container.NewGridWrap(fyne.NewSize(128, addressListRowHeight),
				container.NewStack(chipBackground, container.NewCenter(chipLabel)))

			indexText := canvas.NewText(fmt.Sprintf("#%d", info.Index), qgMuted)
			indexText.TextSize = addressListTextSize
			indexText.FontSource = fontSpaceMonoRegular
			indexText.Alignment = fyne.TextAlignTrailing
			index := container.NewGridWrap(fyne.NewSize(addressIndexColWidth, addressListRowHeight), indexText)

			addressText := canvas.NewText(addr, qgMuted)
			addressText.TextSize = addressListTextSize
			addressText.FontSource = fontSpaceMonoRegular

			balanceValue := canvas.NewText(balanceText, qgMuted)
			balanceValue.TextSize = addressListTextSize
			balanceValue.FontSource = fontSpaceMonoRegular

			copyBtn := widget.NewButtonWithIcon("", theme.NewColoredResource(theme.ContentCopyIcon(), theme.ColorNamePlaceHolder), func() {
				w.Clipboard().SetContent(addr)
				addrStatusLabel.SetText("Address copied to clipboard.")
			})
			copyBtn.Importance = widget.LowImportance
			// Spacer keeps balance/copy on the right without a Border center
			// that paints the address under those widgets.
			row := container.New(layout.NewCustomPaddedHBoxLayout(addressListSpacing),
				index, chip, addressText, layout.NewSpacer(), balanceValue, copyBtn)
			row = container.New(layout.NewCustomPaddedLayout(0, 0, 0, addressListRightInset), row)
			hairline := canvas.NewRectangle(qgBorder)
			hairline.SetMinSize(fyne.NewSize(1, 1))
			addrListBox.Add(container.New(layout.NewCustomPaddedVBoxLayout(0), row, hairline))
		}
		addrListBox.Refresh()
		addrListThemed.Refresh()

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
	connectBtn.Importance = widget.HighImportance

	networkTab := container.NewTabItem("Network",
		scrollPage(
			pageTitle("Network"),
			pageIntro("Connect to a Qogecoin node for balances, confirmation tracking, and broadcast."),
			widget.NewLabel("Node RPC connection:"),
			rpcEndpoint,
			rpcUser,
			rpcPass,
			container.NewCenter(connectBtn),
			widget.NewLabel("Local cookie authentication is attempted automatically when a wallet is opened or created."),
		),
	)

	refreshBtn := widget.NewButtonWithIcon("Refresh addresses", theme.ViewRefreshIcon(), func() {
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
	refreshBtn.Importance = widget.LowImportance
	refreshBtn.IconPlacement = widget.ButtonIconTrailingText

	addressesTab = container.NewTabItem("My Addresses",
		container.NewBorder(
			container.NewVBox(
				pageTitle("My Addresses"),
				pageIntro("Lifecycle state is shown on each row. Refresh updates balances from the connected node."),
				addressSummaryCards,
				container.NewBorder(nil, nil, showSpentRetiredCheck, refreshBtn),
			),
			container.NewVBox(
				widget.NewSeparator(),
				addrStatusLabel,
				widget.NewSeparator(),
				concentrationWarning,
			),
			nil, nil,
			addrListScroll,
		),
	)

	// ── Send tab ───────────────────────────────────────────────────────────
	//
	// Flow:
	//   1. Select From address (must be FUNDED)
	//   2. Select a wallet-owned FRESH destination or explicitly enter an external one
	//   3. Enter amount in QOGE
	//   4. Click "Preview" → fetches UTXO, computes change, shows confirm dialog
	//   5. Click "Sign" in dialog → signs, serializes BIP144, displays raw hex
	//   6. Run Test in Mempool successfully to enable Broadcast Transaction.
	//
	// Refresh automatically marks the source SPENT after its tracked transaction
	// reaches one on-chain confirmation.

	sendFromSelect := widget.NewSelect(nil, nil)
	sendFromOptionAddresses := make(map[string]string)
	sendFromSelectStyled := container.NewThemeOverride(sendFromSelect, qogeFundedSelectTheme{Theme: NewQogeTheme()})

	sendToSelect := widget.NewSelect(nil, nil)

	internalToLabel := widget.NewLabel("Wallet-owned To address (FRESH)")
	externalToLabel := widget.NewLabel("External mainnet address:")
	externalToEntry := widget.NewEntry()
	externalToEntry.SetPlaceHolder("P2PKH, P2SH, P2WPKH, P2WSH, P2TR, or P2QPK")
	externalValidationLabel := widget.NewLabel("")
	externalValidationLabel.Wrapping = fyne.TextWrapWord

	recipientMode := widget.NewRadioGroup([]string{recipientModeWallet, recipientModeExternal}, nil)
	recipientMode.Horizontal = true
	recipientMode.OnChanged = func(mode string) {
		external := mode == recipientModeExternal
		if external {
			internalToLabel.Hide()
			sendToSelect.Hide()
			externalToLabel.Show()
			externalToEntry.Show()
			externalValidationLabel.Show()
		} else {
			internalToLabel.Show()
			sendToSelect.Show()
			externalToLabel.Hide()
			externalToEntry.Hide()
			externalValidationLabel.Hide()
		}
	}
	externalToEntry.OnChanged = func(value string) {
		if value == "" {
			externalValidationLabel.SetText("")
			return
		}
		destination, err := qogeaddress.DecodeMainnetDestination(value)
		if err != nil {
			externalValidationLabel.SetText(fmt.Sprintf("Invalid external address: %v", err))
			return
		}
		externalValidationLabel.SetText(fmt.Sprintf("Valid Qogecoin mainnet destination: %s", destination.Type))
	}
	recipientMode.SetSelected(recipientModeWallet)

	amountEntry := widget.NewEntry()
	amountEntry.SetPlaceHolder("e.g. 1 or 0.5")
	amountField := container.NewGridWrap(fyne.NewSize(180, amountEntry.MinSize().Height), amountEntry)

	sendStatusLabel := widget.NewLabel("")
	sendStatusLabel.Wrapping = fyne.TextWrapWord

	// signedTxHex holds the complete hex of the last signed transaction in
	// memory. It is never rendered directly into a text widget — only a short
	// preview is shown on screen to avoid freezing the GUI with 34,528 chars.
	var signedTxHex string
	var broadcastContext signedBroadcastContext
	var broadcastGate broadcastGate

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

	broadcastBtn := widget.NewButton("⚠ Broadcast Transaction", nil)
	broadcastBtn.Importance = widget.DangerImportance
	broadcastGate.Reset(broadcastBtn)

	testMempoolBtn := widget.NewButton("Test in Mempool (testmempoolaccept)", func() {
		broadcastGate.Reset(broadcastBtn)
		if signedTxHex == "" {
			sendStatusLabel.SetText("No signed transaction — preview and sign first.")
			return
		}
		if rpc == nil {
			sendStatusLabel.SetText("No node connected — connect from the Network tab first.")
			return
		}
		result, err := rpc.TestMempoolAccept(context.Background(), signedTxHex)
		if err != nil {
			sendStatusLabel.SetText(fmt.Sprintf("testmempoolaccept RPC error: %v", err))
			return
		}
		if result.Allowed {
			broadcastGate.RecordMempoolResult(signedTxHex, true, broadcastBtn)
			sendStatusLabel.SetText(fmt.Sprintf(
				"testmempoolaccept: ALLOWED  vsize=%d  fee=%g QOGE", result.VSize, result.Fees.Base))
		} else {
			sendStatusLabel.SetText(fmt.Sprintf(
				"testmempoolaccept: REJECTED  reason: %s", result.RejectReason))
		}
	})

	broadcastBtn.OnTapped = func() {
		if !broadcastGate.Allows(signedTxHex) || broadcastContext.rawHex != signedTxHex {
			sendStatusLabel.SetText("Broadcast blocked — run Test in Mempool successfully for the current signed transaction first.")
			broadcastGate.Reset(broadcastBtn)
			return
		}
		if rpc == nil {
			sendStatusLabel.SetText("Broadcast blocked — no node connected.")
			return
		}

		ctx := broadcastContext
		message := fmt.Sprintf(
			"This will broadcast a real, irreversible mainnet transaction.\n\n"+
				"Destination: %s\n"+
				"Type: %s\n"+
				"Amount: %s QOGE (%d sat)\n\n"+
				"Broadcast this transaction now?",
			ctx.destination, ctx.destinationType, rpcclient.FormatQOGE(ctx.amountSats), ctx.amountSats,
		)
		confirm := dialog.NewConfirm("Confirm Broadcast", message, func(ok bool) {
			if !ok {
				sendStatusLabel.SetText("Broadcast cancelled.")
				return
			}
			if !broadcastGate.Allows(signedTxHex) || ctx.rawHex != signedTxHex {
				sendStatusLabel.SetText("Broadcast blocked — signed transaction changed after confirmation opened.")
				broadcastGate.Reset(broadcastBtn)
				return
			}
			txid, err := rpc.SendRawTransaction(context.Background(), ctx.rawHex)
			if err != nil {
				sendStatusLabel.SetText(fmt.Sprintf("sendrawtransaction RPC error: %v", err))
				return
			}
			broadcastGate.Reset(broadcastBtn)
			sendStatusLabel.SetText(fmt.Sprintf("Transaction broadcast successfully.\nTxid: %s", txid))
		}, w)
		confirm.SetConfirmText("Broadcast Now")
		confirm.SetConfirmImportance(widget.SuccessImportance)
		confirm.Show()
	}

	// populateSendDropdowns refreshes the From/To dropdowns from the current
	// wallet state. Called each time the Preview button is clicked so the
	// lists stay accurate.
	populateSendDropdowns := func() error {
		if wlt == nil {
			return nil
		}
		infos, err := wlt.ListAddresses()
		if err != nil {
			return err
		}
		var fundedAddresses, fresh []string
		for _, info := range infos {
			switch info.State {
			case keystore.StateFunded:
				fundedAddresses = append(fundedAddresses, info.Address)
			case keystore.StateFresh:
				if !info.Reserved {
					fresh = append(fresh, info.Address)
				}
			}
		}

		var balances map[string]int64
		var balanceErr error
		if rpc != nil && len(fundedAddresses) > 0 {
			descriptors := make([]string, len(fundedAddresses))
			for i, address := range fundedAddresses {
				descriptors[i] = "addr(" + address + ")"
			}
			result, err := rpc.ScanTxOutSet(context.Background(), descriptors)
			if err != nil {
				balanceErr = fmt.Errorf("FUNDED balance lookup failed: %w", err)
			} else {
				balances, balanceErr = rpcclient.AggregateBalances(result, fundedAddresses)
				if balanceErr != nil {
					balanceErr = fmt.Errorf("FUNDED balance aggregation failed: %w", balanceErr)
				}
			}
		}

		previousAddress, _ := resolveSendFromOption(sendFromSelect.Selected, sendFromOptionAddresses)
		fundedOptions := make([]string, 0, len(fundedAddresses))
		newOptionAddresses := make(map[string]string, len(fundedAddresses))
		selectedOption := ""
		for _, address := range fundedAddresses {
			balanceSats, balanceKnown := balances[address]
			option := formatSendFromOption(address, balanceSats, balanceKnown)
			fundedOptions = append(fundedOptions, option)
			newOptionAddresses[option] = address
			if address == previousAddress {
				selectedOption = option
			}
		}
		sendFromOptionAddresses = newOptionAddresses
		sendFromSelect.Options = fundedOptions
		if selectedOption != "" {
			sendFromSelect.Selected = selectedOption
		} else {
			sendFromSelect.Selected = ""
		}
		sendFromSelect.Refresh()

		sendToSelect.Options = fresh
		if len(fresh) == 0 {
			sendToSelect.Selected = ""
		}
		sendToSelect.Refresh()
		return balanceErr
	}

	previewBtn := widget.NewButton("Preview Transaction", func() {
		broadcastGate.Reset(broadcastBtn)
		if wlt == nil {
			sendStatusLabel.SetText("Open a wallet first.")
			return
		}
		if rpc == nil {
			sendStatusLabel.SetText("Node RPC required to fetch UTXO — connect from the Network tab.")
			return
		}

		if err := populateSendDropdowns(); err != nil {
			sendStatusLabel.SetText(err.Error())
		}

		fromAddr, selected := resolveSendFromOption(sendFromSelect.Selected, sendFromOptionAddresses)
		if !selected {
			sendStatusLabel.SetText("Select a From address (FUNDED).")
			return
		}
		toAddr, toDestination, err := resolveSendDestination(
			recipientMode.Selected == recipientModeExternal,
			sendToSelect.Selected,
			externalToEntry.Text,
		)
		if err != nil {
			sendStatusLabel.SetText(fmt.Sprintf("Invalid destination: %v", err))
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
				"To:        %s\n"+
				"Type:      %s\n\n"+
				"Amount:    %s QOGE  (%d sat)\n"+
				"Fee:       0.00010000 QOGE  (%d sat)  [fixed]\n"+
				"%s"+
				"UTXO:      %s:%d  (%s QOGE)\n\n"+
				"⚠  This will irreversibly spend real mainnet QOGE.\n"+
				"   Signing does NOT broadcast automatically.\n"+
				"   After signing, run Test in Mempool, then use the separate\n"+
				"   Broadcast Transaction button.",
			fromAddr,
			toAddr,
			toDestination.Type,
			rpcclient.FormatQOGE(sendSats), sendSats,
			feeSats,
			changeLines,
			utxo.Txid, utxo.Vout, rpcclient.FormatQOGE(utxoSats),
		)

		content := widget.NewLabel(previewText)
		content.TextStyle = fyne.TextStyle{Monospace: true}
		content.Wrapping = fyne.TextWrapBreak

		scrolledContent := container.NewVScroll(content)
		scrolledContent.SetMinSize(fyne.NewSize(760, 420))

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

				toScript := append([]byte(nil), toDestination.ScriptPubKey...)

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
				broadcastContext = signedBroadcastContext{
					rawHex: signedTxHex, destination: toAddr, destinationType: toDestination.Type, amountSats: sendSats,
				}
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
				statusMsg += "Run Test in Mempool successfully to enable Broadcast Transaction."
				sendStatusLabel.SetText(statusMsg)
			},
			w,
		)
	})
	previewBtn.Importance = widget.HighImportance

	refreshSendAddresses := func() {
		if wlt == nil {
			sendStatusLabel.SetText("Open a wallet first.")
			return
		}
		if err := populateSendDropdowns(); err != nil {
			sendStatusLabel.SetText(err.Error())
			return
		}
		sendStatusLabel.SetText("Address lists refreshed.")
	}
	refreshSendBtn := widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), refreshSendAddresses)
	refreshSendBtn.Importance = widget.LowImportance
	refreshSendSpacer := container.NewGridWrap(refreshSendBtn.MinSize(), layout.NewSpacer())

	sendTab = container.NewTabItem("Send",
		scrollPage(
			pageTitle("Send"),
			pageIntro("Spend from a FUNDED address after 20 confirmations. Preview freezes the destination before signing."),
			widget.NewLabel("From address: (FUNDED - spendable after 20 confirmations)"),
			container.NewBorder(nil, nil, nil, container.NewCenter(refreshSendBtn), sendFromSelectStyled),
			widget.NewLabel("Destination mode:"),
			recipientMode,
			internalToLabel,
			container.NewBorder(nil, nil, nil, refreshSendSpacer, sendToSelect),
			externalToLabel,
			externalToEntry,
			externalValidationLabel,
			widget.NewLabel("Amount (QOGE):"),
			container.NewHBox(amountField, previewBtn),
			widget.NewLabel("Fee: 0.0001 QOGE (fixed)"),
			widget.NewSeparator(),
			widget.NewLabel("Signed transaction hex:"),
			rawHexPreviewLabel,
			container.NewCenter(copyTxHexBtn),
			container.NewCenter(testMempoolBtn),
			container.NewCenter(broadcastBtn),
			widget.NewSeparator(),
			sendStatusLabel,
		),
	)

	// ── Window layout ──────────────────────────────────────────────────────

	tabs = newMainTabs(walletTab, addressesTab, sendTab, networkTab)

	walletNavBtn := widget.NewButtonWithIcon("Wallet", theme.AccountIcon(), nil)
	addressesNavBtn = widget.NewButtonWithIcon("My Addresses", theme.ListIcon(), nil)
	sendNavBtn = widget.NewButtonWithIcon("Send", theme.MailSendIcon(), nil)
	networkNavBtn := widget.NewButtonWithIcon("Network", theme.SettingsIcon(), nil)
	navButtons := []*widget.Button{walletNavBtn, addressesNavBtn, sendNavBtn, networkNavBtn}
	for _, button := range navButtons {
		button.Alignment = widget.ButtonAlignLeading
	}
	addressesNavBtn.Disable()
	sendNavBtn.Disable()

	pages := []*container.TabItem{walletTab, addressesTab, sendTab, networkTab}
	pageHost := container.NewStack(walletTab.Content, addressesTab.Content, sendTab.Content, networkTab.Content)
	selectPage := func(selected *container.TabItem, selectedButton *widget.Button) {
		tabs.Select(selected)
		for i, page := range pages {
			if page == selected {
				page.Content.Show()
				navButtons[i].Importance = widget.HighImportance
			} else {
				page.Content.Hide()
				navButtons[i].Importance = widget.LowImportance
			}
			navButtons[i].Refresh()
		}
		selectedButton.Refresh()
		pageHost.Refresh()
	}
	walletNavBtn.OnTapped = func() { selectPage(walletTab, walletNavBtn) }
	addressesNavBtn.OnTapped = func() { selectPage(addressesTab, addressesNavBtn) }
	sendNavBtn.OnTapped = func() { selectPage(sendTab, sendNavBtn) }
	networkNavBtn.OnTapped = func() { selectPage(networkTab, networkNavBtn) }
	selectPage(walletTab, walletNavBtn)

	const sidebarWidth float32 = 188
	navItem := func(btn *widget.Button) fyne.CanvasObject {
		return container.NewGridWrap(fyne.NewSize(sidebarWidth, 40), btn)
	}
	sidebarInner := container.NewVBox(
		container.NewPadded(container.NewVBox(brandWordmark(), brandTagline())),
		widget.NewSeparator(),
		navItem(walletNavBtn),
		navItem(addressesNavBtn),
		navItem(sendNavBtn),
		navItem(networkNavBtn),
	)
	sidebarRail := container.NewStack(
		canvas.NewRectangle(qgSidebar),
		container.NewPadded(sidebarInner),
	)
	sidebarWithTheme := container.NewThemeOverride(sidebarRail, qogeSidebarTheme{Theme: NewQogeTheme()})
	footer := container.NewStack(
		canvas.NewRectangle(qgBg),
		container.NewVBox(widget.NewSeparator(), rpcFooterStatus),
	)
	pageContent := container.New(layout.NewCustomPaddedLayout(12, 12, 16, 16), pageHost)
	content := container.NewBorder(nil, nil,
		container.NewHBox(sidebarWithTheme, widget.NewSeparator()),
		nil, pageContent)
	contentWithBackground := container.NewStack(canvas.NewRectangle(qgBg), content)
	w.SetContent(container.NewBorder(nil, footer, nil, nil, contentWithBackground))

	w.SetCloseIntercept(func() {
		if wlt != nil {
			wlt.Close()
		}
		w.Close()
	})

	w.ShowAndRun()
}
