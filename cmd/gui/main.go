// cmd/gui/main.go — Fyne GUI for Symbiont Wallet
//
// Five tabs: Wallet lifecycle, address state tracking, local transaction history,
// transaction construction, and Network RPC setup.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"image/color"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
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
	transactionExplorerBase = "https://explorer.qoge.org/tx/"
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

func filterTransactionRecords(records []wallet.TransactionRecord, hideOutgoing, hideIncoming bool) (visible []wallet.TransactionRecord, hidden int) {
	visible = make([]wallet.TransactionRecord, 0, len(records))
	for _, record := range records {
		hide := hideOutgoing && record.Direction == wallet.TransactionOutgoing ||
			hideIncoming && record.Direction == wallet.TransactionIncoming
		if hide {
			hidden++
			continue
		}
		visible = append(visible, record)
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
	source          string
	destination     string
	destinationType qogeaddress.DestinationType
	amountSats      int64
	feeSats         int64
}

type preparedSpendUTXO struct {
	TxID string
	Vout uint32
	Sats int64
}

type preparedSpendInputs struct {
	WalletInputs []wallet.SpendInput
	SpentUTXOs   []wallet.SpentUTXO
	TxInputs     []txbuilder.TxInput
	UTXOs        []preparedSpendUTXO
	TotalSats    int64
}

func prepareSpendInputs(unspents []rpcclient.ScanUnspent) (preparedSpendInputs, error) {
	if len(unspents) == 0 {
		return preparedSpendInputs{}, fmt.Errorf("no UTXOs")
	}
	ordered := append([]rpcclient.ScanUnspent(nil), unspents...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Txid == ordered[j].Txid {
			return ordered[i].Vout < ordered[j].Vout
		}
		return ordered[i].Txid < ordered[j].Txid
	})
	prepared := preparedSpendInputs{
		WalletInputs: make([]wallet.SpendInput, 0, len(ordered)),
		SpentUTXOs:   make([]wallet.SpentUTXO, 0, len(ordered)),
		TxInputs:     make([]txbuilder.TxInput, 0, len(ordered)),
		UTXOs:        make([]preparedSpendUTXO, 0, len(ordered)),
	}
	seen := make(map[string]struct{}, len(ordered))
	for i, unspent := range ordered {
		outpoint := fmt.Sprintf("%s:%d", unspent.Txid, unspent.Vout)
		if _, duplicate := seen[outpoint]; duplicate {
			return preparedSpendInputs{}, fmt.Errorf("duplicate UTXO %s", outpoint)
		}
		seen[outpoint] = struct{}{}
		txidLE, err := txbuilder.TxIDLEFromHex(unspent.Txid)
		if err != nil {
			return preparedSpendInputs{}, fmt.Errorf("UTXO %d txid: %w", i, err)
		}
		sats, err := rpcclient.FloatQOGEToSatoshis(unspent.Amount)
		if err != nil || sats <= 0 {
			return preparedSpendInputs{}, fmt.Errorf("UTXO %s amount is invalid: %v", outpoint, err)
		}
		if prepared.TotalSats > math.MaxInt64-sats {
			return preparedSpendInputs{}, fmt.Errorf("UTXO total overflows satoshi range")
		}
		script, err := hex.DecodeString(unspent.ScriptPubKey)
		if err != nil || len(script) == 0 {
			return preparedSpendInputs{}, fmt.Errorf("UTXO %s scriptPubKey is invalid: %v", outpoint, err)
		}
		input := wallet.SpendInput{TxIDLE: txidLE, Vout: unspent.Vout, NSequence: 0xffffffff}
		prepared.WalletInputs = append(prepared.WalletInputs, input)
		prepared.SpentUTXOs = append(prepared.SpentUTXOs, wallet.SpentUTXO{Amount: sats, Script: script})
		prepared.TxInputs = append(prepared.TxInputs, txbuilder.TxInput(input))
		prepared.UTXOs = append(prepared.UTXOs, preparedSpendUTXO{TxID: unspent.Txid, Vout: unspent.Vout, Sats: sats})
		prepared.TotalSats += sats
	}
	return prepared, nil
}

func transactionExplorerURL(txid string) (*url.URL, error) {
	decoded, err := hex.DecodeString(txid)
	if err != nil || len(decoded) != 32 || len(txid) != 64 {
		return nil, fmt.Errorf("invalid transaction ID")
	}
	return url.Parse(transactionExplorerBase + txid)
}

func broadcastAndRecord(send func() (string, error), record func(string) error) (txid string, historyErr error, err error) {
	txid, err = send()
	if err != nil {
		return "", nil, err
	}
	return txid, record(txid), nil
}

func newMainTabs(walletTab, addressesTab, transactionsTab, sendTab, networkTab *container.TabItem) *container.AppTabs {
	tabs := container.NewAppTabs(walletTab, addressesTab, transactionsTab, sendTab, networkTab)
	tabs.DisableItem(addressesTab)
	tabs.DisableItem(transactionsTab)
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

type themeToggle struct {
	*fyne.Container
	sunButton  *widget.Button
	moonButton *widget.Button
	light      bool
}

func newThemeToggle(a fyne.App, changed func()) *themeToggle {
	toggle := &themeToggle{
		sunButton:  widget.NewButtonWithIcon("", qogeSunIcon, nil),
		moonButton: widget.NewButtonWithIcon("", qogeMoonIcon, nil),
	}
	toggle.sunButton.Importance = widget.LowImportance
	toggle.moonButton.Importance = widget.HighImportance

	setLight := func(light bool) {
		if toggle.light == light {
			return
		}
		toggle.light = light
		setQogeTheme(a, light)
		if light {
			toggle.sunButton.Importance = widget.HighImportance
			toggle.moonButton.Importance = widget.LowImportance
		} else {
			toggle.sunButton.Importance = widget.LowImportance
			toggle.moonButton.Importance = widget.HighImportance
		}
		toggle.sunButton.Refresh()
		toggle.moonButton.Refresh()
		if changed != nil {
			changed()
		}
	}
	toggle.sunButton.OnTapped = func() { setLight(true) }
	toggle.moonButton.OnTapped = func() { setLight(false) }

	outline := canvas.NewRectangle(color.Transparent)
	outline.StrokeColor = qgDisplayToggleEdge
	outline.StrokeWidth = 1
	outline.CornerRadius = 8
	themedSunButton := container.NewThemeOverride(toggle.sunButton,
		qogeSunToggleTheme{Theme: newActiveQogeTheme()})
	sunOutline := canvas.NewRectangle(color.Transparent)
	sunOutline.StrokeColor = qgDisplaySunEdge
	sunOutline.StrokeWidth = 1
	sunOutline.CornerRadius = 6
	sunSegment := container.NewStack(themedSunButton, sunOutline)
	segments := container.NewGridWithColumns(2, toggle.moonButton, sunSegment)
	toggle.Container = container.NewStack(outline,
		container.New(layout.NewCustomPaddedLayout(1, 1, 1, 1), segments))
	return toggle
}

func main() {
	a := app.NewWithID("io.qoge.symbiont-wallet")
	setQogeTheme(a, false)
	w := a.NewWindow("Symbiont Wallet")
	w.Resize(fyne.NewSize(1100, 860))

	var wlt *wallet.Wallet
	var rpc *rpcclient.Client
	var tabs *container.AppTabs
	var addressesTab, transactionsTab, sendTab *container.TabItem
	var rpcFooterStatus *widget.Label
	var renderTransactions func()
	var addressesNavBtn, transactionsNavBtn, sendNavBtn *widget.Button

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
			tabs.EnableItem(transactionsTab)
			tabs.EnableItem(sendTab)
		}
		if addressesNavBtn != nil {
			addressesNavBtn.Enable()
		}
		if sendNavBtn != nil {
			sendNavBtn.Enable()
		}
		if transactionsNavBtn != nil {
			transactionsNavBtn.Enable()
		}
		if renderTransactions != nil {
			renderTransactions()
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
	addrListThemed := container.NewThemeOverride(addrListBox, qogeAddressListTheme{Theme: newActiveQogeTheme()})
	addrListScroll := container.NewVScroll(addrListThemed)
	addrListScroll.SetMinSize(fyne.NewSize(0, 120))

	addrStatusLabel := widget.NewLabel("Press Refresh to see your addresses.")
	addrStatusLabel.Wrapping = fyne.TextWrapWord
	spendableSummary, spendableCard := newSummaryCard("Spendable", "FUNDED", QGDisplayFunded)
	pendingSummary, pendingCard := newSummaryCard("Pending", "SPEND_PENDING", QGDisplayPending)
	addressCountSummary, addressCountCard := newSummaryCard("Addresses", "Total", QGDisplayFresh)
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

			stateColor := QGDisplayFresh
			switch info.State {
			case keystore.StateFunded:
				stateColor = QGDisplayFunded
			case keystore.StateSpendPending:
				stateColor = QGDisplayPending
			case keystore.StateSpent:
				stateColor = QGDisplaySpent
			case keystore.StateRetired:
				stateColor = QGDisplayRetired
			}
			chipBackground := canvas.NewRectangle(adaptiveTint(stateColor, 0x28, 0x18))
			chipBackground.CornerRadius = 8
			chipLabel := canvas.NewText(stateLabel, stateColor)
			chipLabel.TextSize = addressListTextSize
			chipLabel.FontSource = fontSpaceMonoRegular
			chip := container.NewGridWrap(fyne.NewSize(128, addressListRowHeight),
				container.NewStack(chipBackground, container.NewCenter(chipLabel)))

			indexText := canvas.NewText(fmt.Sprintf("#%d", info.Index), qgDisplayMuted)
			indexText.TextSize = addressListTextSize
			indexText.FontSource = fontSpaceMonoRegular
			indexText.Alignment = fyne.TextAlignTrailing
			index := container.NewGridWrap(fyne.NewSize(addressIndexColWidth, addressListRowHeight), indexText)

			addressText := canvas.NewText(addr, qgDisplayMuted)
			addressText.TextSize = addressListTextSize
			addressText.FontSource = fontSpaceMonoRegular

			balanceValue := canvas.NewText(balanceText, qgDisplayMuted)
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
			hairline := canvas.NewRectangle(qgDisplayBorder)
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
	themeToggleBtn := newThemeToggle(a, func() {
		if hasAddressSnapshot {
			renderAddressList()
		}
		canvas.Refresh(w.Content())
	})

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
					deposits, depositErr := rpcclient.AnalyzeDeposits(result, freshAddrs)
					if fundingErr != nil {
						balanceErr = fmt.Sprintf("Funding analysis error: %v", fundingErr)
					} else if depositErr != nil {
						balanceErr = fmt.Sprintf("Deposit analysis error: %v", depositErr)
					} else {
						observedAt := time.Now().UTC()
						for _, addr := range freshAddrs {
							fs := funding[addr]
							incoming := make([]wallet.IncomingDeposit, 0, len(deposits[addr]))
							for _, deposit := range deposits[addr] {
								incoming = append(incoming, wallet.IncomingDeposit{TxID: deposit.TxID, AmountSats: deposit.AmountSats})
							}
							changed, observeErr := wlt.ObserveFundingWithHistory(addr, fs.BalanceSats, fs.Confirmations, incoming, observedAt)
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
		if renderTransactions != nil {
			renderTransactions()
		}
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

	// ── Transactions tab ───────────────────────────────────────────────────

	historyList := container.NewVBox()
	historyScroll := container.NewVScroll(historyList)
	historyScroll.SetMinSize(fyne.NewSize(0, 120))
	historyStatus := widget.NewLabel("Transaction history is stored locally in this wallet.")
	historyStatus.Wrapping = fyne.TextWrapWord
	hideOutgoingCheck := widget.NewCheck("Hide OUTGOING", func(bool) { renderTransactions() })
	hideIncomingCheck := widget.NewCheck("Hide INCOMING", func(bool) { renderTransactions() })
	renderTransactions = func() {
		if wlt == nil {
			return
		}
		records, err := wlt.ListTransactions()
		if err != nil {
			historyStatus.SetText(fmt.Sprintf("History read failed: %v", err))
			return
		}
		visible, hidden := filterTransactionRecords(records, hideOutgoingCheck.Checked, hideIncomingCheck.Checked)
		historyList.RemoveAll()
		if len(records) == 0 {
			historyList.Add(widget.NewLabel("No recorded transactions yet."))
		} else if len(visible) == 0 {
			historyList.Add(widget.NewLabel("No transactions match the current filters."))
		}
		for _, record := range visible {
			record := record
			copyTxID := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
				w.Clipboard().SetContent(record.TxID)
				historyStatus.SetText("Transaction ID copied to clipboard.")
			})
			copyTxID.Importance = widget.LowImportance
			var txid fyne.CanvasObject
			explorerURL, urlErr := transactionExplorerURL(record.TxID)
			if urlErr == nil {
				link := widget.NewHyperlink(record.TxID, explorerURL)
				link.TextStyle = fyne.TextStyle{Monospace: true}
				txid = link
			} else {
				label := widget.NewLabel(record.TxID)
				label.TextStyle = fyne.TextStyle{Monospace: true}
				label.Wrapping = fyne.TextWrapBreak
				txid = label
			}
			var details string
			if record.Direction == wallet.TransactionOutgoing {
				details = fmt.Sprintf("OUTGOING\nAmount: %s QOGE\nFee: %s QOGE\nFrom: %s\nTo: %s (%s)\nBroadcast by this wallet: %s", rpcclient.FormatQOGE(record.AmountSats), rpcclient.FormatQOGE(record.FeeSats), record.SourceAddress, record.Destination, record.DestinationType, record.RecordedAt.Local().Format(time.RFC3339))
			} else {
				details = fmt.Sprintf("INCOMING\nAmount: %s QOGE\nReceived at: %s\nFirst recorded as FUNDED by Refresh: %s", rpcclient.FormatQOGE(record.AmountSats), record.Destination, record.RecordedAt.Local().Format(time.RFC3339))
			}
			historyList.Add(widget.NewCard("", "", container.NewVBox(widget.NewLabel(details), container.NewBorder(nil, nil, nil, copyTxID, txid))))
		}
		historyList.Refresh()
		historyStatus.SetText(fmt.Sprintf("%d recorded transaction(s), %d hidden, newest first. Confirmation status is not tracked here.", len(records), hidden))
	}
	refreshHistoryBtn := widget.NewButtonWithIcon("Refresh history", theme.ViewRefreshIcon(), renderTransactions)
	refreshHistoryBtn.Importance = widget.LowImportance
	transactionsTab = container.NewTabItem("Transactions", container.NewBorder(container.NewVBox(pageTitle("Transactions"), pageIntro("Local write-once history anchored by transaction ID. Internal change is excluded."), container.NewHBox(hideOutgoingCheck, hideIncomingCheck), container.NewCenter(refreshHistoryBtn)), historyStatus, nil, nil, historyScroll))

	// ── Send tab ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
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
	sendFromSelectStyled := container.NewThemeOverride(sendFromSelect, qogeFundedSelectTheme{Theme: newActiveQogeTheme()})

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
	feeRateEntry := widget.NewEntry()
	feeRateEntry.SetText(txbuilder.DefaultFeeRateQOGE)
	feeRateField := container.NewGridWrap(fyne.NewSize(180, feeRateEntry.MinSize().Height), feeRateEntry)
	feeRateLabel := widget.NewLabel("Fee rate (QOGE/kB): A too-low fee may result in a slow or never-confirming transaction.")
	feeRateLabel.Wrapping = fyne.TextWrapWord

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

	testMempoolBtn := widget.NewButton("Test Transaction", func() {
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
	testMempoolBtn.Importance = widget.SuccessImportance

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
			txid, historyErr, err := broadcastAndRecord(
				func() (string, error) { return rpc.SendRawTransaction(context.Background(), ctx.rawHex) },
				func(txid string) error {
					return wlt.RecordOutgoingTransaction(wallet.OutgoingTransaction{TxID: txid, SourceAddress: ctx.source, Destination: ctx.destination, DestinationType: string(ctx.destinationType), AmountSats: ctx.amountSats, FeeSats: ctx.feeSats, BroadcastAt: time.Now().UTC()})
				},
			)
			if err != nil {
				sendStatusLabel.SetText(fmt.Sprintf("sendrawtransaction RPC error: %v", err))
				return
			}
			broadcastGate.Reset(broadcastBtn)
			if historyErr != nil {
				sendStatusLabel.SetText(fmt.Sprintf("Transaction broadcast successfully.\nTxid: %s\nWARNING: local history write failed: %v", txid, historyErr))
			} else {
				sendStatusLabel.SetText(fmt.Sprintf("Transaction broadcast successfully.\nTxid: %s", txid))
				if renderTransactions != nil {
					renderTransactions()
				}
			}
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
			sendStatusLabel.SetText("Node RPC required to fetch UTXOs — connect from the Network tab.")
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
		if err != nil || sendSats <= 0 {
			sendStatusLabel.SetText(fmt.Sprintf("Invalid amount: %v", err))
			return
		}
		feeRateSats, err := txbuilder.ParseFeeRate(feeRateEntry.Text)
		if err != nil {
			sendStatusLabel.SetText(fmt.Sprintf("Invalid fee rate: %v", err))
			return
		}
		sendStatusLabel.SetText("Fetching all UTXOs from node...")
		scanResult, err := rpc.ScanTxOutSet(context.Background(), []string{"addr(" + fromAddr + ")"})
		if err != nil {
			sendStatusLabel.SetText(fmt.Sprintf("scantxoutset error: %v", err))
			return
		}
		prepared, err := prepareSpendInputs(scanResult.Unspents)
		if err != nil {
			sendStatusLabel.SetText(fmt.Sprintf("Cannot prepare UTXOs: %v", err))
			return
		}
		toScript := append([]byte(nil), toDestination.ScriptPubKey...)
		feePlan, err := txbuilder.PlanP2QPKFee(prepared.TotalSats, sendSats, feeRateSats, len(prepared.WalletInputs), toScript)
		if err != nil {
			sendStatusLabel.SetText(err.Error())
			return
		}
		var changeAddr string
		spendOutputs := []wallet.SpendOutput{{Amount: sendSats, Script: toScript}}
		txOutputs := []txbuilder.TxOutput{{Amount: sendSats, Script: toScript}}
		if feePlan.IncludeChange {
			changeAddr, err = wlt.NextReceiveAddress()
			if err != nil {
				sendStatusLabel.SetText(fmt.Sprintf("Cannot select change address: %v", err))
				return
			}
			if changeAddr == toAddr {
				sendStatusLabel.SetText("Change address conflicts with the destination — select a different wallet-owned destination or use an external address.")
				return
			}
			changeScript, err := txbuilder.P2QPKScript(changeAddr)
			if err != nil {
				sendStatusLabel.SetText(fmt.Sprintf("change script error: %v", err))
				return
			}
			spendOutputs = append(spendOutputs, wallet.SpendOutput{Amount: feePlan.ChangeSats, Script: changeScript})
			txOutputs = append(txOutputs, txbuilder.TxOutput{Amount: feePlan.ChangeSats, Script: changeScript})
		}
		var utxoLines strings.Builder
		for i, utxo := range prepared.UTXOs {
			fmt.Fprintf(&utxoLines, "  %d. %s:%d  (%s QOGE / %d sat)\n",
				i+1, utxo.TxID, utxo.Vout, rpcclient.FormatQOGE(utxo.Sats), utxo.Sats)
		}
		changeLines := "Change:      none\n"
		if feePlan.IncludeChange {
			changeLines = fmt.Sprintf("Change:      %s QOGE  (%d sat)\n  → to:     %s\n",
				rpcclient.FormatQOGE(feePlan.ChangeSats), feePlan.ChangeSats, changeAddr)
		}
		previewText := fmt.Sprintf(
			"From:        %s\n\n"+
				"To:          %s\n"+
				"Type:        %s\n\n"+
				"Inputs:      %d UTXO(s)\n"+
				"Total input: %s QOGE  (%d sat)\n"+
				"UTXOs:\n%s\n"+
				"Amount:      %s QOGE  (%d sat)\n"+
				"Fee rate:    %s QOGE/kB\n"+
				"Final vsize: %d vB\n"+
				"Actual fee:  %s QOGE  (%d sat)\n"+
				"%s\n"+
				"⚠  This will irreversibly spend real mainnet QOGE.\n"+
				"   Signing does NOT broadcast automatically.\n"+
				"   After signing, run Test Transaction, then use the separate\n"+
				"   Broadcast Transaction button.",
			fromAddr, toAddr, toDestination.Type,
			len(prepared.UTXOs), rpcclient.FormatQOGE(prepared.TotalSats), prepared.TotalSats, utxoLines.String(),
			rpcclient.FormatQOGE(sendSats), sendSats,
			rpcclient.FormatQOGE(feeRateSats), feePlan.VSize,
			rpcclient.FormatQOGE(feePlan.FeeSats), feePlan.FeeSats,
			changeLines,
		)
		content := widget.NewLabel(previewText)
		content.TextStyle = fyne.TextStyle{Monospace: true}
		content.Wrapping = fyne.TextWrapBreak
		scrolledContent := container.NewVScroll(content)
		scrolledContent.SetMinSize(fyne.NewSize(760, 420))
		sendStatusLabel.SetText("Preview ready — confirm to sign.")
		dialog.ShowCustomConfirm("Confirm Transaction", "Sign", "Cancel", scrolledContent, func(ok bool) {
			if !ok {
				sendStatusLabel.SetText("Cancelled.")
				return
			}
			sendStatusLabel.SetText(fmt.Sprintf("Signing %d input(s)…", len(prepared.WalletInputs)))
			params := wallet.P2QPKSpendParams{
				NVersion: 2, NLockTime: 0,
				Inputs: prepared.WalletInputs, SpentUTXOs: prepared.SpentUTXOs,
				Outputs: spendOutputs, InputIndex: 0,
				FromAddr: fromAddr, ChangeAddr: changeAddr,
			}
			pubKey, signatures, err := wlt.SignP2QPKInputs(params)
			if err != nil {
				sendStatusLabel.SetText(fmt.Sprintf("SignP2QPKInputs error: %v", err))
				return
			}
			witnesses := make([]txbuilder.P2QPKWitness, len(signatures))
			for i, signature := range signatures {
				witnesses[i] = txbuilder.P2QPKWitness{Sig: signature, PubKey: pubKey}
			}
			signed := txbuilder.SignedP2QPKTx{
				NVersion: params.NVersion, NLockTime: params.NLockTime,
				Inputs: prepared.TxInputs, Outputs: txOutputs, Witnesses: witnesses,
			}
			raw, err := txbuilder.SerializeBIP144(signed)
			if err != nil {
				sendStatusLabel.SetText(fmt.Sprintf("serialization error: %v", err))
				return
			}
			signedTxHex = hex.EncodeToString(raw)
			broadcastContext = signedBroadcastContext{
				rawHex: signedTxHex, source: fromAddr, destination: toAddr,
				destinationType: toDestination.Type, amountSats: sendSats, feeSats: feePlan.FeeSats,
			}
			preview := fmt.Sprintf("%d bytes / %d vB / %d inputs / %d hex chars\n%s…\n…%s",
				len(raw), feePlan.VSize, len(prepared.TxInputs), len(signedTxHex),
				signedTxHex[:64], signedTxHex[len(signedTxHex)-64:])
			rawHexPreviewLabel.SetText(preview)
			statusMsg := fmt.Sprintf("Signed %d inputs — %d bytes raw tx, %d vB, fee %s QOGE.\n"+
				"From address is now SPEND_PENDING until Refresh detects at least 1 on-chain confirmation.\n",
				len(prepared.TxInputs), len(raw), feePlan.VSize, rpcclient.FormatQOGE(feePlan.FeeSats))
			if feePlan.IncludeChange {
				statusMsg += fmt.Sprintf("Change address %s is reserved until its balance reaches %d confirmations.\n", changeAddr, wallet.FundingMinConfirmations)
			}
			statusMsg += "Run Test Transaction successfully to enable Broadcast Transaction."
			sendStatusLabel.SetText(statusMsg)
		}, w)
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
	nextStepToTest := widget.NewLabel("step 2")
	nextStepToTest.TextStyle = fyne.TextStyle{Italic: true}
	nextStepToBroadcast := widget.NewLabel("step 3")
	nextStepToBroadcast.TextStyle = fyne.TextStyle{Italic: true}
	transactionActionRow := container.NewHBox(
		amountField,
		previewBtn,
		nextStepToTest,
		testMempoolBtn,
		nextStepToBroadcast,
		broadcastBtn,
	)

	sendTab = container.NewTabItem("Send",
		scrollPage(
			pageTitle("Send"),
			widget.NewLabel("From address: (FUNDED - spendable after 20 confirmations)"),
			container.NewBorder(nil, nil, nil, container.NewCenter(refreshSendBtn), sendFromSelectStyled),
			container.NewHBox(widget.NewLabel("Destination mode:"), recipientMode),
			internalToLabel,
			container.NewBorder(nil, nil, nil, refreshSendSpacer, sendToSelect),
			externalToLabel,
			externalToEntry,
			externalValidationLabel,
			widget.NewLabel("Amount (QOGE):"),
			transactionActionRow,
			feeRateLabel,
			feeRateField,
			widget.NewSeparator(),
			widget.NewLabel("Signed transaction hex:"),
			rawHexPreviewLabel,
			container.NewCenter(copyTxHexBtn),
			widget.NewSeparator(),
			sendStatusLabel,
		),
	)

	// ── Window layout ──────────────────────────────────────────────────────

	tabs = newMainTabs(walletTab, addressesTab, transactionsTab, sendTab, networkTab)

	walletNavBtn := widget.NewButtonWithIcon("Wallet", theme.AccountIcon(), nil)
	addressesNavBtn = widget.NewButtonWithIcon("My Addresses", theme.ListIcon(), nil)
	transactionsNavBtn = widget.NewButtonWithIcon("Transactions", theme.HistoryIcon(), nil)
	sendNavBtn = widget.NewButtonWithIcon("Send", theme.MailSendIcon(), nil)
	networkNavBtn := widget.NewButtonWithIcon("Network", theme.SettingsIcon(), nil)
	navButtons := []*widget.Button{walletNavBtn, addressesNavBtn, transactionsNavBtn, sendNavBtn, networkNavBtn}
	for _, button := range navButtons {
		button.Alignment = widget.ButtonAlignLeading
	}
	addressesNavBtn.Disable()
	transactionsNavBtn.Disable()
	sendNavBtn.Disable()

	pages := []*container.TabItem{walletTab, addressesTab, transactionsTab, sendTab, networkTab}
	pageHost := container.NewStack(walletTab.Content, addressesTab.Content, transactionsTab.Content, sendTab.Content, networkTab.Content)
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
	transactionsNavBtn.OnTapped = func() { selectPage(transactionsTab, transactionsNavBtn) }
	sendNavBtn.OnTapped = func() { selectPage(sendTab, sendNavBtn) }
	networkNavBtn.OnTapped = func() { selectPage(networkTab, networkNavBtn) }
	selectPage(walletTab, walletNavBtn)

	const sidebarWidth float32 = 188
	navItem := func(btn *widget.Button) fyne.CanvasObject {
		return container.NewGridWrap(fyne.NewSize(sidebarWidth, 40), btn)
	}
	sidebarNavigation := container.NewVBox(
		container.NewPadded(container.NewVBox(brandWordmark(), brandTagline())),
		widget.NewSeparator(),
		navItem(walletNavBtn),
		navItem(addressesNavBtn),
		navItem(transactionsNavBtn),
		navItem(sendNavBtn),
		navItem(networkNavBtn),
	)
	themeToggle := container.NewGridWrap(fyne.NewSize(80, 40), themeToggleBtn.Container)
	sidebarInner := container.NewBorder(nil, container.NewCenter(themeToggle), nil, nil, sidebarNavigation)
	sidebarRail := container.NewStack(
		canvas.NewRectangle(qgDisplayBg),
		container.NewPadded(sidebarInner),
	)
	sidebarWithTheme := container.NewThemeOverride(sidebarRail, qogeSidebarTheme{Theme: newActiveQogeTheme()})
	footer := container.NewStack(
		canvas.NewRectangle(qgDisplayBg),
		container.NewVBox(widget.NewSeparator(), rpcFooterStatus),
	)
	pageContent := container.New(layout.NewCustomPaddedLayout(12, 12, 16, 16), pageHost)
	content := container.NewBorder(nil, nil,
		container.NewHBox(sidebarWithTheme, widget.NewSeparator()),
		nil, pageContent)
	contentWithBackground := container.NewStack(canvas.NewRectangle(qgDisplayBg), content)
	w.SetContent(container.NewBorder(nil, footer, nil, nil, contentWithBackground))

	w.SetCloseIntercept(func() {
		if wlt != nil {
			wlt.Close()
		}
		w.Close()
	})

	w.ShowAndRun()
}
