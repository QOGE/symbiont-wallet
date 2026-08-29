// cmd/gui/main.go — Fyne GUI for Symbiont Wallet
//
// Three tabs:
//   - Receive:   open/create wallet, generate fresh P2QPK address, mark payment received.
//   - Addresses: list every address with its lifecycle state and optional on-chain balance.
//   - Send:      build, preview, sign, and display a raw P2QPK spend transaction.
//               broadcast is manual (copy hex → qogecoin-cli sendrawtransaction).
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

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

func main() {
	a := app.NewWithID("io.qoge.symbiont-wallet")
	w := a.NewWindow("Symbiont Wallet")
	w.Resize(fyne.NewSize(620, 640))

	var wlt *wallet.Wallet
	var rpc *rpcclient.Client

	// ── Receive tab ────────────────────────────────────────────────────────

	status := widget.NewLabel("No wallet open.")
	status.Wrapping = fyne.TextWrapWord

	addrDisplay := widget.NewEntry()
	addrDisplay.Disable()

	seedEntry := widget.NewPasswordEntry()
	seedEntry.SetPlaceHolder("32-byte seed, hex-encoded (64 hex chars)")

	openBtn := widget.NewButton("Open / Create Wallet", func() {
		seedHex := seedEntry.Text
		seed, err := hex.DecodeString(seedHex)
		if err != nil || len(seed) != 32 {
			dialog.ShowError(fmt.Errorf("seed must be exactly 32 bytes, hex-encoded (64 hex chars)"), w)
			return
		}
		if wlt != nil {
			wlt.Close()
			wlt = nil
		}
		newWallet, err := wallet.New(walletDBPath(), seed)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		wlt = newWallet
		status.SetText("Wallet open.")
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
		status.SetText("New address generated — share this to receive funds.")
	})

	markReceivedEntry := widget.NewEntry()
	markReceivedEntry.SetPlaceHolder("Address that received a payment")

	markReceivedBtn := widget.NewButton("Mark Payment Received", func() {
		if wlt == nil {
			dialog.ShowError(fmt.Errorf("open a wallet first"), w)
			return
		}
		if err := wlt.MarkPaymentReceived(markReceivedEntry.Text); err != nil {
			dialog.ShowError(err, w)
			return
		}
		status.SetText("Address marked PENDING — awaiting confirmation before spend.")
	})

	receiveTab := container.NewTabItem("Receive",
		container.NewVBox(
			widget.NewLabel("Seed (hex, 64 chars):"),
			seedEntry,
			openBtn,
			widget.NewSeparator(),
			newAddrBtn,
			widget.NewLabel("Your P2QPK address:"),
			addrDisplay,
			widget.NewSeparator(),
			markReceivedEntry,
			markReceivedBtn,
			widget.NewSeparator(),
			status,
		),
	)

	// ── Addresses tab ──────────────────────────────────────────────────────

	addrListBox := container.NewVBox()
	addrListScroll := container.NewVScroll(addrListBox)
	addrListScroll.SetMinSize(fyne.NewSize(0, 220))

	addrStatusLabel := widget.NewLabel("Open a wallet, then press Refresh.")
	addrStatusLabel.Wrapping = fyne.TextWrapWord

	rpcEndpoint := widget.NewEntry()
	rpcEndpoint.SetPlaceHolder("host:port  (e.g. 127.0.0.1:8332)")
	rpcUser := widget.NewEntry()
	rpcUser.SetPlaceHolder("RPC username")
	rpcPass := widget.NewPasswordEntry()
	rpcPass.SetPlaceHolder("RPC password")

	rpcStatusLabel := widget.NewLabel("No node connected — balances will not be shown.")
	rpcStatusLabel.Wrapping = fyne.TextWrapWord

	connectBtn := widget.NewButton("Connect to Node", func() {
		ep := rpcEndpoint.Text
		user := rpcUser.Text
		pass := rpcPass.Text
		if ep == "" {
			rpcStatusLabel.SetText("No endpoint entered — leave blank to skip balance lookup.")
			rpc = nil
			return
		}
		c := rpcclient.New(ep, user, pass)
		if err := c.Ping(context.Background()); err != nil {
			rpcStatusLabel.SetText(fmt.Sprintf("Node unreachable: %v", err))
			rpc = nil
			return
		}
		rpc = c
		rpcStatusLabel.SetText(fmt.Sprintf("Connected to %s", ep))
	})

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
				}
			}
		}

		addrListBox.RemoveAll()
		if len(infos) == 0 {
			addrListBox.Add(widget.NewLabel("(no addresses)"))
		}
		for _, info := range infos {
			var line string
			if balances != nil {
				sats := balances[info.Address]
				line = fmt.Sprintf("#%-3d  %-8s  %-14s  %s",
					info.Index, info.State,
					rpcclient.FormatQOGE(sats)+" QOGE",
					info.Address)
			} else {
				line = fmt.Sprintf("#%-3d  %-8s  %s",
					info.Index, info.State, info.Address)
			}
			lbl := widget.NewLabel(line)
			lbl.TextStyle = fyne.TextStyle{Monospace: true}
			addrListBox.Add(lbl)
		}
		addrListBox.Refresh()

		summary := fmt.Sprintf("%d address(es)", len(infos))
		if balanceErr != "" {
			summary += " — " + balanceErr
		} else if balances != nil {
			summary += " — balances from node"
		} else {
			summary += " — no node connected, state only"
		}
		addrStatusLabel.SetText(summary)
	})

	addressesTab := container.NewTabItem("Addresses",
		container.NewVBox(
			widget.NewLabel("Node RPC (optional — leave blank for state-only view):"),
			rpcEndpoint,
			rpcUser,
			rpcPass,
			connectBtn,
			rpcStatusLabel,
			widget.NewSeparator(),
			refreshBtn,
			addrListScroll,
			widget.NewSeparator(),
			addrStatusLabel,
		),
	)

	// ── Send tab ───────────────────────────────────────────────────────────
	//
	// Flow:
	//   1. Select From address (must be PENDING — has received a payment)
	//   2. Select To address (must be FRESH — wallet-controlled)
	//   3. Enter amount in QOGE
	//   4. Click "Preview" → fetches UTXO, computes change, shows confirm dialog
	//   5. Click "Sign" in dialog → signs, serializes BIP144, displays raw hex
	//   6. Broadcast manually: qogecoin-cli sendrawtransaction <hex>
	//
	// After broadcast+confirmation, call OnConfirmation on the From address
	// (currently a CLI-only operation) to mark it SPENT.

	sendFromSelect := widget.NewSelect(nil, nil)
	sendFromSelect.PlaceHolder = "(no PENDING addresses — mark payment received first)"

	sendToSelect := widget.NewSelect(nil, nil)
	sendToSelect.PlaceHolder = "(no FRESH addresses)"

	amountEntry := widget.NewEntry()
	amountEntry.SetPlaceHolder("e.g. 1 or 0.5")

	sendStatusLabel := widget.NewLabel("")
	sendStatusLabel.Wrapping = fyne.TextWrapWord

	rawHexEntry := widget.NewMultiLineEntry()
	rawHexEntry.Disable()
	rawHexEntry.SetPlaceHolder("Signed transaction hex will appear here after signing.")
	rawHexScroll := container.NewVScroll(rawHexEntry)
	rawHexScroll.SetMinSize(fyne.NewSize(0, 100))

	testMempoolBtn := widget.NewButton("Test in Mempool (testmempoolaccept)", func() {
		hexStr := rawHexEntry.Text
		if hexStr == "" {
			sendStatusLabel.SetText("No signed transaction — preview and sign first.")
			return
		}
		if rpc == nil {
			sendStatusLabel.SetText("No node connected — connect from the Addresses tab first.")
			return
		}
		result, err := rpc.TestMempoolAccept(context.Background(), hexStr)
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
		var pending, fresh []string
		for _, info := range infos {
			switch info.State {
			case keystore.StatePending:
				pending = append(pending, info.Address)
			case keystore.StateFresh:
				fresh = append(fresh, info.Address)
			}
		}
		sendFromSelect.Options = pending
		if len(pending) == 0 {
			sendFromSelect.PlaceHolder = "(no PENDING addresses — mark payment received first)"
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
			sendStatusLabel.SetText("Select a From address (PENDING).")
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
		utxoSats := int64(utxo.Amount*float64(rpcclient.SatoshisPerQOGE) + 0.5)

		feeSats := txbuilder.FixedFeeSats
		changeSats, err := txbuilder.CalcChange(utxoSats, sendSats, feeSats)
		if err != nil {
			sendStatusLabel.SetText(err.Error())
			return
		}

		// Peek the auto-selected change address (lowest-index FRESH).
		changeAddr, err := wlt.NextReceiveAddress()
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

		// Build the preview text shown in the confirm dialog.
		previewText := fmt.Sprintf(
			"From:      %s\n\n"+
				"To:        %s\n\n"+
				"Amount:    %s QOGE  (%d sat)\n"+
				"Fee:       0.00010000 QOGE  (%d sat)  [fixed]\n"+
				"Change:    %s QOGE  (%d sat)\n"+
				"  → to:   %s\n\n"+
				"UTXO:      %s:%d  (%s QOGE)\n\n"+
				"⚠  This will irreversibly spend real mainnet QOGE.\n"+
				"   The signed transaction will NOT be broadcast automatically.\n"+
				"   You must broadcast it manually via:\n"+
				"     qogecoin-cli sendrawtransaction <hex>",
			fromAddr,
			toAddr,
			rpcclient.FormatQOGE(sendSats), sendSats,
			feeSats,
			rpcclient.FormatQOGE(changeSats), changeSats,
			changeAddr,
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

				// Convert txid from RPC display order to wire byte order.
				txidLE, err := txbuilder.TxIDLEFromHex(utxo.Txid)
				if err != nil {
					sendStatusLabel.SetText(fmt.Sprintf("txid conversion error: %v", err))
					return
				}

				// Derive scriptPubKey for the From address (the UTXO being spent).
				fromScript, err := txbuilder.P2QPKScript(fromAddr)
				if err != nil {
					sendStatusLabel.SetText(fmt.Sprintf("from script error: %v", err))
					return
				}

				// Build scriptPubKeys for To and Change outputs.
				toScript, err := txbuilder.P2QPKScript(toAddr)
				if err != nil {
					sendStatusLabel.SetText(fmt.Sprintf("to script error: %v", err))
					return
				}
				changeScript, err := txbuilder.P2QPKScript(changeAddr)
				if err != nil {
					sendStatusLabel.SetText(fmt.Sprintf("change script error: %v", err))
					return
				}

				params := wallet.P2QPKSpendParams{
					NVersion:  2,
					NLockTime: 0,
					Inputs: []wallet.SpendInput{
						{TxIDLE: txidLE, Vout: utxo.Vout, NSequence: 0xFFFFFFFF},
					},
					SpentUTXOs: []wallet.SpentUTXO{
						{Amount: utxoSats, Script: fromScript},
					},
					Outputs: []wallet.SpendOutput{
						{Amount: sendSats, Script: toScript},
						{Amount: changeSats, Script: changeScript},
					},
					InputIndex: 0,
					FromAddr:   fromAddr,
					ChangeAddr: changeAddr,
				}

				pubKey, sig, err := wlt.SignP2QPKInput(params)
				if err != nil {
					sendStatusLabel.SetText(fmt.Sprintf("SignP2QPKInput error: %v", err))
					return
				}

				signed := txbuilder.SignedP2QPKTx{
					NVersion:  params.NVersion,
					NLockTime: params.NLockTime,
					Inputs: []txbuilder.TxInput{
						{TxIDLE: txidLE, Vout: utxo.Vout, NSequence: 0xFFFFFFFF},
					},
					Outputs: []txbuilder.TxOutput{
						{Amount: sendSats, Script: toScript},
						{Amount: changeSats, Script: changeScript},
					},
					Sig:    sig,
					PubKey: pubKey,
				}

				raw, err := txbuilder.SerializeBIP144(signed)
				if err != nil {
					sendStatusLabel.SetText(fmt.Sprintf("serialization error: %v", err))
					return
				}

				rawHexEntry.Enable()
				rawHexEntry.SetText(hex.EncodeToString(raw))
				rawHexEntry.Disable()

				sendStatusLabel.SetText(fmt.Sprintf(
					"Signed — %d bytes raw tx (%d bytes hex).\n"+
						"From address is still PENDING until OnConfirmation is called after broadcast+confirm.\n"+
						"Change address %s is now PENDING.\n"+
						"Broadcast manually: qogecoin-cli sendrawtransaction <hex>",
					len(raw), len(raw)*2, changeAddr))
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

	sendTab := container.NewTabItem("Send",
		container.NewVBox(
			widget.NewLabel("From address (PENDING — has received a payment):"),
			sendFromSelect,
			widget.NewLabel("To address (FRESH — wallet-controlled recipient):"),
			sendToSelect,
			widget.NewLabel("Amount (QOGE):"),
			container.NewHBox(amountEntry, widget.NewLabel("  Fee: 0.0001 QOGE fixed")),
			refreshSendBtn,
			previewBtn,
			widget.NewSeparator(),
			widget.NewLabel("Signed transaction hex (broadcast manually):"),
			rawHexScroll,
			testMempoolBtn,
			widget.NewSeparator(),
			sendStatusLabel,
		),
	)

	// ── Window layout ──────────────────────────────────────────────────────

	tabs := container.NewAppTabs(receiveTab, addressesTab, sendTab)
	w.SetContent(tabs)

	w.SetCloseIntercept(func() {
		if wlt != nil {
			wlt.Close()
		}
		w.Close()
	})

	w.ShowAndRun()
}
