// cmd/gui/main.go — minimal Fyne GUI for Symbiont Wallet
//
// Covers only the RECEIVE side: open/create a wallet, generate a fresh
// P2QPK address, and mark an address as payment-received.
//
// Deliberately NOT included: the send/sign flow (SignP2QPKInput), which
// needs real UTXO data from a node and its own design. Also not included:
// a "list all addresses + state" view — keystore.KeyIndex.ListByState exists
// but is not yet exposed through the wallet.Wallet public API.
package main

import (
	"encoding/hex"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/saogen/qoge-sphincs-wallet/wallet"
)

func main() {
	a := app.NewWithID("io.qoge.symbiont-wallet")
	w := a.NewWindow("Symbiont Wallet")
	w.Resize(fyne.NewSize(480, 400))

	var wlt *wallet.Wallet

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
		newWallet, err := wallet.New("wallet.db", seed)
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

	w.SetContent(container.NewVBox(
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
	))

	w.SetCloseIntercept(func() {
		if wlt != nil {
			wlt.Close()
		}
		w.Close()
	})

	w.ShowAndRun()
}
