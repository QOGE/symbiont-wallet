// cmd/gui/theme.go — QOGE brand theme for Symbiont Wallet.
//
// Palette tokens are lifted from qoge.org's stylesheet so the wallet,
// the brand site and (eventually) the pool site agree. Deliberate
// deviations from the web tokens are marked DEVIATION below.
//
// The theme is fixed-dark: it ignores fyne.ThemeVariant and always returns the
// dark palette. A wallet should look identical on every machine it is opened
// on — a user who has learned that magenta means "this is the action that
// spends money" should not have that cue change with an OS setting.

package main

import (
	_ "embed"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
)

// ---------------------------------------------------------------------------
// Brand tokens — qoge.org
// ---------------------------------------------------------------------------

var (
	// qgBg is --bg: night-blue canvas. Sidebar, cards, overlays, and headers
	// use this same field — one colour, no stacked surface lifts.
	qgBg      = color.NRGBA{R: 0x0E, G: 0x0E, B: 0x1A, A: 0xff}
	qgSidebar = qgBg
	qgSurface = qgBg

	// qgSurfaceHi is the only lifted fill: inputs and ordinary buttons, so
	// controls stay visible on the flat field without competing with magenta.
	qgSurfaceHi = color.NRGBA{R: 0x24, G: 0x24, B: 0x3A, A: 0xff}

	// qgText is the global foreground: a restrained dark grey-blue.
	qgText = color.NRGBA{R: 0x82, G: 0x8A, B: 0xA3, A: 0xff}

	// qgMuted is --muted: rgba(240,239,255,0.45).
	qgMuted = color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x73}

	// qgFundedSelectText is a restrained grey-blue for the dense FUNDED
	// address-and-balance selector in Send.
	qgFundedSelectText = qgText

	// qgFaint is below --muted, for retired rows and disabled labels.
	qgFaint = color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x40}

	// qgBorder is --border. DEVIATION: the web token is 0.08 alpha; at that
	// value Fyne's 1px separators disappear in a dense ledger. Lifted to 0.16.
	qgBorder = color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x29}

	// qgMagenta is --magenta: the single accent. Reserved for the one primary
	// action on screen. 4.8:1 against qgSurface — adequate as a label or
	// border, marginal for sustained body text, so it is never used for prose.
	qgMagenta = color.NRGBA{R: 0xD4, G: 0x00, B: 0xFF, A: 0xff}

	// qgOnMagenta is the label colour on a magenta fill. DEVIATION: white on
	// magenta is 4.0:1 and fails WCAG AA. Near-black is 5.2:1 and passes.
	qgOnMagenta = color.NRGBA{R: 0x0A, G: 0x0A, B: 0x12, A: 0xff}

	// qgCream is --logo-fill. Held in reserve for the wordmark only.
	qgCream = color.NRGBA{R: 0xED, G: 0xE8, B: 0xC8, A: 0xff}
)

// ---------------------------------------------------------------------------
// Lifecycle palette — consumed by the address ledger renderer
// ---------------------------------------------------------------------------
//
// One colour per keystore state, fixed for the life of the application. These
// are semantic, not decorative: a user reads the chip colour before the word.
//
// qgStateFresh is derived from --blue rather than being it. --blue (#0A14FF)
// measures 2.5:1 against the surface and is illegible standing alone; the site
// only ever renders it inside a gradient. This lift measures 6.4:1.

var (
	QGStateFresh   = color.NRGBA{R: 0x7C, G: 0x8C, B: 0xFF, A: 0xff} // FRESH
	QGStateFunded  = color.NRGBA{R: 0x4A, G: 0xDE, B: 0x80, A: 0xff} // FUNDED
	QGStatePending = color.NRGBA{R: 0xFB, G: 0xBF, B: 0x24, A: 0xff} // SPEND_PENDING
	QGStateSpent   = qgMuted                                         // SPENT
	QGStateRetired = qgFaint                                         // RETIRED
	QGStateDanger  = color.NRGBA{R: 0xF8, G: 0x71, B: 0x71, A: 0xff} // broadcast / failure
)

// QGStateTint returns a low-alpha fill for a state chip background, given the
// chip's foreground colour. Chip text uses the full-strength colour above.
func QGStateTint(c color.NRGBA) color.NRGBA {
	c.A = 0x28
	return c
}

func magentaAlpha(alpha uint8) color.NRGBA {
	c := qgMagenta
	c.A = alpha
	return c
}

// ---------------------------------------------------------------------------
// Fonts
// ---------------------------------------------------------------------------
//
// Space Grotesk Regular and Bold (SIL Open Font License 1.1); the accompanying
// license is in fonts/OFL.txt. Bold is used only when TextStyle.Bold is set.
// Italic and monospace requests keep Regular so UI chrome stays Space Grotesk.
//
// Space Mono Regular (SIL OFL 1.1, fonts/SpaceMono-OFL.txt) is reserved for
// the address ledger: a slightly smaller, non-bold tabular family so long
// bech32 strings scan as a pool rather than as UI headings.

//go:embed fonts/SpaceGrotesk-Regular.ttf
var spaceGroteskRegularTTF []byte

//go:embed fonts/SpaceGrotesk-Bold.ttf
var spaceGroteskBoldTTF []byte

//go:embed fonts/SpaceMono-Regular.ttf
var spaceMonoRegularTTF []byte

var (
	fontSpaceGroteskRegular = fyne.NewStaticResource("SpaceGrotesk-Regular.ttf", spaceGroteskRegularTTF)
	fontSpaceGroteskBold    = fyne.NewStaticResource("SpaceGrotesk-Bold.ttf", spaceGroteskBoldTTF)
	fontSpaceMonoRegular    = fyne.NewStaticResource("SpaceMono-Regular.ttf", spaceMonoRegularTTF)
)

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

// QogeTheme implements fyne.Theme against the QOGE brand palette.
type QogeTheme struct{}

var _ fyne.Theme = (*QogeTheme)(nil)

// NewQogeTheme returns the wallet theme. Install it with:
//
//	a := app.NewWithID("io.qoge.symbiont-wallet")
//	a.Settings().SetTheme(NewQogeTheme())
func NewQogeTheme() fyne.Theme { return &QogeTheme{} }

func (t *QogeTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {

	// Canvas and surfaces share qgBg. Inputs and ordinary buttons use
	// qgSurfaceHi so they remain visible as controls on the flat field.
	case theme.ColorNameBackground,
		theme.ColorNameOverlayBackground,
		theme.ColorNameMenuBackground,
		theme.ColorNameHeaderBackground:
		return qgBg
	case theme.ColorNameInputBackground:
		return qgSurfaceHi
	case theme.ColorNameButton:
		return qgSurfaceHi
	case theme.ColorNameDisabledButton:
		return qgBg

	// Text.
	case theme.ColorNameForeground:
		return qgText
	case theme.ColorNamePlaceHolder:
		return qgMuted
	case theme.ColorNameDisabled:
		return qgFaint

	// Accent. Fyne fills HighImportance buttons with ColorNamePrimary and
	// labels them with ColorNameForegroundOnPrimary — hence the near-black.
	case theme.ColorNamePrimary:
		return qgMagenta
	case theme.ColorNameForegroundOnPrimary:
		return qgOnMagenta
	case theme.ColorNameHyperlink:
		return QGStateFresh

	// Semantic roles.
	case theme.ColorNameSuccess:
		return QGStateFunded
	case theme.ColorNameForegroundOnSuccess:
		return qgOnMagenta
	case theme.ColorNameWarning:
		return QGStatePending
	case theme.ColorNameForegroundOnWarning:
		return qgOnMagenta
	case theme.ColorNameError:
		return QGStateDanger
	case theme.ColorNameForegroundOnError:
		return qgOnMagenta

	// Lines and interaction states.
	case theme.ColorNameSeparator,
		theme.ColorNameInputBorder:
		return qgBorder
	case theme.ColorNameHover:
		return color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x14}
	case theme.ColorNamePressed:
		return color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x22}
	case theme.ColorNameFocus,
		theme.ColorNameSelection:
		return magentaAlpha(0x4D)
	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x33}
	case theme.ColorNameScrollBarBackground:
		return qgBg
	case theme.ColorNameShadow:
		return color.NRGBA{A: 0x88}
	}

	return theme.DefaultTheme().Color(name, theme.VariantDark)
}

func (t *QogeTheme) Font(style fyne.TextStyle) fyne.Resource {
	if style.Bold {
		return fontSpaceGroteskBold
	}
	return fontSpaceGroteskRegular
}

func (t *QogeTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

// qogeSidebarTheme squares the nav buttons slightly without changing
// ordinary application-button radii.
type qogeSidebarTheme struct {
	fyne.Theme
}

// addressListSpacing is the gap between My Addresses rows. It is applied only
// to the address ledger so the rest of the app keeps the global type rhythm.
const addressListSpacing float32 = 3

// addressListRightInset pulls the balance/copy cluster off the scroll edge.
const addressListRightInset float32 = 5

// addressListTextSize is slightly smaller than the global body size (13).
const addressListTextSize float32 = 11

// addressIndexColWidth fits a 3-digit index in Space Mono 11 without using a
// widget.Label. Labels add InnerPadding on each side; a 48×22 GridWrap then
// clips the last glyph of "#11" and the STATUS chip paints over the overflow.
const addressIndexColWidth float32 = 36

// addressListRowHeight is the ledger row cell height. It tracks the mono
// glyph height, not Label inner-padding.
const addressListRowHeight float32 = 20

// qogeAddressListTheme tightens padding and sets Space Mono Regular for the
// address ledger only. Bold requests are ignored so the pool stays non-bold.
type qogeAddressListTheme struct {
	fyne.Theme
}

// qogeFundedSelectTheme gives only the Send From selector a quieter,
// denser text treatment. Other selects retain the application theme.
type qogeFundedSelectTheme struct {
	fyne.Theme
}

func (t qogeFundedSelectTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	if name == theme.ColorNameForeground || name == theme.ColorNamePlaceHolder {
		return qgFundedSelectText
	}
	return t.Theme.Color(name, variant)
}

func (t qogeFundedSelectTheme) Size(name fyne.ThemeSizeName) float32 {
	if name == theme.SizeNameText {
		return 11
	}
	return t.Theme.Size(name)
}

func (t qogeAddressListTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return addressListSpacing
	case theme.SizeNameInnerPadding:
		// Labels in this ledger must not add extra inset: InnerPadding was
		// clipping the last glyph of addresses and trailing balances.
		return 0
	case theme.SizeNameText, theme.SizeNameCaptionText:
		return addressListTextSize
	}
	return t.Theme.Size(name)
}

func (t qogeAddressListTheme) Font(_ fyne.TextStyle) fyne.Resource {
	return fontSpaceMonoRegular
}

func (t qogeSidebarTheme) Size(name fyne.ThemeSizeName) float32 {
	if name == theme.SizeNameButtonRadius {
		return 6
	}
	return t.Theme.Size(name)
}

func (t *QogeTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {

	// Type scale. Fyne's default body size is 14; 13 is tighter and lets the
	// ledger fit more rows without dropping below a legible size for a
	// 62-character address.
	case theme.SizeNameText:
		return 13
	case theme.SizeNameCaptionText:
		return 11
	case theme.SizeNameSubHeadingText:
		return 16
	case theme.SizeNameHeadingText:
		return 22

	// Spacing.
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInnerPadding:
		return 10
	case theme.SizeNameLineSpacing:
		return 4

	// Radii. These are the hooks that carry most of the visual change; Fyne's
	// stock values are squarer than the brand.
	case theme.SizeNameButtonRadius:
		return 8
	case theme.SizeNameInputRadius:
		return 8
	case theme.SizeNameSelectionRadius:
		return 6
	case theme.SizeNameCardRadius:
		return 14
	case theme.SizeNameDialogRadius:
		return 14
	case theme.SizeNamePopupRadius:
		return 12
	case theme.SizeNameMenuRadius:
		return 12

	// Hairlines and chrome.
	case theme.SizeNameSeparatorThickness:
		return 1
	case theme.SizeNameInputBorder:
		return 1
	case theme.SizeNameScrollBar:
		return 10
	case theme.SizeNameScrollBarSmall:
		return 4
	case theme.SizeNameScrollBarRadius:
		return 5
	case theme.SizeNameInlineIcon:
		return 18
	}

	return theme.DefaultTheme().Size(name)
}

// pageTitle is the large heading at the top of each page.
func pageTitle(text string) *canvas.Text {
	title := canvas.NewText(text, qgText)
	title.TextSize = 22
	title.TextStyle = fyne.TextStyle{Bold: true}
	return title
}

// brandWordmark is the cream sidebar mark reserved by qgCream.
func brandWordmark() *canvas.Text {
	mark := canvas.NewText("SYMBIONT", qgCream)
	mark.TextSize = 16
	mark.TextStyle = fyne.TextStyle{Bold: true}
	return mark
}

// brandTagline is the quiet product line under the wordmark.
func brandTagline() *canvas.Text {
	tag := canvas.NewText("QOGE WALLET", qgMuted)
	tag.TextSize = 10
	return tag
}

// summaryValue is the numeric line on a compact My Addresses stat card.
type summaryValue struct {
	text *canvas.Text
}

func (s *summaryValue) SetText(v string) {
	if s == nil || s.text == nil {
		return
	}
	s.text.Text = v
	s.text.Refresh()
}

// newSummaryCard returns a compact tinted tile. Accent is both the text colour
// and a low-alpha fill so Spendable / Pending / Total stay distinct without
// using Fyne's heading-sized Card widget.
func newSummaryCard(title, caption string, accent color.NRGBA) (*summaryValue, fyne.CanvasObject) {
	fill := accent
	fill.A = 0x38
	bg := canvas.NewRectangle(fill)
	bg.CornerRadius = 8

	heading := canvas.NewText(title, accent)
	heading.TextSize = 11
	heading.TextStyle = fyne.TextStyle{Bold: true}

	note := canvas.NewText(caption, qgMuted)
	note.TextSize = 9

	value := canvas.NewText("—", accent)
	value.TextSize = 12
	value.TextStyle = fyne.TextStyle{Bold: true}

	inner := container.New(layout.NewCustomPaddedVBoxLayout(1), heading, note, value)
	card := container.NewStack(bg, container.New(layout.NewCustomPaddedLayout(6, 6, 8, 8), inner))
	return &summaryValue{text: value}, card
}
