// cmd/gui/theme.go — QOGE brand theme for Symbiont Wallet.
//
// Palette tokens are lifted from qoge.org's stylesheet so the wallet,
// the brand site and (eventually) the pool site agree. Deliberate
// deviations from the web tokens are marked DEVIATION below.
//
// The application selects an explicit dark or light palette at runtime rather
// than following the host OS preference. This prevents an OS theme change from
// silently producing a half-light/half-dark UI.

package main

import (
	_ "embed"
	"image/color"
	"sync/atomic"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
)

type qogePalette struct {
	bg, surface, surfaceHi, disabledButton, text, muted, faint, border color.NRGBA
	magenta, onMagenta, cream                                          color.NRGBA
	fresh, funded, pending, spent, retired, danger                     color.NRGBA
	hover, pressed, focus, scrollBar, shadow                           color.NRGBA
	onSemantic                                                         color.NRGBA
}

var qogeDarkPalette = qogePalette{
	bg: color.NRGBA{R: 0x0E, G: 0x0E, B: 0x1A, A: 0xff}, surface: color.NRGBA{R: 0x0E, G: 0x0E, B: 0x1A, A: 0xff}, surfaceHi: color.NRGBA{R: 0x24, G: 0x24, B: 0x3A, A: 0xff}, disabledButton: color.NRGBA{R: 0x0E, G: 0x0E, B: 0x1A, A: 0xff},
	text: color.NRGBA{R: 0x82, G: 0x8A, B: 0xA3, A: 0xff}, muted: color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x73}, faint: color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x40}, border: color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x29},
	magenta: color.NRGBA{R: 0xD4, G: 0x00, B: 0xFF, A: 0xff}, onMagenta: color.NRGBA{R: 0x0A, G: 0x0A, B: 0x12, A: 0xff}, cream: color.NRGBA{R: 0xED, G: 0xE8, B: 0xC8, A: 0xff},
	fresh: color.NRGBA{R: 0x7C, G: 0x8C, B: 0xFF, A: 0xff}, funded: color.NRGBA{R: 0x4A, G: 0xDE, B: 0x80, A: 0xff}, pending: color.NRGBA{R: 0xFB, G: 0xBF, B: 0x24, A: 0xff}, danger: color.NRGBA{R: 0xF8, G: 0x71, B: 0x71, A: 0xff},
	hover: color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x14}, pressed: color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x22}, focus: color.NRGBA{R: 0xD4, G: 0x00, B: 0xFF, A: 0x4D}, scrollBar: color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x33}, shadow: color.NRGBA{A: 0x88}, onSemantic: color.NRGBA{R: 0x0A, G: 0x0A, B: 0x12, A: 0xff},
}

var qogeLightPalette = qogePalette{
	bg: color.NRGBA{R: 0xF5, G: 0xF6, B: 0xFA, A: 0xff}, surface: color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xff}, surfaceHi: color.NRGBA{R: 0xE4, G: 0xE7, B: 0xF0, A: 0xff}, disabledButton: color.NRGBA{R: 0xEE, G: 0xF0, B: 0xF5, A: 0xff},
	text: color.NRGBA{R: 0x39, G: 0x44, B: 0x5A, A: 0xff}, muted: color.NRGBA{R: 0x66, G: 0x70, B: 0x85, A: 0xff}, faint: color.NRGBA{R: 0x98, G: 0xA2, B: 0xB3, A: 0xff}, border: color.NRGBA{R: 0xC9, G: 0xCF, B: 0xDC, A: 0xff},
	magenta: color.NRGBA{R: 0xD9, G: 0x8C, B: 0xEB, A: 0xff}, onMagenta: color.NRGBA{R: 0x0A, G: 0x0A, B: 0x12, A: 0xff}, cream: color.NRGBA{R: 0x5B, G: 0x4F, B: 0x28, A: 0xff},
	fresh: color.NRGBA{R: 0x40, G: 0x54, B: 0xC7, A: 0xff}, funded: color.NRGBA{R: 0x16, G: 0x7A, B: 0x45, A: 0xff}, pending: color.NRGBA{R: 0x8A, G: 0x5A, B: 0x00, A: 0xff}, danger: color.NRGBA{R: 0xB4, G: 0x23, B: 0x18, A: 0xff},
	hover: color.NRGBA{A: 0x0F}, pressed: color.NRGBA{A: 0x18}, focus: color.NRGBA{R: 0xD9, G: 0x8C, B: 0xEB, A: 0x38}, scrollBar: color.NRGBA{R: 0x7B, G: 0x84, B: 0x98, A: 0xff}, shadow: color.NRGBA{A: 0x33}, onSemantic: color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xff},
}

func init() {
	qogeDarkPalette.spent, qogeDarkPalette.retired = qogeDarkPalette.muted, qogeDarkPalette.faint
	qogeLightPalette.spent, qogeLightPalette.retired = qogeLightPalette.muted, qogeLightPalette.faint
}

var qogeLightActive atomic.Bool

type adaptiveColor struct{ dark, light color.NRGBA }

func (c adaptiveColor) RGBA() (uint32, uint32, uint32, uint32) {
	if qogeLightActive.Load() {
		return c.light.RGBA()
	}
	return c.dark.RGBA()
}

func adaptive(dark, light color.NRGBA) color.Color { return adaptiveColor{dark: dark, light: light} }

var (
	qogeSunIcon  = theme.NewThemedResource(fyne.NewStaticResource("qoge-theme-sun.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="#000000" d="M11 1h2v3h-2V1zm0 19h2v3h-2v-3zM1 11h3v2H1v-2zm19 0h3v2h-3v-2zM4.22 2.81l2.12 2.12-1.41 1.41L2.81 4.22l1.41-1.41zm13.44 13.44 2.12 2.12-1.41 1.41-2.12-2.12 1.41-1.41zM2.81 19.78l2.12-2.12 1.41 1.41-2.12 2.12-1.41-1.41zM17.66 6.34l-1.41-1.41 2.12-2.12 1.41 1.41-2.12 2.12zM12 6a6 6 0 1 1 0 12 6 6 0 0 1 0-12zm0 2a4 4 0 1 0 0 8 4 4 0 0 0 0-8z"/></svg>`)))
	qogeMoonIcon = theme.NewThemedResource(fyne.NewStaticResource("qoge-theme-moon.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="none" stroke="#000000" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`)))

	qgDisplayBg         = adaptive(qogeDarkPalette.bg, qogeLightPalette.bg)
	qgDisplaySidebar    = adaptive(qogeDarkPalette.bg, qogeLightPalette.surface)
	qgDisplayText       = adaptive(qogeDarkPalette.text, qogeLightPalette.text)
	qgDisplayMuted      = adaptive(qogeDarkPalette.muted, qogeLightPalette.muted)
	qgDisplayFaint      = adaptive(qogeDarkPalette.faint, qogeLightPalette.faint)
	qgDisplayBorder     = adaptive(qogeDarkPalette.border, qogeLightPalette.border)
	qgDisplayToggleEdge = adaptive(qogeDarkPalette.border, qogeLightPalette.border)
	qgDisplaySunEdge    = adaptive(color.NRGBA{}, qogeLightPalette.border)
	qgDisplayCream      = adaptive(qogeDarkPalette.cream, qogeLightPalette.cream)
	QGDisplayFresh      = adaptive(qogeDarkPalette.fresh, qogeLightPalette.fresh)
	QGDisplayFunded     = adaptive(qogeDarkPalette.funded, qogeLightPalette.funded)
	QGDisplayPending    = adaptive(qogeDarkPalette.pending, qogeLightPalette.pending)
	QGDisplaySpent      = adaptive(qogeDarkPalette.spent, qogeLightPalette.spent)
	QGDisplayRetired    = adaptive(qogeDarkPalette.retired, qogeLightPalette.retired)
)

func adaptiveTint(c color.Color, darkAlpha, lightAlpha uint8) color.Color {
	if dynamic, ok := c.(adaptiveColor); ok {
		dark, light := dynamic.dark, dynamic.light
		dark.A, light.A = darkAlpha, lightAlpha
		return adaptive(dark, light)
	}
	r, g, b, _ := c.RGBA()
	return color.NRGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: darkAlpha}
}

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
type QogeTheme struct{ light, followActive bool }

var _ fyne.Theme = (*QogeTheme)(nil)

// NewQogeTheme returns the wallet theme. Install it with:
//
//	a := app.NewWithID("io.qoge.symbiont-wallet")
//	a.Settings().SetTheme(NewQogeTheme())
func NewQogeTheme() fyne.Theme       { return &QogeTheme{} }
func NewQogeLightTheme() fyne.Theme  { return &QogeTheme{light: true} }
func newActiveQogeTheme() fyne.Theme { return &QogeTheme{followActive: true} }

func setQogeTheme(a fyne.App, light bool) {
	qogeLightActive.Store(light)
	if light {
		a.Settings().SetTheme(NewQogeLightTheme())
		return
	}
	a.Settings().SetTheme(NewQogeTheme())
}

func (t *QogeTheme) palette() (qogePalette, fyne.ThemeVariant) {
	light := t.light
	if t.followActive {
		light = qogeLightActive.Load()
	}
	if light {
		return qogeLightPalette, theme.VariantLight
	}
	return qogeDarkPalette, theme.VariantDark
}

func (t *QogeTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	p, fallbackVariant := t.palette()
	switch name {

	// Canvas and surfaces share qgBg. Inputs and ordinary buttons use
	// qgSurfaceHi so they remain visible as controls on the flat field.
	case theme.ColorNameBackground:
		return p.bg
	case theme.ColorNameOverlayBackground,
		theme.ColorNameMenuBackground,
		theme.ColorNameHeaderBackground:
		return p.surface
	case theme.ColorNameInputBackground:
		return p.surfaceHi
	case theme.ColorNameButton:
		return p.surfaceHi
	case theme.ColorNameDisabledButton:
		return p.disabledButton

	// Text.
	case theme.ColorNameForeground:
		return p.text
	case theme.ColorNamePlaceHolder:
		return p.muted
	case theme.ColorNameDisabled:
		return p.faint

	// Accent. Fyne fills HighImportance buttons with ColorNamePrimary and
	// labels them with ColorNameForegroundOnPrimary — hence the near-black.
	case theme.ColorNamePrimary:
		return p.magenta
	case theme.ColorNameForegroundOnPrimary:
		return p.onMagenta
	case theme.ColorNameHyperlink:
		return p.fresh

	// Semantic roles.
	case theme.ColorNameSuccess:
		return p.funded
	case theme.ColorNameForegroundOnSuccess:
		return p.onSemantic
	case theme.ColorNameWarning:
		return p.pending
	case theme.ColorNameForegroundOnWarning:
		return p.onSemantic
	case theme.ColorNameError:
		return p.danger
	case theme.ColorNameForegroundOnError:
		return p.onSemantic

	// Lines and interaction states.
	case theme.ColorNameSeparator,
		theme.ColorNameInputBorder:
		return p.border
	case theme.ColorNameHover:
		return p.hover
	case theme.ColorNamePressed:
		return p.pressed
	case theme.ColorNameFocus,
		theme.ColorNameSelection:
		return p.focus
	case theme.ColorNameScrollBar:
		return p.scrollBar
	case theme.ColorNameScrollBarBackground:
		return p.bg
	case theme.ColorNameShadow:
		return p.shadow
	}

	return theme.DefaultTheme().Color(name, fallbackVariant)
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

// qogeFundedSelectTheme gives only the Send From selector a slightly smaller
// type treatment than general application controls. Its foreground follows the
// active application palette through the embedded theme.
type qogeFundedSelectTheme struct {
	fyne.Theme
}

// qogeSunToggleTheme keeps the light-mode selector visually distinct from the
// pale magenta used by the rest of the light palette.
type qogeSunToggleTheme struct {
	fyne.Theme
}

func (t qogeSunToggleTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	if qogeLightActive.Load() {
		switch name {
		case theme.ColorNamePrimary:
			return color.NRGBA{}
		case theme.ColorNameForeground, theme.ColorNameForegroundOnPrimary:
			return qogeLightPalette.border
		}
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
	title := canvas.NewText(text, qgDisplayText)
	title.TextSize = 22
	title.TextStyle = fyne.TextStyle{Bold: true}
	return title
}

// brandWordmark is the cream sidebar mark reserved by qgCream.
func brandWordmark() *canvas.Text {
	mark := canvas.NewText("SYMBIONT", qgDisplayCream)
	mark.TextSize = 16
	mark.TextStyle = fyne.TextStyle{Bold: true}
	return mark
}

// brandTagline is the quiet product line under the wordmark.
func brandTagline() *canvas.Text {
	tag := canvas.NewText("QOGE WALLET", qgDisplayMuted)
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
func newSummaryCard(title, caption string, accent color.Color) (*summaryValue, fyne.CanvasObject) {
	bg := canvas.NewRectangle(adaptiveTint(accent, 0x38, 0x24))
	bg.CornerRadius = 8

	heading := canvas.NewText(title, accent)
	heading.TextSize = 11
	heading.TextStyle = fyne.TextStyle{Bold: true}

	note := canvas.NewText(caption, qgDisplayMuted)
	note.TextSize = 9

	value := canvas.NewText("—", accent)
	value.TextSize = 12
	value.TextStyle = fyne.TextStyle{Bold: true}

	inner := container.New(layout.NewCustomPaddedVBoxLayout(1), heading, note, value)
	card := container.NewStack(bg, container.New(layout.NewCustomPaddedLayout(6, 6, 8, 8), inner))
	return &summaryValue{text: value}, card
}
