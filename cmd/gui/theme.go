// cmd/gui/theme.go — QOGE brand theme for Symbiont Wallet.
//
// Palette tokens are lifted verbatim from qoge.org's stylesheet so the wallet,
// the brand site and (eventually) the pool site agree. Two deliberate
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
	"fyne.io/fyne/v2/theme"
)

// ---------------------------------------------------------------------------
// Brand tokens — qoge.org
// ---------------------------------------------------------------------------

var (
	// qgBg is --bg: the window canvas.
	qgBg = color.NRGBA{R: 0x0E, G: 0x0E, B: 0x1A, A: 0xff}

	// qgSurface is --surface: cards, panels, popovers.
	qgSurface = color.NRGBA{R: 0x0E, G: 0x0E, B: 0x1A, A: 0xff}

	// A visible edge without competing with the accent.
	// Secondary controls should stay quiet.
	qgSurfaceHi = color.NRGBA{R: 0x24, G: 0x24, B: 0x3A, A: 0xff}

	// qgText is --text.
	qgText = color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0xff}

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
	c.A = 0x24
	return c
}

// ---------------------------------------------------------------------------
// Fonts
// ---------------------------------------------------------------------------
//
// Space Grotesk Regular (weight 400) is embedded under the SIL Open Font
// License 1.1; the accompanying license is in fonts/OFL.txt. Returning the
// same regular resource for every TextStyle keeps the application globally
// Space Grotesk normal, including labels that request bold or monospace.

//go:embed fonts/SpaceGrotesk-Regular.ttf
var spaceGroteskRegularTTF []byte

var fontSpaceGroteskRegular = fyne.NewStaticResource("SpaceGrotesk-Regular.ttf", spaceGroteskRegularTTF)

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

	// Canvas and surfaces.
	case theme.ColorNameBackground:
		return qgBg
	case theme.ColorNameOverlayBackground,
		theme.ColorNameMenuBackground:
		return qgSurface
	case theme.ColorNameHeaderBackground:
		return qgSurface
	case theme.ColorNameInputBackground:
		return qgSurfaceHi
	case theme.ColorNameButton:
		return qgSurfaceHi
	case theme.ColorNameDisabledButton:
		return qgSurface

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
		return color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x12}
	case theme.ColorNamePressed:
		return color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x1E}
	case theme.ColorNameFocus,
		theme.ColorNameSelection:
		return color.NRGBA{R: 0xD4, G: 0x00, B: 0xFF, A: 0x4D}
	case theme.ColorNameScrollBar:
		return color.NRGBA{R: 0xF0, G: 0xEF, B: 0xFF, A: 0x33}
	case theme.ColorNameShadow:
		return color.NRGBA{A: 0x66}
	}

	return theme.DefaultTheme().Color(name, theme.VariantDark)
}

func (t *QogeTheme) Font(_ fyne.TextStyle) fyne.Resource {
	return fontSpaceGroteskRegular
}

func (t *QogeTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

type qogeSidebarTheme struct {
	fyne.Theme
}

func (t qogeSidebarTheme) Size(name fyne.ThemeSizeName) float32 {
	if name == theme.SizeNameButtonRadius {
		return 3
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
		return 15
	case theme.SizeNameHeadingText:
		return 20

	// Spacing.
	case theme.SizeNamePadding:
		return 5
	case theme.SizeNameInnerPadding:
		return 9
	case theme.SizeNameLineSpacing:
		return 5

	// Radii. These are the hooks that carry most of the visual change; Fyne's
	// stock values are squarer than the brand.
	case theme.SizeNameButtonRadius:
		return 8
	case theme.SizeNameInputRadius:
		return 8
	case theme.SizeNameSelectionRadius:
		return 6
	case theme.SizeNameCardRadius:
		return 12
	case theme.SizeNameDialogRadius:
		return 12
	case theme.SizeNamePopupRadius:
		return 10
	case theme.SizeNameMenuRadius:
		return 10

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
