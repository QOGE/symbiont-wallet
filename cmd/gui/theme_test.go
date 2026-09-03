package main

import (
	"image/color"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	fynetest "fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
)

func TestQogeThemeTypeScaleIsReadable(t *testing.T) {
	th := NewQogeTheme()
	if got := th.Size(theme.SizeNameText); got != 13 {
		t.Fatalf("text size = %v, want 13", got)
	}
	if got := th.Size(theme.SizeNameCaptionText); got != 11 {
		t.Fatalf("caption size = %v, want 11", got)
	}
	if got := th.Size(theme.SizeNameSubHeadingText); got < 15 {
		t.Fatalf("subheading size = %v, want >= 15", got)
	}
	if got := th.Size(theme.SizeNameHeadingText); got < 20 {
		t.Fatalf("heading size = %v, want >= 20", got)
	}
}

func colorNRGBA(t *testing.T, c color.Color) color.NRGBA {
	t.Helper()
	nr, ok := c.(color.NRGBA)
	if !ok {
		t.Fatalf("color type %T, want color.NRGBA", c)
	}
	return nr
}

func TestQogeThemeStaysDarkAndUsesBrandMagenta(t *testing.T) {
	th := NewQogeTheme()
	wantMagenta := color.NRGBA{R: 0xD4, G: 0x00, B: 0xFF, A: 0xff}
	if got := colorNRGBA(t, th.Color(theme.ColorNamePrimary, theme.VariantLight)); got != wantMagenta {
		t.Fatalf("primary (light variant) = %#v, want %#v", got, wantMagenta)
	}
	if got := colorNRGBA(t, th.Color(theme.ColorNamePrimary, theme.VariantDark)); got != wantMagenta {
		t.Fatalf("primary (dark variant) = %#v, want %#v", got, wantMagenta)
	}
	wantText := color.NRGBA{R: 0x82, G: 0x8A, B: 0xA3, A: 0xff}
	if got := colorNRGBA(t, th.Color(theme.ColorNameForeground, theme.VariantDark)); got != wantText {
		t.Fatalf("foreground = %#v, want %#v", got, wantText)
	}
}

func TestQogeThemeUsesFlatCanvas(t *testing.T) {
	th := NewQogeTheme()
	for _, name := range []fyne.ThemeColorName{
		theme.ColorNameBackground,
		theme.ColorNameOverlayBackground,
		theme.ColorNameMenuBackground,
		theme.ColorNameHeaderBackground,
		theme.ColorNameScrollBarBackground,
	} {
		if got := colorNRGBA(t, th.Color(name, theme.VariantLight)); got != qgBg {
			t.Fatalf("%s = %#v, want %#v", name, got, qgBg)
		}
	}
	if qgSidebar != qgBg || qgSurface != qgBg {
		t.Fatal("sidebar and surface tokens must alias qgBg")
	}
}

func TestAddressListThemeUsesCustomSpacing(t *testing.T) {
	th := qogeAddressListTheme{Theme: NewQogeTheme()}
	if got := th.Size(theme.SizeNamePadding); got != addressListSpacing {
		t.Fatalf("address list padding = %v, want %v", got, addressListSpacing)
	}
	if got := th.Size(theme.SizeNameInnerPadding); got != 0 {
		t.Fatalf("address list inner padding = %v, want 0 so glyphs are not clipped", got)
	}
}

func TestAddressIndexColumnFitsTwoDigitIndexes(t *testing.T) {
	fynetest.NewApp()
	defer fynetest.NewApp()

	txt := canvas.NewText("#11", qgText)
	txt.TextSize = addressListTextSize
	txt.FontSource = fontSpaceMonoRegular
	if txt.MinSize().Width >= addressIndexColWidth {
		t.Fatalf("#11 width %v does not fit index column %v", txt.MinSize().Width, addressIndexColWidth)
	}
	three := canvas.NewText("#999", qgText)
	three.TextSize = addressListTextSize
	three.FontSource = fontSpaceMonoRegular
	if three.MinSize().Width >= addressIndexColWidth {
		t.Fatalf("#999 width %v does not fit index column %v", three.MinSize().Width, addressIndexColWidth)
	}
}

func TestAddressListThemeUsesSmallerNonBoldMono(t *testing.T) {
	global := NewQogeTheme()
	th := qogeAddressListTheme{Theme: global}
	if got := th.Size(theme.SizeNameText); got >= global.Size(theme.SizeNameText) {
		t.Fatalf("address list text size = %v, want smaller than global %v", got, global.Size(theme.SizeNameText))
	}
	if got := th.Font(fyne.TextStyle{}).Name(); got != "SpaceMono-Regular.ttf" {
		t.Fatalf("address list font = %q, want SpaceMono-Regular.ttf", got)
	}
	if got := th.Font(fyne.TextStyle{Bold: true}).Name(); got != "SpaceMono-Regular.ttf" {
		t.Fatalf("address list bold request = %q, want SpaceMono-Regular.ttf", got)
	}
	if global.Font(fyne.TextStyle{Bold: true}).Name() != "SpaceGrotesk-Bold.ttf" {
		t.Fatal("global UI must still use Space Grotesk Bold")
	}
}

func TestSummaryCardsUseLifecycleColours(t *testing.T) {
	spendable, _ := newSummaryCard("Spendable", "FUNDED", QGStateFunded)
	pending, _ := newSummaryCard("Pending", "SPEND_PENDING", QGStatePending)
	total, _ := newSummaryCard("Addresses", "Total", QGStateFresh)
	if colorNRGBA(t, spendable.text.Color) != QGStateFunded {
		t.Fatalf("spendable colour = %#v, want %#v", spendable.text.Color, QGStateFunded)
	}
	if colorNRGBA(t, pending.text.Color) != QGStatePending {
		t.Fatalf("pending colour = %#v, want %#v", pending.text.Color, QGStatePending)
	}
	if colorNRGBA(t, total.text.Color) != QGStateFresh {
		t.Fatalf("total colour = %#v, want %#v", total.text.Color, QGStateFresh)
	}
	if spendable.text.TextSize >= 22 || pending.text.TextSize >= 22 {
		t.Fatal("summary values must not use heading size")
	}
}

func TestQogeThemeBoldUsesBoldFont(t *testing.T) {
	th := NewQogeTheme()
	regular := th.Font(fyne.TextStyle{})
	bold := th.Font(fyne.TextStyle{Bold: true})
	if regular.Name() != "SpaceGrotesk-Regular.ttf" {
		t.Fatalf("regular font = %q", regular.Name())
	}
	if bold.Name() != "SpaceGrotesk-Bold.ttf" {
		t.Fatalf("bold font = %q", bold.Name())
	}
	if th.Font(fyne.TextStyle{Monospace: true}).Name() != "SpaceGrotesk-Regular.ttf" {
		t.Fatal("monospace should stay Space Grotesk Regular")
	}
}
