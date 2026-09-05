# Symbiont Wallet GUI Sidebar and Dual-Theme Implementation Report

Prepared for: Claude Sonnet, project manager  
Updated: 2026-09-05  
Repository: `/home/ion/symbiont-wallet`  
Branch: `main`

## Executive summary

The Symbiont Wallet Fyne GUI now uses a permanent left navigation sidebar and an explicit QOGE dark/light theme system. The work modernized the presentation of the existing wallet features without changing signing, transaction serialization, address decoding, lifecycle rules, or RPC protocol behavior.

The current interface has five pages: Wallet, My Addresses, Transactions, Send, and Network. The default window is `1100x860`. Page content uses increased horizontal padding, while the sidebar retains compact spacing. A persistent RPC status footer remains visible across every page.

## Sidebar implementation

The former visible top tabs were replaced with a 188-pixel left navigation rail. The application retains the existing `container.AppTabs` internally as the authoritative page-selection and enable/disable model; sidebar buttons select those same `TabItem` instances rather than introducing a second navigation state machine.

Current sidebar behavior:

- Wallet and Network are available before a wallet is loaded.
- My Addresses, Transactions, and Send are disabled until a wallet is successfully opened or created.
- The active navigation button uses the primary accent background; inactive buttons use a quiet, transparent low-importance treatment.
- Sidebar buttons use a scoped 6-pixel radius without changing the 8-pixel radius of ordinary application buttons.
- Each entry has an icon and label on one row.
- Sidebar and footer use the same adaptive background color in each theme.
- The QOGE wordmark and product tagline remain at the top.
- The theme selector is centered at the bottom, independent of the navigation list.

The sidebar selects Wallet initially. Page visibility, tab selection, and active-button importance are updated together by the shared `selectPage` callback.

## Current page layout

### Wallet

- Seed entry and secure generated-seed display
- Open Existing Wallet and Create New Wallet actions
- Mandatory seed-backup acknowledgement for creation
- Compact lifecycle controls and wallet status

### My Addresses

- Spendable, pending, and total-address summary cards
- Refresh/status row
- Expandable address ledger with index, lifecycle state, full address, balance, and per-row copy icon
- Optional display of SPENT and RETIRED records
- Concentration warning below the ledger
- No redundant “Generate New Address” preview; visible FRESH rows are the receive/copy surface

### Transactions

- Reverse-chronological local history of outgoing sends and genuine external deposits
- Full transaction IDs with copy controls
- Internal change excluded from incoming history
- Wallet-loaded gating identical to My Addresses and Send

### Send

- FUNDED source selector with address balances
- Separate wallet-owned and external destination modes
- Refresh icon adjacent to the From selector, with matching reserved space beside the lower selector
- Left-aligned amount and action sequence: Preview Transaction, Test Transaction, Broadcast Transaction
- Distinct success styling for mempool testing and danger styling for broadcast
- Expanded transaction-preview area for reliable inspection of long addresses

### Network

- Manual RPC host, port, username, and password controls
- Automatic local cookie-auth connection remains part of wallet open/create
- Theme selection lives in the permanent sidebar, not this page

## Dual-theme implementation

`cmd/gui/theme.go` contains a full custom implementation of Fyne's `Theme` interface: `Color`, `Font`, `Icon`, and `Size`. Theme selection is explicit and does not follow the host OS preference, preventing an unexpected mixed-theme wallet UI.

The application starts in dark mode and switches at runtime through `app.Settings().SetTheme()`. Explicit `canvas.Text` and `canvas.Rectangle` objects that bypass Fyne's named color roles use adaptive color wrappers, so the page background, sidebar, footer, address ledger, lifecycle chips, summary cards, wordmark, and separators all update with the selected theme.

Local `container.NewThemeOverride` instances use an active-theme wrapper rather than a permanently dark theme. This applies to the sidebar, dense My Addresses ledger, and smaller FUNDED-source selector in Send.

### Dark palette

- Background, sidebar, footer, and flat surfaces: `#0E0E1A`
- Elevated inputs and ordinary buttons: `#24243A`
- Foreground text: `#828AA3`
- Primary accent: `#D400FF`
- Foreground on primary: `#0A0A12`
- Wordmark cream: `#EDE8C8`
- FRESH: `#7C8CFF`
- FUNDED/success: `#4ADE80`
- SPEND_PENDING/warning: `#FBBF24`
- Danger/error: `#F87171`
- SPENT and RETIRED use muted and faint foreground roles

### Light palette

- Background, sidebar, and footer: `#F5F6FA`
- Overlay, menu, and header surfaces: `#FFFFFF`
- Inputs and ordinary buttons: `#E4E7F0`
- Disabled buttons: `#EEF0F5`
- Foreground text: `#39445A`
- Muted text: `#667085`
- Faint/disabled text: `#98A2B3`
- Borders: `#C9CFDC`
- Primary accent: pale magenta `#D98CEB`
- Foreground on primary: `#0A0A12`
- Wordmark: `#5B4F28`
- FRESH: `#4054C7`
- FUNDED/success: `#167A45`
- SPEND_PENDING/warning: `#8A5A00`
- Danger/error: `#B42318`
- Semantic-button foreground: `#FFFFFF`

The light palette does not blindly reuse dark-theme foreground, border, interaction, shadow, or lifecycle colors. Each was adjusted for readable contrast and appropriate visual weight on a pale canvas. The dark palette's strong pure magenta remains unchanged.

## Segmented theme selector

The bottom of the sidebar contains a compact two-segment theme selector:

- Moon and sun symbols are always visible side by side.
- Moon selects dark mode; sun selects light mode.
- Selecting the already-active segment is a no-op, so theme and visual state cannot drift apart.
- The outer control is one bordered box with an 8-pixel radius.
- Its border uses the active theme's standard border color.
- In light mode, the sun segment has a transparent fill; its symbol and 1-pixel segment outline use the light border gray `#C9CFDC`.
- Custom sun and moon SVGs are Fyne themed resources, not bitmap assets.

Fyne 2.8.0 has no dedicated built-in sun or moon icon. Its chromatic and achromatic icons describe color rather than light/dark appearance, so small custom SVG resources provide clearer semantics.

## Typography, icons, and component styling

- Space Grotesk Regular is the application-wide normal face.
- Space Grotesk Bold is used when a widget explicitly requests bold text.
- Space Mono Regular is scoped to dense address-ledger content.
- Standard application/navigation icons continue to come from Fyne's default theme.
- Primary, success, warning, and danger importance roles remain semantically distinct.
- Address-state chips and summary cards use low-alpha lifecycle tints rather than full-strength fills.

## Relevant landed commits

- `37e6e8c` — `feat: refresh GUI layout and apply QOGE theme`
- `c6221ec` — `chore: remove redundant Generate New Address display from My Addresses`
- `9b2de87` — `feat: polish GUI theme and My Addresses ledger`
- `9cdbf24` — `chore: unify My Addresses ledger ink and free the status row`
- `582e931` — `feat: show FUNDED balances in Send selector`
- `fc9ad2d` — `style: use grey-blue foreground across GUI theme`
- `0a67522` — `feat: add Transactions tab recording outgoing sends and genuine external deposits`
- `e05e8be` — `chore: combine amount field and action buttons into one left-aligned row in Send tab`
- `ebcd6cb` — `feat: add light theme and segmented sidebar toggle`

This report describes the resulting current interface rather than preserving superseded intermediate dimensions, colors, tab counts, or control arrangements.

## Behavior intentionally unchanged

The sidebar and dual-theme work do not alter:

- Wallet creation/opening or seed authentication
- Five-state address lifecycle rules
- Balance and confirmation scanning
- Transaction-history persistence rules
- P2QPK signing
- Transaction construction or serialization
- Destination-address validation
- Mempool testing or broadcast authorization
- Local-cookie or manual RPC authentication

## Verification

The implementation has been exercised with:

- `gofmt -l ./cmd/gui`
- `git diff --check`
- `go vet ./...`
- `go build ./cmd/gui`
- `go test ./...`
- `go test -race ./...`

Theme tests cover named dark/light color roles, runtime switching, adaptive canvas colors, and synchronization between the segmented selector's active side and installed application theme. GUI navigation tests retain real-canvas click coverage for wallet-loaded page gating.

The running application was also inspected throughout the layout work. That inspection caught a container-wrapping issue in the initial segmented-toggle implementation that unit tests did not expose, reinforcing that green tests demonstrate behavioral non-regression but do not replace visual review for Fyne layout and styling.

## Suggested review focus

1. Confirm the five sidebar entries and wallet-loaded gating behavior.
2. Inspect all pages at the default `1100x860` size and at smaller supported sizes.
3. Switch repeatedly between light and dark modes and confirm canvas-rendered ledger/card elements update with ordinary widgets.
4. Confirm full addresses, balances, transaction IDs, and status messages remain readable.
5. Confirm Preview, Test Transaction, and Broadcast retain their distinct safety styling and gating.
6. Confirm the bottom theme selector remains visible, centered, and legible in both palettes.
