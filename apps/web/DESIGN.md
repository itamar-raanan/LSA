---
name: Linux Security Auditor
description: A precise, warm security instrument for evidence-led Linux fleet operations.
colors:
  graphite-shell: "#292923"
  warm-paper: "#f1eee7"
  raised-paper: "#f7f4ed"
  evidence-surface: "#fbfaf6"
  evidence-strong: "#f4efe4"
  evidence-soft: "#ebe6dc"
  structural-line: "rgba(76, 67, 54, .14)"
  structural-line-strong: "rgba(76, 67, 54, .24)"
  primary-ink: "#292722"
  metadata-ink: "#716b61"
  operational-amber: "#a86b1f"
  amber-strong: "#c18431"
  amber-ink: "#fffaf0"
  incident-red: "#b74f52"
  exposure-orange: "#c66c38"
  stale-gold: "#b78a32"
  informational-blue: "#5d8196"
  assurance-green: "#4f8063"
  focus-amber: "#9a611d"
  overlay: "rgba(47, 42, 34, .48)"
typography:
  display:
    fontFamily: "Geist Variable, Geist, Avenir Next, system-ui, sans-serif"
    fontSize: "28px"
    fontWeight: 650
    lineHeight: 1.08
    letterSpacing: "-0.03em"
  headline:
    fontFamily: "Geist Variable, Geist, Avenir Next, system-ui, sans-serif"
    fontSize: "22px"
    fontWeight: 600
    lineHeight: 1.15
    letterSpacing: "-0.035em"
  title:
    fontFamily: "Geist Variable, Geist, Avenir Next, system-ui, sans-serif"
    fontSize: "12px"
    fontWeight: 600
    lineHeight: 1.5
  body:
    fontFamily: "Geist Variable, Geist, Avenir Next, system-ui, sans-serif"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.6
  label:
    fontFamily: "Geist Variable, Geist, Avenir Next, system-ui, sans-serif"
    fontSize: "10px"
    fontWeight: 600
    lineHeight: 1.5
    letterSpacing: "0.02em"
rounded:
  sm: "5px"
  md: "7px"
  lg: "10px"
  pill: "999px"
spacing:
  xs: "8px"
  sm: "10px"
  md: "12px"
  lg: "16px"
  xl: "20px"
  2xl: "24px"
components:
  button-primary:
    backgroundColor: "{colors.operational-amber}"
    textColor: "{colors.amber-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "0 14px"
    height: "34px"
  button-secondary:
    backgroundColor: "{colors.raised-paper}"
    textColor: "{colors.primary-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "0 14px"
    height: "34px"
  input:
    backgroundColor: "{colors.evidence-surface}"
    textColor: "{colors.primary-ink}"
    typography: "{typography.body}"
    rounded: "{rounded.sm}"
    padding: "0 12px"
    height: "38px"
  filter-chip:
    backgroundColor: "{colors.raised-paper}"
    textColor: "{colors.metadata-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "0 11px"
    height: "34px"
  panel:
    backgroundColor: "{colors.evidence-surface}"
    textColor: "{colors.primary-ink}"
    rounded: "{rounded.md}"
---

# Design System: Linux Security Auditor

## Overview

**Creative North Star: "The Security Instrument"**

Linux Security Auditor should feel like a calibrated instrument: precise, warm, calm, sharp, premium, and trustworthy. The graphite operational shell establishes orientation and restraint; the warm cream workspace and evidence surfaces keep dense analysis legible without becoming clinical.

The system favors compact enterprise analyst density and decisive hierarchy. Operators authenticate with minimal friction, enter a dense console, scan security state, and act without losing source evidence or host context. It explicitly rejects hacker or neon aesthetics, decorative gradients, black cards, oversized controls, ornamental color, and soft consumer-SaaS styling.

**Key Characteristics:**
- Compact, evidence-led information density.
- Warm paper surfaces inside a graphite operational shell.
- Structural borders and tonal layering instead of decorative shadow.
- Amber reserved for action and current state.
- Calm semantic color for assurance, incidents, severity, and evidence status.

## Colors

The palette combines Graphite Shell, Warm Paper, and Evidence Surface neutrals with Operational Amber, Assurance Green, and Incident Red as disciplined operational signals.

### Primary
- **Operational Amber:** Use for primary actions, current navigation state, active filters, focus, and the smallest necessary emphasis.
- **Amber Strong:** Use for controlled highlights and the brand mark, never as general decoration.
- **Amber Ink:** Use for text and icons placed on amber actions.

### Secondary
- **Assurance Green:** Use for healthy, verified, online, or safely completed states.
- **Incident Red:** Use for critical findings, destructive actions, revoked states, and incident-level urgency.
- **Exposure Orange:** Use for high-severity exposure below critical.
- **Stale Gold:** Use for warning, medium severity, and stale evidence states.
- **Informational Blue:** Use for low-severity or informational security signals.

### Neutral
- **Graphite Shell:** Use for the persistent desktop navigation shell and dark brand anchor.
- **Warm Paper:** Use for the main workspace canvas.
- **Raised Paper:** Use for quiet controls, rails, and shallow tonal separation.
- **Evidence Surface:** Use for panels, tables, dialogs, and the login form.
- **Evidence Strong:** Use for table headers and stronger grouped regions.
- **Evidence Soft:** Use for subdued controls and inset regions.
- **Primary Ink:** Use for headings, decisive labels, and primary data.
- **Metadata Ink:** Use for secondary descriptions and metadata; rendered metadata must maintain at least 4.5:1 contrast against its surface.
- **Structural Line / Structural Line Strong:** Use to define hierarchy, grouping, and boundaries without shadow.
- **Overlay:** Use behind dialogs, command surfaces, and inspectors.

**The Amber Discipline Rule.** Amber communicates action or current state; its rarity is part of the hierarchy.

**The Metadata Contrast Rule.** Operational metadata must maintain a contrast ratio of at least 4.5:1 on every warm surface.

## Typography

**Display Font:** Geist Variable (with Geist, Avenir Next, system-ui, and sans-serif fallbacks)

**Body Font:** Geist Variable (with Geist, Avenir Next, system-ui, and sans-serif fallbacks)

**Label/Mono Font:** Geist Variable, using tabular numerals where data alignment matters

**Character:** Geist is used everywhere for a single, disciplined voice. Tight, heavy display text creates sharp orientation while compact labels, metadata, and tabular numerals support fast analyst scanning.

### Hierarchy
- **Display** (650, compact 28px, 1.08): Page titles and primary route orientation.
- **Headline** (600, compact 22px, 1.15): Dialog, inspector, and investigation titles.
- **Title** (600, compact 12px, 1.5): Panel headings and high-value row titles.
- **Body** (400, compact 12px, 1.6): Explanations, instructions, and evidence context; keep descriptive copy near 58–68 characters per line where practical.
- **Label** (600, compact 10px, 0.02em tracking): Kicker text, table headers, metadata labels, and statuses.

**The One-Family Rule.** Use Geist everywhere; code-like and numeric content gains tabular alignment rather than a separate monospace personality.

## Layout

Desktop uses a persistent graphite sidebar, a restrained top bar, and a warm workspace capped at 1580px with 24px horizontal padding. The default rhythm is compact: 8–12px between related controls, 16–24px between groups, 34px controls, 52–54px table and toolbar rows, and 120px minimum metric panels. Dense tables and split workspaces preserve source context alongside actions.

At 1023px the sidebar yields to mobile navigation and workspace padding tightens. At 767px multi-column metrics collapse to two columns, toolbars stack, nonessential table columns move into expandable details, and page padding becomes 12px. At 640px summary grids and investigation context collapse; overlays use near-full viewport bounds. At 479px the system further simplifies metadata and actions while retaining the same compact control language.

**The Context-Preservation Rule.** Responsive layouts may stack or progressively disclose, but must not separate an action from the evidence, host, or security state needed to judge it.

## Elevation & Depth

The system is flat and layered. Structural borders, warm tonal changes, inset rules, and occasional one-pixel accent rails establish depth by default; ordinary panels and cards use no ambient shadow. The login form receives a soft ambient shadow because it is a singular authentication surface. Dialogs, command surfaces, inspectors, and floating quick views may use stronger ambient shadow over a muted overlay to signal temporary elevation.

### Shadow Vocabulary
- **Flat:** No shadow for ordinary panels, cards, tables, and workspace sections.
- **Raised Login:** A broad, restrained ambient shadow for the centered authentication form.
- **Floating Overlay:** A deeper ambient shadow for dialogs, inspectors, and command surfaces that sit above active context.

**The Flat-by-Default Rule.** Borders and tonal layers carry structure; ambient shadow is reserved for login and temporary overlays.

## Shapes

The form language is compact and mechanical without becoming harsh. Core controls use a restrained 5px radius, panels use 7px, and dialogs or singular shells use 10px. Pills are reserved for filters and short status labels; severity badges are tighter still. One-pixel borders define containers, rows, and control states, while thin amber rails identify selection or current state.

**The Radius Ladder Rule.** Use the 5px / 7px / 10px ladder for controls, panels, and overlays; do not introduce large soft consumer radii.

## Components

### Buttons
- **Shape:** Compact and decisive, with a restrained control radius and fixed 34px height.
- **Primary:** Operational Amber with Amber Ink, a slightly darker border, and 12–16px horizontal padding according to label length.
- **Hover / Focus:** Darken the amber and border on hover; use the system focus outline, then compress to 97% on active press.
- **Secondary / Ghost:** Secondary buttons use Raised Paper with a structural border; ghost buttons stay transparent until hover.
- **Danger / Success:** Semantic buttons use Incident Red or Assurance Green only when the action itself carries that meaning.

### Chips
- **Style:** Compact 34px filter pills use Raised Paper, a structural border, and metadata-colored 10–11px labels.
- **State:** Active chips shift to a warm amber-tinted evidence surface and amber-brown ink; press feedback moves down by one pixel.

### Cards / Containers
- **Corner Style:** Evidence panels use the middle radius.
- **Background:** Evidence Surface over Warm Paper, with Evidence Strong or Evidence Soft for grouped subregions.
- **Shadow Strategy:** Flat by default; see Elevation & Depth.
- **Border:** One-pixel structural lines define the perimeter and internal sections.
- **Internal Padding:** Compact panels use 12–16px; investigation and dialog bodies may use 20–24px.

### Inputs / Fields
- **Style:** Evidence Surface, structural border, compact radius, 38px standard field height, and 12px horizontal padding.
- **Focus:** Shift the border to Operational Amber and add a restrained two-pixel amber focus halo.
- **Error / Disabled:** Errors use Incident Red border, text, and a pale red evidence surface; disabled controls retain shape and reduce opacity.

### Navigation

Desktop navigation sits on Graphite Shell with quiet stone labels. Hover raises contrast without introducing color; the active item gains warm light text, a subtle graphite tonal shift, and a thin amber rail. Mobile navigation preserves the same active-state grammar and prioritizes direct access to search and route controls.

### Brand Mark

The 32px graphite instrument mark contains three amber evidence bars at distinct heights. It is square, compact, and structural, pairing with the full product name and the restrained "Fleet Intelligence" descriptor where space allows.

### Data Tables and Statuses

Tables use warm header bands, 36px headers, approximately 52px data rows, structural row dividers, and subtle hover fill. Severity badges use small squared corners; state pills use the pill silhouette. Color supplements explicit text labels and never carries meaning alone.

## Do's and Don'ts

### Do:
- **Do** use amber only for primary action, current state, or a narrow evidence emphasis.
- **Do** preserve compact 34px controls and the 5px / 7px / 10px radius ladder.
- **Do** use borders, section rules, and tonal layers to make dense evidence scannable.
- **Do** keep metadata contrast at or above 4.5:1 and preserve visible keyboard focus.
- **Do** keep actions beside the host, evidence, and security state required to judge them.

### Don't:
- **Don't** use hacker styling, neon color, or decorative gradients.
- **Don't** introduce black content cards, ornamental color, or shadow-heavy card stacks.
- **Don't** enlarge routine controls or soften the interface into consumer-SaaS styling.
- **Don't** use amber as ambient decoration or semantic status when a specific severity color exists.
- **Don't** hide safety boundaries, evidence lineage, or stale-state consequences behind visual polish.
