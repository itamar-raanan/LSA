# LSA UX/UI review

## Executive summary

LSA already exposes the essential security workflows—posture overview, Linux assets, findings, software inventory, fleet policy, evidence intake, and administration—but the experience is less coherent than the underlying product. The largest release risks are inconsistent visual foundations, an overloaded Agents workspace, inconsistent data-table behavior, and destructive actions without a consistent confirmation model.

The redesign should preserve the warm, calm product direction and focus first on operational clarity. The target workflow is: identify risk, understand affected scope, inspect evidence, and take a safe action without losing context.

- Overall UX score: **6/10**
- Overall UI score: **6/10**
- Target after the roadmap: **8.5/10** for both

## Strengths

- The product model is credible for security and systems teams.
- Navigation already separates daily operations from Administration.
- Asset, finding, policy, and software data can support useful drill-down workflows.
- Warm neutral surfaces distinguish LSA from generic dark “hacker” consoles.
- Existing loading, empty, and error states provide a foundation for consistent feedback.
- Frontend APIs are separated cleanly enough to redesign views without changing backend contracts.

## Weaknesses

- Legacy dark-theme declarations are repaired by a later override layer, which makes contrast regressions likely.
- Several pages use one-off buttons, overlays, tables, spacing, and labels instead of shared primitives.
- Small metadata and uppercase letter spacing reduce readability at operational density.
- Agents combines fleet navigation, group navigation, policy editing, version history, deployment, and creation flows in one crowded workspace.
- Dashboard metrics do not consistently open the investigation they summarize.
- Findings and Applications expose useful data but do not yet behave like persistent investigation queues.
- Destructive actions have inconsistent confirmation and impact messaging.

## Critical issues

| Priority | Problem | Why it hurts usability | Proposed solution | Expected benefit | Effort |
| --- | --- | --- | --- | --- | --- |
| High | Dark source styles plus warm overrides | New components can inherit black surfaces or low-contrast text unexpectedly | Replace legacy colors with semantic tokens at the source and remove repair overrides | Predictable contrast and faster UI work | Medium |
| High | Custom overlays lack a shared interaction model | Focus, Escape, focus return, stacking, and mobile fit can differ by dialog | Use one Radix-based Dialog/AlertDialog primitive | Accessible and consistent modal behavior | Medium |
| High | Agents has too many simultaneous navigation levels | Users must parse fleet, group, tab, category, form, and history context at once | Split into Fleet, Group, Policy, and Deployment components with progressive disclosure | Faster comprehension and fewer policy mistakes | Large |
| High | Destructive identity and fleet actions are inconsistent | A mistaken click can remove access or fleet trust | Require named confirmation with impact and recovery guidance | Safer administration | Medium |
| Medium | Tables implement different controls and responsive behavior | Users relearn basic operations on each page | Extend and adopt one enterprise SecurityTable | Predictable daily workflows | Large |
| Medium | Investigation context is not encoded in URLs | Returning from details can lose filters and scope | Store filters, sort, page, and selected facets in query parameters | Faster repeated investigation | Medium |

## Quick wins

1. Introduce semantic surface, text, border, status, focus, overlay, and z-index tokens.
2. Use Geist for all interface text while preserving technical casing and tabular numbers.
3. Remove global title-casing and raise very small operational labels to readable sizes.
4. Replace token, signing-key, enrollment, and confirmation overlays with the shared Dialog primitive.
5. Require confirmation before deleting an identity provider.
6. Reduce every page header to one primary action and only necessary supporting actions.

## Long-term improvements

- Create a persistent analyst investigation model across Dashboard, Findings, Applications, and Assets.
- Separate posture freshness, agent heartbeat, and intelligence freshness as distinct concepts.
- Add role-aware bulk workflows with preview, impact, and audit history.
- Add saved views for common asset and finding filters.
- Add visual regression coverage for the primary routes and responsive breakpoints.
- Measure task success using time-to-risk, time-to-affected-host, and policy publication errors.

## Navigation recommendations

Recommended primary structure:

- Overview
- Assets
- Applications
- Security Findings
- Agents
- Evidence Intake
- Administration

Administration should contain Users & Access, Authentication, Credentials & Trust, and TLS. Certificates should not return as a duplicate top-level destination. Tokens and Signing Keys should eventually become one Credentials & Trust section because both administer machine trust rather than daily security operations.

## Workflow improvements

### Risk investigation

**Current:** Overview → metric → manually locate list → apply filters → open host.

**Recommended:** Overview urgent item → pre-filtered Findings → finding inspector → affected Asset tab. Preserve the originating filter and scroll position on return.

### Asset investigation

**Current:** Assets → quick card or full record, with findings and inventory context split across surfaces.

**Recommended:** Assets → quick inspector for triage → full record with Overview, Findings, Applications, and Evidence tabs. Keep the inspector for comparison and lightweight context only.

### Fleet policy

**Current:** Agents → group → policy → category → edit/apply/history inside one dense canvas.

**Recommended:** Agents opens on All Hosts. Selecting a group opens a stable group header with Hosts, Policy, and Deployment tabs. Policy editing uses category navigation, a focused control workspace, and a Review & Publish step.

### Evidence intake

**Current:** Reports terminology mixes generated reports and uploaded scanner evidence.

**Recommended:** Rename to Evidence Intake. Explain accepted sources and connect missing-token states directly to Credentials & Trust for authorized users.

## Component improvements

| Component | Problem | Proposed solution | Benefit | Effort |
| --- | --- | --- | --- | --- |
| Buttons | Multiple class families and one-off icon controls | One Button API with primary, secondary, ghost, destructive, and icon variants | Consistent hierarchy and states | Medium |
| Dialogs | Custom fixed overlays | Shared Radix Dialog and AlertDialog | Focus safety, Escape, stacking, mobile fit | Medium |
| Cards | Similar data appears in different panel styles | Define metric, content, status, and inspector card roles | Clearer hierarchy | Medium |
| Tables | Controls and responsive rules vary | Shared SecurityTable with sort, filter, columns, selection, export, pagination | Predictable operations | Large |
| Badges | Status and severity can look interchangeable | Separate StatusBadge and SeverityBadge semantics | Faster scanning | Small |
| Forms | Help, validation, and action placement vary | Shared Field, inline error, hint, and form footer patterns | Lower error rate | Medium |
| Empty states | Some states explain but do not offer a next step | Add a permission-aware relevant action | Better feature discovery | Small |
| Toasts/errors | Feedback varies by page | Standardize success, recoverable error, and blocking error patterns | Clear recovery | Medium |

## Screen-by-screen recommendations

### Login

- **Problem:** Supporting copy competes with the only task: signing in.
- **Solution:** Keep username, password, one clear sign-in action, and concise authentication guidance.
- **Benefit:** Faster entry and fewer distractions.
- **Effort:** Small.

### Overview

- **Problem:** Metrics summarize state but do not consistently lead to action.
- **Solution:** Prioritize urgent findings, affected assets, stale agents, and compliance; make every item open a scoped destination.
- **Benefit:** System status is understandable in ten seconds and actionable immediately.
- **Effort:** Large.

### Assets

- **Problem:** The quick Host Card and full record can duplicate detail without a clear boundary.
- **Solution:** Use the card for triage and the full record for tabbed investigation; preserve table context.
- **Benefit:** Faster comparisons without losing the asset list.
- **Effort:** Medium.

### Applications

- **Problem:** Inventory, vulnerabilities, and affected hosts compete in one view.
- **Solution:** Lead with software exposure summary, then provide separate Vulnerabilities and Affected Hosts views with freshness/source context.
- **Benefit:** Clearer software-to-host correlation.
- **Effort:** Medium.

### Security Findings

- **Problem:** Category browsing is useful but does not yet act like a prioritized work queue.
- **Solution:** Add persistent facets, priority sorting, a detail inspector, evidence, affected hosts, and remediation guidance.
- **Benefit:** Analysts can triage and resolve findings efficiently.
- **Effort:** Large.

### Agents

- **Problem:** The workspace contains too many simultaneous panes and actions.
- **Solution:** Keep All Hosts as the default, use a stable group list, and progressively reveal Hosts, Policy, and Deployment tasks.
- **Benefit:** Group membership and policy intent stay understandable.
- **Effort:** Large.

### Evidence Intake

- **Problem:** “Reports” does not clearly describe import behavior.
- **Solution:** Rename, explain offline versus agent submission, show history and failures, and guide token creation.
- **Benefit:** Fewer failed imports and less terminology confusion.
- **Effort:** Medium.

### Administration

- **Problem:** Trust, identity, and access operations use inconsistent forms and confirmations.
- **Solution:** Standardize field help, validation, state feedback, and named destructive confirmations; consolidate credentials.
- **Benefit:** Safer administration and easier setup.
- **Effort:** Medium.

## Design system recommendations

- **Typography:** Geist throughout; page titles 28–36px, section titles 16–20px, body 13–15px, operational metadata no smaller than 11px. Preserve hostnames, IDs, CVEs, paths, protocols, and product names exactly.
- **Color:** Warm neutral surfaces for structure. Amber is the primary action/focus accent. Red, orange, yellow, green, and blue are reserved for severity or status.
- **Spacing:** Use a 4px base scale and prefer 8, 12, 16, 24, and 32px gaps.
- **Elevation:** Use borders and restrained shadows; avoid nested card stacks.
- **Motion:** 120–220ms for local state changes, transform/opacity only, and honor reduced motion.
- **Actions:** One primary action per state. Secondary actions support it; low-frequency actions belong in row or overflow menus.

## Accessibility recommendations

- Use semantic landmarks, headings, tables, buttons, and links before adding ARIA.
- Trap focus in modal dialogs; support Escape and return focus to the trigger.
- Provide visible focus with at least 3:1 contrast against adjacent surfaces.
- Expose sort direction, expanded state, selected rows, and validation errors programmatically.
- Do not communicate severity or status by color alone.
- Keep touch targets at least 40px where space permits.
- Support 360px width without page-level horizontal overflow.
- Respect `prefers-reduced-motion` and avoid animated layout properties.

## Prioritized implementation roadmap

The executable roadmap and acceptance criteria are maintained in [ui-roadmap.md](./ui-roadmap.md). Delivery proceeds from foundation and safety, through fleet operations and shared data workspaces, to investigation workflows and final administration polish.
