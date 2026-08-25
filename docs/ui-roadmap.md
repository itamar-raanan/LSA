# LSA frontend roadmap

This roadmap implements the approved UX/UI audit from foundational risk to product polish. Each phase must preserve existing API contracts and pass the offline frontend test, lint, and production-build checks before moving forward.

## Phase 1 — Foundation and accessibility (high)

- Consolidate the warm palette into semantic design tokens.
- Remove the legacy dark-theme declarations and specificity overrides.
- Use Geist consistently, preserve technical casing, and keep operational text at readable sizes.
- Standardize primary, secondary, ghost, destructive, and icon buttons.
- Replace custom overlays with accessible dialog and confirmation primitives.
- Establish named z-index layers for navigation, inspectors, dialogs, menus, and tooltips.
- Add visual regression coverage for Login, Overview, Assets, Host Card, Agents, and Administration.

Acceptance criteria:

- No dark surface appears inside the warm workspace.
- No page-level rule globally recolors Tailwind utilities to repair contrast.
- Dialog focus is trapped, Escape closes the dialog, and focus returns to its trigger.
- Technical values keep their original casing.
- Keyboard focus is visible on every interactive control.

## Phase 2 — Core operations (high)

Implementation status: complete. Fleet status, inventory, group navigation, workspace header, Policy, and Deployment behavior now live in focused Agent components, leaving the route page responsible for data loading and workspace orchestration. The policy category rail was replaced with one scoped selector, keeping Fleet Groups and the Hosts/Policy/Deployment workspace tabs as the only navigation levels. Host Detail exposes URL-addressable Overview, Findings, Applications, and Evidence workspaces.

- Split Agents into Fleet, Group, Policy, and Deployment components.
- Keep one clear primary action in each workspace state.
- Separate agent heartbeat health from audit-report freshness.
- Add named confirmation for provider deletion, agent revocation, user disablement, and administrator role changes.
- Convert Asset Detail into Overview, Findings, Applications, and Evidence tabs.

Acceptance criteria:

- The Agents workspace never renders more than two navigation levels at once.
- A group policy can be understood, edited, reviewed, and published without losing group context.
- Destructive identity and fleet actions explain their impact before execution.

## Phase 3 — Data workspaces (medium)

Implementation status: complete for the primary analyst workspaces. The shared table supports controlled URL state, responsive priority columns with row disclosure, selection feedback, sticky headers, and server pagination. Assets, Applications, and Findings now execute search, filters, sorting, and pagination in the database while preserving lightweight aggregate facets and deep-link investigation context. Existing unpaged API callers retain their original response shapes. Agents, Users, Tokens, and Signing Keys use the same table behavior with client-side datasets appropriate to their current scale.

- Extend SecurityTable for filters, selection, bulk actions, sticky headers, and server pagination.
- Adopt it for Applications, Findings, Tokens, Signing Keys, Users, and Agents.
- Preserve filters and investigation context in the URL.
- Add priority-column and expandable-row behavior for narrow screens.

Acceptance criteria:

- Sorting, filtering, pagination, columns, row actions, and export behave consistently.
- Every table remains usable at 360px without page-level horizontal overflow.
- Screen readers receive the active sort direction and selection state.

## Phase 4 — Investigation workflows (medium)

Implementation status: complete. The Overview now prioritizes urgent findings, affected assets, stale reports, and compliance using bounded server queries rather than complete fleet downloads. Dashboard, Finding, and Application drill-downs carry a validated local return target into Host Detail, so the exact queue, filters, search, sort, page, and selected record are restored. Investigation surfaces now identify posture freshness and the locally retained report or cached vulnerability-intelligence source.

- Rework Overview around urgent findings, affected assets, stale agents, and compliance.
- Make every dashboard metric open a pre-filtered destination.
- Make Findings a priority queue with category facets and a dedicated detail inspector.
- Separate vulnerability and affected-host views in Application investigation.
- Add data-freshness and intelligence-source context.

Acceptance criteria:

- An analyst reaches an affected asset from an urgent dashboard item in two interactions or fewer.
- Returning from an asset preserves the original queue and filters.
- Every investigation surface answers what happened, why it matters, and what to do next.

## Phase 5 — Administration and polish (low)

Implementation status: complete. Credentials and Trust consolidates ingestion tokens and signing keys, Reports is now Evidence Intake, and administrators receive direct first-run actions from empty workspaces. Global search supports full keyboard operation and bounded server-side entity search across assets, applications, and findings. Shared date formatting, page-specific loading structures, warm-theme recovery states, responsive behavior, and the routed 404 experience complete the final console polish pass.

- Consolidate Tokens and Signing Keys under Credentials & Trust.
- Rename Reports to Evidence Intake and add a route to token creation for administrators.
- Add action-bearing empty states, consistent timestamps, and page-specific skeletons.
- Implement real command-palette keyboard navigation and entity search.
- Add a useful 404 page and finish responsive and accessibility QA.

Acceptance criteria:

- Navigation names match page purpose and product terminology.
- Empty states always provide a relevant next step when the user has permission.
- The command palette does not advertise unsupported keyboard or search behavior.

## Delivery sequence

1. UI foundation
2. Agents workspace
3. Shared data table
4. Asset and finding investigation
5. Dashboard and application correlation
6. Administration consolidation
7. Final accessibility, responsive, and performance pass
