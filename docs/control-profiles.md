# Debian 13 audit profiles

The Debian 13 v0.4 scanner emits the complete 354-control catalog in every report. Applicable controls are audited; controls outside the selected profile are emitted as `not_applicable`. This keeps comparisons stable when profiles or host roles change.

## Coverage

- 334 Debian 13 benchmark controls across sections 1 through 7
- 322 automated read-only benchmark checks
- 12 explicit manual benchmark reviews
- 20 supplemental Linux security-health checks
- 354 unique normalized findings in every report

The supplemental checks cover filesystem exposure, local users, sudo policy, risky services, listening sockets, kernel state, held packages, and recent failed authentication activity.

## LSA deployment profiles

- `production_server` maps to `level2_server`.
- `minimal_server` maps to `level1_server`.
- `router` maps to `level2_server`; forwarding-related deviations should be documented as exceptions.
- `container` maps to `level1_server`; host-owned services that do not exist in the container normally resolve as not applicable or failed evidence depending on the benchmark procedure.

## Direct benchmark profiles

- `level1_server`
- `level2_server`
- `level1_workstation`
- `level2_workstation`

Level 2 profiles inherit their corresponding Level 1 profile.

## Result behavior

- `pass` — the observed state satisfies the audit procedure.
- `fail` — the observed state does not satisfy it.
- `manual` — the control requires human or policy review.
- `not_applicable` — the control is outside the selected profile, has a documented exception, or does not apply to the detected software state.
- `error` — evidence could not be evaluated reliably.

## Read-only boundary

The scanner never applies the remediation text bundled with a control. Audit code is rejected by tests if it contains package changes, service-state changes, account changes, permission changes, mounts, firewall mutations, kernel writes, destructive file operations, or writes into system paths. Three prototype checks that used temporary files were rewritten to evaluate their observations in memory.

Benchmark control IDs are normalized as `CIS-DEBIAN13-<section>`. Supplemental controls use `LSA-HEALTH-<id>`.
