# Debian 13 audit profiles

The Debian 13 v0.6 scanner emits a deduplicated 390-control catalog in every report. Applicable controls are audited; controls outside the selected profile are emitted as `not_applicable`. This keeps comparisons stable when profiles or host roles change.

## Coverage

- 334 Debian 13 benchmark controls across sections 1 through 7
- 322 automated read-only benchmark checks
- 12 explicit manual benchmark reviews
- 56 non-overlapping portable Linux checks
- 390 unique normalized findings in every Debian 13 report

The full portable catalog contains 98 controls and runs on Debian 12, Ubuntu 22.04/24.04, and RHEL-family 8/9. Forty-two portable controls identify an equivalent Debian 13 benchmark control and are automatically suppressed when that benchmark is active.

The portable checks cover authentication and authorization, filesystem and boot security, SSH, network hardening, audit and logging, packages, services, local vulnerability signals, kernel state, time synchronization, persistence signals, container exposure, repository trust, and agent self-protection. Inventory controls that require a host-specific allowlist emit `review`; agent self-protection controls emit `not_applicable` when the agent is absent.

## Finding-category mapping

Every control has exactly one primary console category. Related evidence may cross domains, but the finding is not duplicated into multiple queues.

| Audit domain | Canonical finding categories |
| --- | --- |
| Authentication and authorization | `accounts` |
| Filesystems and boot security | `filesystem`, `kernel` |
| Expanded SSH hardening | `ssh` |
| Expanded network hardening | `network` |
| Audit and logging | `audit`, `logging`, `time` |
| Packages, services, and vulnerabilities | `packages`, `updates`, `services` |
| Additional operating systems | Uses the same canonical categories; OS is report metadata, not a finding category |

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
