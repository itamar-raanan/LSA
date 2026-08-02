# Debian 13 control profiles

The Debian 13 scanner emits every catalogued control in every report. Profile-specific controls use `not_applicable` instead of disappearing, preserving stable comparisons and making coverage visible.

## Profiles

- `production_server` — general-purpose long-running server with host firewall, audit, time, logging, and automatic-update services.
- `minimal_server` — reduced server footprint while retaining host security services.
- `router` — network-forwarding system; the IPv4-forwarding prohibition is not applicable.
- `container` — image-managed workload without host-level systemd, firewall, audit, AppArmor, cron, or persistent-journal ownership.

## Control groups

- `UPD` — security repository, pending upgrades, reboot state, and automatic updates.
- `FS` — ownership and permissions for identity databases.
- `ACC` — empty passwords and privileged-account identity.
- `SSH` — root and password login, empty passwords, authentication attempts, X11, and rhosts.
- `NET` — forwarding, nftables, legacy remote access, and listening-socket review.
- `KRN` — core dumps, ASLR, kernel-pointer exposure, kernel logs, and process tracing.
- `PKG` and `SVC` — unattended-upgrades package and cron service posture.
- `OBS` — auditd, AppArmor, time synchronization, and persistent journaling.

Control IDs use the `LSA-DEBIAN13-*` namespace. They must not be presented as CIS-certified mappings unless a separately licensed and verified benchmark mapping is introduced.
