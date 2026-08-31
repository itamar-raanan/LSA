# Native Linux agent packages

`build-agent-packages.sh` produces architecture-specific Debian and RPM packages
from the same versioned source used by the universal archive. Both packages
install the scanner and hardened systemd unit, but deliberately leave the service
disabled until an administrator completes one-time enrollment.

Each artifact includes all Python dependency wheels required by its build
architecture for Python 3.11, 3.12, and 3.13. The enrollment command installs only
from that integrity-protected wheelhouse with `--no-index`, so managed hosts never
need PyPI or public internet access.

Build on a Linux host with `dpkg-deb` and `rpmbuild`:

```bash
./packaging/build-agent-packages.sh ./dist/agents
```

The default build resolves binary wheels from PyPI once on the packaging host. For
a fully disconnected or reproducible packaging environment, prepare a reviewed
wheelhouse separately and pass it without allowing the build script network access:

```bash
LSA_AGENT_WHEELHOUSE_DIR=/secure/lsa-agent-wheelhouse \
  ./packaging/build-agent-packages.sh ./dist/agents
```

To prepare that reviewed wheelhouse explicitly:

```bash
./packaging/build-agent-wheelhouse.sh /secure/lsa-agent-wheelhouse x86_64
```

Package installation never enables remediation. The 0.11.1 agent advertises audit,
runtime-integrity, governance-planning, signed-platform-control, and two-phase
platform-key-rotation capabilities. It also advertises validation-only remediation
contract, read-only dry-run, and deterministic recovery-planning support. Validation
uses a separate signed protocol, returns an agent-signed no-change receipt with
checkpoint and reverse rollback requirements, and is not connected to the audit
task table or a privileged executor. After a successful signed preflight, a separate
administrator request can create AES-256-GCM encrypted, root-only local checkpoints
and a durable journal. A separate explicit verification authenticates that accepted
journal, decrypts each blob in memory, and compares its original digest without
returning plaintext. The agent still contains no restore or host-mutation primitive.
It refuses unsigned control responses and any policy without the server's
audit-only enforcement lock.
