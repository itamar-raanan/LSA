# Native Linux agent packages

`build-agent-packages.sh` produces an architecture-independent Debian package and
RPM from the same versioned source used by the universal archive. Both packages
install the scanner and hardened systemd unit, but deliberately leave the service
disabled until an administrator completes one-time enrollment.

Build on a Linux host with `dpkg-deb` and `rpmbuild`:

```bash
./packaging/build-agent-packages.sh ./dist/agents
```

Package installation never enables remediation. The 0.11.0 agent advertises audit,
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
