# Native Linux agent packages

`build-agent-packages.sh` produces an architecture-independent Debian package and
RPM from the same versioned source used by the universal archive. Both packages
install the scanner and hardened systemd unit, but deliberately leave the service
disabled until an administrator completes one-time enrollment.

Build on a Linux host with `dpkg-deb` and `rpmbuild`:

```bash
./packaging/build-agent-packages.sh ./dist/agents
```

Package installation never enables remediation. The 0.4.3 agent advertises only
the `audit` capability and refuses any policy without the server's audit-only
enforcement lock.
