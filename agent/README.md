# LSA unified Linux agent

The agent is an outbound-only client for managed Linux hosts. It enrolls once with a short-lived token, generates an Ed25519 identity locally, polls its group policy and audit-task queue, runs only the locally installed LSA audit controls, inventories installed packages and systemd services, signs the resulting bundle, and uploads it over HTTPS.

This release is audit-only. Policy values `manual` and `remediate` are retained for future workflows, but the platform returns `enforcement_enabled: false` and the agent refuses to run if that lock is absent. Policy responses never contain commands.

## Install and enroll

From **Agents** in the console, choose **Install agent** and download the Debian/Ubuntu package, RHEL-family package, or universal Linux archive. Verify its displayed SHA-256 checksum after transferring it to the host. The host needs Python 3.11+, systemd, and network access to install the constrained Python dependencies.

For Debian 13 or Ubuntu 24.04+:

```bash
sudo apt install ./lsa-agent_0.4.3_all.deb
sudo lsa-agent-enroll --platform-url 'https://lsa.example.com:8444' --token 'lsa_enroll_...'
```

For RHEL, Rocky Linux, or AlmaLinux 9+:

```bash
sudo dnf install ./lsa-agent-0.4.3-1.noarch.rpm
sudo lsa-agent-enroll --platform-url 'https://lsa.example.com:8444' --token 'lsa_enroll_...'
```

The native package only stages the runtime. It does not start the service before successful enrollment.

For the universal archive:

Create a one-time enrollment token for the target group, then run:

```bash
tar -xzf lsa-agent-0.4.3-linux-universal.tar.gz
cd lsa-agent-0.4.3
sudo ./install.sh --platform-url 'https://lsa.example.com:8444' --token 'lsa_enroll_...'
```

The installer places the runtime in `/opt/lsa-agent`, configuration in `/etc/lsa-agent`, state in `/var/lib/lsa-agent`, and the service unit in `/usr/lib/systemd/system`.

The private key, host ingestion token, and local state are stored with mode `0600` under `/var/lib/lsa-agent`. The server only receives the public key. The agent uses encrypted HTTPS on the dedicated gateway, TCP 8444 by default, but release 0.4.3 does not validate the gateway certificate or hostname. The signed agent protocol still authenticates enrolled agents to the platform, but a network attacker could impersonate the platform during enrollment or agent polling. The agent does not use the management console port.

The agent advertises `signed-change-set-planning-v1` so the management plane can verify that it supplies the identity, freshness, policy, and integrity evidence needed for signed governance planning. This capability does not enable configuration writes or change-set execution; task consumption remains restricted to `audit`.

The daemon polls every 60 seconds by default while scheduled audits continue to follow the group policy interval and jitter. **Run audit now** queues only the built-in `audit` task. The signed protocol cannot carry a command, script, or remediation payload, and the agent reports completion or a bounded failure message back to the console.

Release 0.4 validates `integrity-manifest.json` before every server exchange and scan. The manifest covers the installed agent runtime, scanner, control catalog, and dependency declaration. Any missing, symlinked, or modified managed file stops the cycle. The agent also persists the highest accepted policy version and rejects a lower version; a legitimate server-side restore is published as a new higher version.

Application inventory uses the same read-only scanner module as offline mode. Debian and Ubuntu packages are read through `dpkg-query`, RHEL-family packages through `rpm`, and service state through systemd. The inventory does not include process arguments, environment variables, open files, or application configuration.
