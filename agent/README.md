# LSA unified Linux agent

The agent is an outbound-only client for managed Linux hosts. It enrolls once with a short-lived token, generates an Ed25519 identity locally, polls its group policy, runs only the locally installed LSA audit controls, signs the resulting bundle, and uploads it over HTTPS.

This release is audit-only. Policy values `manual` and `remediate` are retained for future workflows, but the platform returns `enforcement_enabled: false` and the agent refuses to run if that lock is absent. Policy responses never contain commands.

## Install and enroll

From **Agents** in the console, choose **Install agent** and download the universal Linux package. Verify its displayed SHA-256 checksum after transferring it to the host. The host needs Python 3.11+, systemd, and network access to install the pinned Python dependencies.

Create a one-time enrollment token for the target group, then run:

```bash
tar -xzf lsa-agent-0.1.0-linux-universal.tar.gz
cd lsa-agent-0.1.0
sudo ./install.sh --platform-url 'https://lsa.example.com:8443' --token 'lsa_enroll_...'
```

For a platform certificate issued by a private CA, copy the CA certificate to the host and pass `--ca-bundle /path/to/ca.pem`. The installer places the runtime in `/opt/lsa-agent`, configuration in `/etc/lsa-agent`, state in `/var/lib/lsa-agent`, and the service unit in `/etc/systemd/system`.

The private key, host ingestion token, and local state are stored with mode `0600` under `/var/lib/lsa-agent`. The server only receives the public key. Set `ca_bundle` to the CA that issued the platform certificate on TCP 8443.
