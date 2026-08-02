# LSA unified Linux agent

The agent is an outbound-only client for managed Linux hosts. It enrolls once with a short-lived token, generates an Ed25519 identity locally, polls its group policy, runs only the locally installed LSA audit controls, signs the resulting bundle, and uploads it over HTTPS.

This release is audit-only. Policy values `manual` and `remediate` are retained for future workflows, but the platform returns `enforcement_enabled: false` and the agent refuses to run if that lock is absent. Policy responses never contain commands.

## Install and enroll

Install Python 3.12+, `ansible-core`, `httpx`, and `cryptography`, then place this repository at `/opt/lsa-agent`, copy `config.example.json` to `/etc/lsa-agent/config.json`, and copy `lsa-agent.service` to `/etc/systemd/system/`.

Create a one-time enrollment token for the target group in Settings → Agents, then run:

```bash
sudo /opt/lsa-agent/venv/bin/python /opt/lsa-agent/agent/lsa_agent.py enroll --token 'lsa_enroll_...'
sudo systemctl enable --now lsa-agent
```

The private key, host ingestion token, and local state are stored with mode `0600` under `/var/lib/lsa-agent`. The server only receives the public key. Set `ca_bundle` to the CA that issued the platform certificate on TCP 8443.
