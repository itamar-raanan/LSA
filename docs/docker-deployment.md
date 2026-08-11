# Docker deployment

LSA runs as five long-lived containers plus a one-shot TLS-volume initializer:

- `web` serves the compiled React console and reverse-proxies API traffic.
- `api` applies database migrations and runs the FastAPI application as a non-root user.
- `postgres` stores all platform state in the persistent `lsa-postgres` volume.
- `minio` stores original evidence bundles in the persistent `lsa-evidence` volume.
- `vulnerability-sync` refreshes OSV and CISA KEV intelligence over its isolated egress network.

The API creates an object-lock-enabled evidence bucket and verifies every object's SHA-256 digest before download. AWS S3 uses SSE-S3 by default; the bundled MinIO service relies on protected volume storage unless KMS-backed SSE is configured. Redis remains absent until the application has a real consumer for it.

## First start

Copy the deployment environment template and replace every placeholder value:

```bash
cp deploy/.env.example deploy/.env
chmod 600 deploy/.env
```

Generate secrets with a password manager or a cryptographically secure generator. Keep the PostgreSQL password URL-safe because Compose embeds it in `LSA_DATABASE_URL`.

Replace both S3 credential placeholders as well. MinIO is private to the Docker network and has no published console or API port.

Validate and start the stack:

```bash
make docker-config
make up
make ps
```

The only published service is the TLS gateway. Management is available on `127.0.0.1:8443`, while the restricted agent data plane is available on `127.0.0.1:8444`; no plaintext HTTP port is exposed. Open `https://localhost:8443`, then sign in with `LSA_BOOTSTRAP_EMAIL` and `LSA_BOOTSTRAP_PASSWORD`. Configure agents with `LSA_AGENT_PUBLIC_URL`, which must resolve to the agent listener from managed hosts.

## TLS certificates and internet exposure

The first boot generates a 30-day self-signed certificate for `localhost`, so the platform remains HTTPS-only during initial setup. The expected browser warning disappears after an administrator uploads the organization certificate and matching private key under **Settings → TLS certificates**. The upload accepts `.crt`/`.pem` certificates and `.key`/`.pem` private keys in PEM or DER encoding; private keys must be unencrypted. The leaf certificate must be first when a PEM chain contains multiple certificates.

The private key is encrypted in PostgreSQL, materialized into an internal restricted volume, and reloaded atomically by the gateway. Set `LSA_TLS_HOST` to the externally visible management DNS name before configuring OpenID Connect because it forms the callback URL. Set `LSA_AGENT_PUBLIC_URL` to the externally visible agent origin. Change `LSA_TLS_BIND` or `LSA_AGENT_TLS_BIND` to `0.0.0.0` only when the host firewall permits the intended clients. Do not expose PostgreSQL, MinIO, or the API container directly.

Managed agent release 0.4.4 keeps HTTPS encryption but does not validate the agent gateway certificate or hostname. Its console-generated install command pins a tenant-specific platform public key, and enrollment credentials are stored only after a signed identity proof is verified. Management browsers and identity-provider callbacks continue to use normal TLS validation on port 8443.

## Signed evidence policy

Set this after every production scanner has a registered signing key:

```dotenv
LSA_REQUIRE_SIGNED_BUNDLES=true
```

The setting rejects unsigned ZIP bundles and disables raw JSON report ingestion.

## Backups

Create a logical database backup without stopping the platform:

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml \
  exec -T postgres pg_dump -U lsa -d lsa -Fc > lsa-backup.dump
```

If the database or user names differ, substitute the values from `deploy/.env`. Store backups encrypted and test restores regularly.

The database backup contains evidence metadata, not the original ZIP objects. Back up or replicate the `lsa-evidence` MinIO volume separately. A complete restore requires a matching PostgreSQL backup and evidence-volume snapshot from the same backup window.

Restore into an empty database:

```bash
docker compose --env-file deploy/.env -f deploy/docker-compose.yml \
  exec -T postgres pg_restore -U lsa -d lsa --clean --if-exists < lsa-backup.dump
```

## Upgrades

Back up PostgreSQL, fetch the new source revision, then rebuild:

```bash
make up
```

The API container applies pending Alembic migrations before accepting traffic. Review release notes before upgrades that change the PostgreSQL major version; those require a database migration rather than a simple image replacement.

When upgrading an existing Docker deployment to the evidence-vault release, add `LSA_S3_ACCESS_KEY`, `LSA_S3_SECRET_KEY`, `LSA_S3_BUCKET`, `LSA_S3_REGION`, `LSA_S3_SERVER_SIDE_ENCRYPTION`, and `LSA_ARTIFACT_RETENTION_DAYS` to `deploy/.env` before running `make up`. Keep `LSA_S3_SERVER_SIDE_ENCRYPTION=none` for the bundled MinIO service unless MinIO KMS has been configured; AWS S3 deployments may use `AES256`.

## Operations

```bash
make ps
make logs
make down
```

`make down` preserves the database and evidence volumes. Avoid `docker compose down --volumes` unless permanent deletion of all platform data is explicitly intended.

The external health endpoints are:

- `/healthz` checks the web gateway.
- `/health` checks the API process.
- `/ready` checks the API and its live PostgreSQL connection. Compose uses this endpoint for API health gating.
- `https://localhost:8444/agent-healthz` checks the restricted agent listener. Other non-agent paths on port 8444 return `404`.

If startup fails, inspect `make logs`. Common causes are unchanged placeholder secrets, an invalid database password in the connection URL, or management port 8443 or agent port 8444 already being in use.
