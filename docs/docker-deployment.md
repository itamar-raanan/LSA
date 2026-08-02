# Docker deployment

LSA runs as four containers:

- `web` serves the compiled React console and reverse-proxies API traffic.
- `api` applies database migrations and runs the FastAPI application as a non-root user.
- `postgres` stores all platform state in the persistent `lsa-postgres` volume.
- `minio` stores original evidence bundles in the persistent `lsa-evidence` volume.

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

The default bind address is `127.0.0.1:8080`. This is deliberate: it prevents accidental internet exposure. Open `http://localhost:8080`, then sign in with `LSA_BOOTSTRAP_EMAIL` and `LSA_BOOTSTRAP_PASSWORD`.

## Internet exposure and TLS

Keep `LSA_HTTP_BIND=127.0.0.1` and place a TLS reverse proxy or load balancer on the host in front of port 8080. Forward the original `Host`, `X-Forwarded-For`, and `X-Forwarded-Proto` headers. Do not expose the PostgreSQL or API containers directly.

If the host firewall and an external TLS proxy already protect the service, `LSA_HTTP_BIND=0.0.0.0` permits remote connections. HTTPS is required for production ingestion tokens and administrator sessions.

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

If startup fails, inspect `make logs`. Common causes are unchanged placeholder secrets, an invalid database password in the connection URL, or port 8080 already being in use.
