FROM debian:13-slim AS agent-package-builder

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends dpkg-dev python3 python3-pip python3-venv rpm \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY agent ./agent
COPY scanner ./scanner
COPY packaging ./packaging
RUN chmod 0755 packaging/build-agent-packages.sh packaging/build-agent-wheelhouse.sh agent/lsa-agent-enroll \
    && packaging/build-agent-wheelhouse.sh /agent-wheelhouse \
    && LSA_AGENT_WHEELHOUSE_DIR=/agent-wheelhouse packaging/build-agent-packages.sh /agent-dist

FROM python:3.13-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/apps/api \
    LSA_AGENT_PACKAGE_DIR=/app/agent-dist \
    LSA_AGENT_WHEELHOUSE_DIR=/app/agent-wheelhouse

WORKDIR /app

COPY pyproject.toml README.md alembic.ini ./
COPY apps/api ./apps/api
RUN pip install --no-cache-dir .

COPY agent ./agent
COPY scanner ./scanner
COPY --from=agent-package-builder /agent-dist ./agent-dist
COPY --from=agent-package-builder /agent-wheelhouse ./agent-wheelhouse

RUN groupadd --system lsa \
    && useradd --system --gid lsa --home-dir /app --shell /usr/sbin/nologin lsa \
    && chown -R lsa:lsa /app

COPY --chown=lsa:lsa --chmod=755 apps/api/docker-entrypoint.sh /usr/local/bin/lsa-api-entrypoint

USER lsa
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=6 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=2)" || exit 1

ENTRYPOINT ["lsa-api-entrypoint"]
