FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/apps/api

WORKDIR /app

COPY pyproject.toml README.md alembic.ini ./
COPY apps/api ./apps/api
RUN pip install --no-cache-dir .

RUN groupadd --system lsa \
    && useradd --system --gid lsa --home-dir /app --shell /usr/sbin/nologin lsa \
    && chown -R lsa:lsa /app

COPY --chown=lsa:lsa --chmod=755 apps/api/docker-entrypoint.sh /usr/local/bin/lsa-api-entrypoint

USER lsa
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=6 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=2)" || exit 1

ENTRYPOINT ["lsa-api-entrypoint"]
