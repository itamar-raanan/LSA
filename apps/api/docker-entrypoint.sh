#!/bin/sh
set -eu

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

echo "Applying database migrations..."
alembic -c /app/alembic.ini upgrade head

echo "Starting LSA API..."
exec uvicorn lsa.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers "${LSA_WEB_CONCURRENCY:-2}" \
  --proxy-headers \
  --forwarded-allow-ips="*"
