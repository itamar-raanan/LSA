#!/bin/sh
set -eu

case "${3:-}" in
  tls.reload)
    # Let the upload response complete before replacing the certificate used
    # by new management connections.
    sleep 2
    nginx -t >/dev/null 2>&1 && nginx -s reload
    ;;
esac
