#!/bin/sh
set -eu

case "${3:-}" in
  tls.crt|tls.key)
    nginx -t >/dev/null 2>&1 && nginx -s reload
    ;;
esac
