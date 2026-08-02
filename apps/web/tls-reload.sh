#!/bin/sh
set -eu

/sbin/inotifyd /usr/local/bin/lsa-tls-reload /tls:wy &
