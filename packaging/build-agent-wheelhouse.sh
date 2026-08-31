#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
OUTPUT_DIR=${1:?Usage: build-agent-wheelhouse.sh OUTPUT_DIR [x86_64|arm64]}
REQUESTED_ARCH=${2:-$(uname -m)}

case "$REQUESTED_ARCH" in
  x86_64|amd64)
    PLATFORM_ARCH=x86_64
    ;;
  aarch64|arm64)
    PLATFORM_ARCH=aarch64
    ;;
  *)
    echo "Unsupported agent wheelhouse architecture: $REQUESTED_ARCH" >&2
    exit 1
    ;;
esac

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
install -d -m 0755 "$OUTPUT_DIR"

for python_abi in 311 312 313; do
  python3 -m pip download \
    --disable-pip-version-check \
    --only-binary=:all: \
    --implementation cp \
    --python-version "$python_abi" \
    --abi "cp$python_abi" \
    --platform "manylinux_2_34_$PLATFORM_ARCH" \
    --platform "manylinux_2_28_$PLATFORM_ARCH" \
    --platform "manylinux2014_$PLATFORM_ARCH" \
    --dest "$OUTPUT_DIR" \
    -r "$SOURCE_ROOT/agent/requirements.txt"
done

WHEEL_FOUND=false
for wheel in "$OUTPUT_DIR"/*.whl; do
  if [ -f "$wheel" ]; then WHEEL_FOUND=true; break; fi
done
[ "$WHEEL_FOUND" = true ] || { echo "Agent wheelhouse build produced no wheels" >&2; exit 1; }

echo "Built offline agent wheelhouse for $REQUESTED_ARCH and Python 3.11-3.13 in $OUTPUT_DIR"
