#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
OUTPUT_DIR=${1:-"$SOURCE_ROOT/dist/agents"}
VERSION=$(tr -d '[:space:]' < "$SOURCE_ROOT/agent/VERSION")
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
export SOURCE_DATE_EPOCH TZ=UTC

[ -n "$VERSION" ] || { echo "agent/VERSION is empty" >&2; exit 1; }
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 1; }
command -v rpmbuild >/dev/null 2>&1 || { echo "rpmbuild is required" >&2; exit 1; }

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM
install -d -m 0755 "$OUTPUT_DIR"

DEB_ROOT="$WORK_DIR/deb"
install -d -m 0755 "$DEB_ROOT/DEBIAN" "$DEB_ROOT/opt/lsa-agent" "$DEB_ROOT/usr/sbin" "$DEB_ROOT/usr/lib/systemd/system"
tar -C "$SOURCE_ROOT" \
  --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo' --exclude='*/tests' \
  -cf - agent scanner | tar -C "$DEB_ROOT/opt/lsa-agent" -xf -
install -m 0644 "$SOURCE_ROOT/agent/requirements.txt" "$DEB_ROOT/opt/lsa-agent/requirements.txt"
python3 "$SOURCE_ROOT/agent/integrity.py" build --root "$DEB_ROOT/opt/lsa-agent" --manifest "$DEB_ROOT/opt/lsa-agent/integrity-manifest.json" >/dev/null
install -m 0755 "$SOURCE_ROOT/agent/lsa-agent-enroll" "$DEB_ROOT/usr/sbin/lsa-agent-enroll"
install -m 0644 "$SOURCE_ROOT/agent/lsa-agent.service" "$DEB_ROOT/usr/lib/systemd/system/lsa-agent.service"
sed "s/@VERSION@/$VERSION/g" "$SCRIPT_DIR/debian/control" > "$DEB_ROOT/DEBIAN/control"
for script in postinst prerm postrm; do
  install -m 0755 "$SCRIPT_DIR/debian/$script" "$DEB_ROOT/DEBIAN/$script"
done
find "$DEB_ROOT" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
dpkg-deb --root-owner-group --build "$DEB_ROOT" "$OUTPUT_DIR/lsa-agent_${VERSION}_all.deb"

RPM_TOP="$WORK_DIR/rpm"
install -d -m 0755 "$RPM_TOP/BUILD" "$RPM_TOP/BUILDROOT" "$RPM_TOP/RPMS" "$RPM_TOP/SOURCES" "$RPM_TOP/SPECS" "$RPM_TOP/SRPMS"
rpmbuild -bb "$SCRIPT_DIR/rpm/lsa-agent.spec" \
  --define "_topdir $RPM_TOP" \
  --define "lsa_source_root $SOURCE_ROOT" \
  --define "lsa_version $VERSION" \
  --define "build_mtime_policy clamp_to_source_date_epoch" \
  --define "use_source_date_epoch_as_buildtime 1"
RPM_PATH=$(find "$RPM_TOP/RPMS" -type f -name 'lsa-agent-*.noarch.rpm' -print -quit)
[ -n "$RPM_PATH" ] || { echo "rpmbuild did not create an agent package" >&2; exit 1; }
install -m 0644 "$RPM_PATH" "$OUTPUT_DIR/lsa-agent-${VERSION}-1.noarch.rpm"

(cd "$OUTPUT_DIR" && sha256sum "lsa-agent_${VERSION}_all.deb" "lsa-agent-${VERSION}-1.noarch.rpm" > SHA256SUMS)
echo "Built native LSA agent packages in $OUTPUT_DIR"
