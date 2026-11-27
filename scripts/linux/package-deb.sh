#!/usr/bin/env bash
set -euo pipefail

# Build Debian package (.deb) for proxy on Linux (amd64 or arm64).
# Usage: package-deb.sh <version> <arch> <binary-path> <geo-dir> <output-dir>
if [[ $# -ne 5 ]]; then
  echo "usage: $0 <version> <arch> <binary-path> <geo-dir> <output-dir>" >&2
  exit 2
fi

RAW_VERSION="$1"
ARCH="$2"
BIN_PATH="$3"
GEO_DIR="$4"
OUT_DIR="$5"

DEB_VERSION="${RAW_VERSION#v}"
PKG_NAME="proxy"
STAGE_DIR="$(mktemp -d)"
trap 'rm -rf "$STAGE_DIR"' EXIT

mkdir -p "$STAGE_DIR/DEBIAN"
mkdir -p "$STAGE_DIR/usr/bin"
mkdir -p "$STAGE_DIR/etc/proxy/data"

install -m 0755 "$BIN_PATH" "$STAGE_DIR/usr/bin/proxy"
install -m 0644 "$GEO_DIR/geoip.dat" "$STAGE_DIR/etc/proxy/data/geoip.dat"
install -m 0644 "$GEO_DIR/geosite.dat" "$STAGE_DIR/etc/proxy/data/geosite.dat"

cat > "$STAGE_DIR/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${DEB_VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Proxy Maintainers <noreply@github.com>
Depends: iproute2, nftables
Description: Cross-platform transparent proxy with TPROXY and built-in DNS
 Proxy is a lightweight transparent proxy and network forwarder for Linux
 and Windows with dual-stack TCP/UDP capture, routing, and DNS engine.
EOF

cat > "$STAGE_DIR/DEBIAN/postinst" <<'EOF'
#!/usr/bin/env bash
set -e
chmod 0755 /usr/bin/proxy
if [ -d /etc/proxy/data ]; then
  chmod 0755 /etc/proxy /etc/proxy/data || true
  chmod 0644 /etc/proxy/data/geoip.dat /etc/proxy/data/geosite.dat 2>/dev/null || true
fi
if [ "$1" = "configure" ] && [ -d /run/systemd/system ]; then
  if systemctl is-active --quiet proxyd.service 2>/dev/null; then
    systemctl restart proxyd.service || true
  fi
fi
EOF
chmod 0755 "$STAGE_DIR/DEBIAN/postinst"

cat > "$STAGE_DIR/DEBIAN/prerm" <<'EOF'
#!/usr/bin/env bash
set -e
if [ "$1" = "remove" ] && [ -d /run/systemd/system ]; then
  if systemctl is-active --quiet proxyd.service 2>/dev/null; then
    systemctl stop proxyd.service || true
  fi
fi
EOF
chmod 0755 "$STAGE_DIR/DEBIAN/prerm"

mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/${PKG_NAME}_${DEB_VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE_DIR" "$OUT_FILE"
echo "Built $OUT_FILE"
