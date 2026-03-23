#!/usr/bin/env bash
set -euo pipefail

PACKAGE="wormhole-nym"
VERSION="0.1.4"
TARGET="x86_64-unknown-linux-musl"
ARCH="amd64"
DEB="${PACKAGE}_${VERSION}_${ARCH}.deb"
STAGING="$(mktemp -d)"

trap 'rm -rf "$STAGING"' EXIT

echo "Building release binary (musl / static)…"
cargo build --release --target "${TARGET}"

echo "Assembling package…"
install -Dm755 "target/${TARGET}/release/${PACKAGE}" "${STAGING}/usr/bin/${PACKAGE}"

mkdir -p "${STAGING}/DEBIAN"
cat > "${STAGING}/DEBIAN/control" <<EOF
Package: ${PACKAGE}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: wormhole-nym
License: GPL-3.0-only
Description: P2P file transfer over the Nym mixnet
 Sends files directly between two machines through the Nym mixnet.
 No relay server, no rendezvous server. Uses SPAKE2 key exchange and
 ChaCha20-Poly1305 encryption. The sender's Nym address is the only
 rendezvous point needed.
EOF

dpkg-deb --build --root-owner-group "${STAGING}" "${DEB}"
echo "Created ${DEB}"
echo "Install with: sudo dpkg -i ${DEB}"
