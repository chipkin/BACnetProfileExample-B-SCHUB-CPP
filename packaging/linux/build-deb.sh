#!/bin/sh
# Builds a Debian/Ubuntu package (.deb) from a built executable and the docs,
# with the same layout and service as install.sh. Used by CI:
#
#   packaging/linux/build-deb.sh <version> <dir with BACnetExampleBSCHUB and docs> <output dir>
#
# Installing the package (sudo apt install ./bacnet-schub-hub_<version>_amd64.deb)
# creates the "bacnethub" user, puts settings in /etc/bacnet-schub/hub.conf,
# makes a lab certificate set if /etc/bacnet-schub/certs is empty, and enables
# and starts the bacnet-schub-hub systemd service.
set -eu

VERSION=$1
SRC=$2
OUT=$3
HERE=$(cd "$(dirname "$0")" && pwd)
PKG=$(mktemp -d)
trap 'rm -rf "$PKG"' EXIT

install -d "$PKG/DEBIAN" "$PKG/opt/bacnet-schub" "$PKG/lib/systemd/system"
install -m 0755 "$SRC/BACnetExampleBSCHUB" "$PKG/opt/bacnet-schub/"
for doc in README.md TUTORIAL.md LICENSE THIRD-PARTY-NOTICES.md SECURITY.md SUPPORT.md PICS.md PICS.pdf \
           production-certificates.md example.conf manual.pdf fact-sheet.pdf; do
    [ -f "$SRC/$doc" ] && install -m 0644 "$SRC/$doc" "$PKG/opt/bacnet-schub/"
done
install -m 0644 "$HERE/bacnet-schub-hub.service" "$PKG/lib/systemd/system/"

cat > "$PKG/DEBIAN/control" <<EOF
Package: bacnet-schub-hub
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Maintainer: Chipkin Automation Systems <support@chipkin.com>
Homepage: https://github.com/chipkin/BACnetProfileExample-B-SCHUB-CPP
Description: BACnet/SC hub (B-SCHUB) built on the CAS BACnet Stack
 A BACnet Secure Connect hub for evaluation and testing (at most 4 BACnet/SC
 connections), with a BACnet/IP port, a status page and certificate
 management over BACnet. Runs as the bacnet-schub-hub systemd service.
EOF

cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    id bacnethub >/dev/null 2>&1 || \
        useradd --system --no-create-home --home-dir /etc/bacnet-schub --shell /usr/sbin/nologin bacnethub
    install -d -m 0750 -o bacnethub -g bacnethub /etc/bacnet-schub /etc/bacnet-schub/certs /var/log/bacnet-schub
    if [ ! -f /etc/bacnet-schub/hub.conf ]; then
        printf '%s\n' "# Settings for the bacnet-schub-hub service; every key is in /opt/bacnet-schub/example.conf." \
            "sc-cert-dir = /etc/bacnet-schub/certs" "log-file = /var/log/bacnet-schub/hub.log" \
            "log-max-size-mb = 10" "log-max-files = 5" > /etc/bacnet-schub/hub.conf
        chown bacnethub:bacnethub /etc/bacnet-schub/hub.conf
        chmod 0600 /etc/bacnet-schub/hub.conf
    fi
    if [ -z "$(ls -A /etc/bacnet-schub/certs 2>/dev/null)" ]; then
        su -s /bin/sh bacnethub -c "/opt/bacnet-schub/BACnetExampleBSCHUB --sc-cert-dir /etc/bacnet-schub/certs --generate-certs" || true
    fi
    systemctl daemon-reload || true
    systemctl enable --now bacnet-schub-hub || true
fi
EOF

cat > "$PKG/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
systemctl disable --now bacnet-schub-hub 2>/dev/null || true
EOF

cat > "$PKG/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
    rm -rf /etc/bacnet-schub /var/log/bacnet-schub
    userdel bacnethub 2>/dev/null || true
fi
systemctl daemon-reload 2>/dev/null || true
EOF

chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm" "$PKG/DEBIAN/postrm"
mkdir -p "$OUT"
# xz, not dpkg-deb's newer zstd default, so older Debian/Ubuntu releases can install it too.
dpkg-deb --root-owner-group -Zxz --build "$PKG" "$OUT/bacnet-schub-hub_${VERSION}_amd64.deb"
