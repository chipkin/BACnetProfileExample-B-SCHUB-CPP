#!/bin/sh
# Installs the BACnet/SC hub from the Linux release archive and sets it up to
# run under systemd. Run from the unpacked archive:
#
#   sudo ./install.sh
#
# What it does (and where things go):
#   /opt/bacnet-schub/            the program and its documentation
#   /etc/bacnet-schub/hub.conf    settings (kept if it already exists)
#   /etc/bacnet-schub/certs/      certificates (a lab set is made if empty)
#   /var/log/bacnet-schub/        the hub's rotating log file
#   bacnet-schub-hub.service      systemd unit, enabled and started
# and creates the system user "bacnethub" the service runs as.
#
# uninstall.sh reverses it (keeping /etc/bacnet-schub unless asked).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
PREFIX=/opt/bacnet-schub
ETC=/etc/bacnet-schub
LOG=/var/log/bacnet-schub
UNIT=/etc/systemd/system/bacnet-schub-hub.service

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root: sudo $0" >&2
    exit 1
fi

if ! id bacnethub >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir "$ETC" --shell /usr/sbin/nologin bacnethub
fi

install -d -m 0755 "$PREFIX"
install -m 0755 "$HERE/BACnetExampleBSCHUB" "$PREFIX/"
for doc in README.md TUTORIAL.md LICENSE THIRD-PARTY-NOTICES.md SECURITY.md SUPPORT.md PICS.md PICS.pdf \
           production-certificates.md example.conf manual.pdf fact-sheet.pdf; do
    [ -f "$HERE/$doc" ] && install -m 0644 "$HERE/$doc" "$PREFIX/"
done

install -d -m 0750 -o bacnethub -g bacnethub "$ETC" "$ETC/certs" "$LOG"
if [ ! -f "$ETC/hub.conf" ]; then
    # example.conf with the paths a service needs, and the log file on.
    {
        echo "# /etc/bacnet-schub/hub.conf - settings for the bacnet-schub-hub service."
        echo "# Every key is listed, commented out, in $PREFIX/example.conf."
        echo "sc-cert-dir = $ETC/certs"
        echo "log-file = $LOG/hub.log"
        echo "log-max-size-mb = 10"
        echo "log-max-files = 5"
        echo "# device-name = <a name unique on your BACnet network>"
        echo "# http-upload-token = <a long random secret, to allow POST /certs/<slot>>"
    } > "$ETC/hub.conf"
    chown bacnethub:bacnethub "$ETC/hub.conf"
    chmod 0600 "$ETC/hub.conf"
fi

if [ -z "$(ls -A "$ETC/certs" 2>/dev/null)" ]; then
    echo "No certificates in $ETC/certs - making a LAB set (replace it for production;"
    echo "see $PREFIX/production-certificates.md)."
    su -s /bin/sh bacnethub -c "$PREFIX/BACnetExampleBSCHUB --sc-cert-dir $ETC/certs --generate-certs"
fi

install -m 0644 "$HERE/bacnet-schub-hub.service" "$UNIT"
systemctl daemon-reload
systemctl enable --now bacnet-schub-hub

echo
echo "Installed. The hub is running as the bacnet-schub-hub service:"
echo "  systemctl status bacnet-schub-hub"
echo "  journalctl -u bacnet-schub-hub -f        (or $LOG/hub.log)"
echo "Settings: $ETC/hub.conf    Certificates: $ETC/certs"
echo "Open UDP 47808 and TCP 47819 in the firewall for BACnet/IP and BACnet/SC."
