#!/bin/sh
# Removes what install.sh installed. Settings and certificates in
# /etc/bacnet-schub and the logs in /var/log/bacnet-schub are kept unless you
# pass --purge.
#
#   sudo ./uninstall.sh [--purge]
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root: sudo $0" >&2
    exit 1
fi

systemctl disable --now bacnet-schub-hub 2>/dev/null || true
rm -f /etc/systemd/system/bacnet-schub-hub.service
systemctl daemon-reload
rm -rf /opt/bacnet-schub

if [ "${1:-}" = "--purge" ]; then
    rm -rf /etc/bacnet-schub /var/log/bacnet-schub
    userdel bacnethub 2>/dev/null || true
    echo "Removed, including settings, certificates and logs."
else
    echo "Removed. Settings and certificates are still in /etc/bacnet-schub, logs in /var/log/bacnet-schub"
    echo "(run with --purge to remove them too)."
fi
