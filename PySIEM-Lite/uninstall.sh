#!/usr/bin/env bash
# ==============================================================================
# PySIEM-Lite: Uninstaller
# ==============================================================================

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run as root: sudo ./uninstall.sh"
    exit 1
fi

echo "[*] Stopping and disabling systemd service..."
systemctl stop pysiem 2>/dev/null || true
systemctl disable pysiem 2>/dev/null || true
rm -f /etc/systemd/system/pysiem.service
systemctl daemon-reload

echo "[*] Removing global binary and application menu launcher..."
rm -f /usr/local/bin/pysiem
rm -f /usr/share/applications/pysiem.desktop

echo "[*] Removing installation directory /opt/pysiem-lite..."
rm -rf /opt/pysiem-lite

echo "[+] PySIEM-Lite has been completely uninstalled."
