#!/usr/bin/env bash
# ==============================================================================
# PySIEM-Lite: Kali Linux Native Tool Installer
# Installs PySIEM-Lite to /opt/pysiem-lite, creates global CLI symlink 'pysiem',
# installs systemd background service, and configures Kali application menu entry.
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
cat << "EOF"
  ____        ____ ___ _____ __  __     _     _ _       
 |  _ \ _   _/ ___|_ _| ____|  \/  |   | |   (_) |_ ___ 
 | |_) | | | \___ \| ||  _| | |\/| |---| |   | | __/ _ \
 |  __/| |_| |___) | || |___| |  | |---| |___| | ||  __/
 |_|    \__, |____/___|_____|_|  |_|   |_____|_|\__\___|
        |___/        Kali Linux Native Installer        
EOF
echo -e "${NC}"

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] This installer must be executed as root.${NC}"
    echo -e "${YELLOW}Please run:${NC} sudo ./install.sh"
    exit 1
fi

INSTALL_DIR="/opt/pysiem-lite"
BIN_LINK="/usr/local/bin/pysiem"
SERVICE_FILE="/etc/systemd/system/pysiem.service"
DESKTOP_ENTRY="/usr/share/applications/pysiem.desktop"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${YELLOW}[1/6] Installing Linux System Dependencies & Python Packages...${NC}"
apt-get update -y
apt-get install -y python3 python3-pip iptables curl rsyslog apache2-utils

# Install Python requirements
pip3 install -r "$SOURCE_DIR/requirements.txt" --break-system-packages 2>/dev/null || pip3 install -r "$SOURCE_DIR/requirements.txt"

echo -e "${YELLOW}[2/6] Deploying PySIEM-Lite to ${INSTALL_DIR}...${NC}"
mkdir -p "$INSTALL_DIR"
cp -r "$SOURCE_DIR"/* "$INSTALL_DIR"/
chmod +x "$INSTALL_DIR/main.py" "$INSTALL_DIR/simulate_attacks.sh" "$INSTALL_DIR/app.py"

echo -e "${YELLOW}[3/6] Creating Global Command CLI '${BIN_LINK}'...${NC}"
cat << 'EOF' > "$BIN_LINK"
#!/usr/bin/env bash
# PySIEM-Lite Global CLI Wrapper
cd /opt/pysiem-lite
exec python3 /opt/pysiem-lite/main.py "$@"
EOF
chmod +x "$BIN_LINK"

echo -e "${YELLOW}[4/6] Creating systemd Background Service (${SERVICE_FILE})...${NC}"
cat << EOF > "$SERVICE_FILE"
[Unit]
Description=PySIEM-Lite Autonomous Host-Based SIEM & Active Defense Engine
After=network.target rsyslog.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/pysiem-lite
ExecStart=/usr/bin/python3 /opt/pysiem-lite/main.py
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

echo -e "${YELLOW}[5/6] Creating Kali Linux Desktop Application Menu Launcher...${NC}"
cat << EOF > "$DESKTOP_ENTRY"
[Desktop Entry]
Name=PySIEM-Lite Console
Comment=Lightweight Host SIEM & Active Defense
Exec=x-terminal-emulator -e "pysiem"
Icon=security-high
Terminal=true
Type=Application
Categories=08-exploitation-tools;11-defensive-tools;Security;
EOF
chmod +x "$DESKTOP_ENTRY"

echo -e "${YELLOW}[6/6] Verifying System Log Permissions & Setup...${NC}"
# Ensure standard log files exist
touch /var/log/auth.log
chmod 640 /var/log/auth.log

echo -e "\n${GREEN}${BOLD}===================================================================${NC}"
echo -e "${GREEN}${BOLD}  PySIEM-Lite Successfully Installed like a Native Kali Tool!      ${NC}"
echo -e "${GREEN}${BOLD}===================================================================${NC}"
echo -e "${CYAN}You can now manage and run PySIEM-Lite from anywhere:${NC}\n"
echo -e "  ${BOLD}1. Run in Foreground (Any terminal):${NC}"
echo -e "     ${YELLOW}sudo pysiem${NC}               (Real mode with live iptables)"
echo -e "     ${YELLOW}pysiem --mock${NC}             (Safe demo mode without touching logs)\n"
echo -e "  ${BOLD}2. Run as a Background Linux Service (systemd):${NC}"
echo -e "     ${YELLOW}sudo systemctl start pysiem${NC}    (Start SIEM in background)"
echo -e "     ${YELLOW}sudo systemctl enable pysiem${NC}   (Auto-start on system boot)"
echo -e "     ${YELLOW}sudo systemctl status pysiem${NC}   (View status & logs)"
echo -e "     ${YELLOW}sudo systemctl stop pysiem${NC}     (Stop service)\n"
echo -e "  ${BOLD}3. Web Console Access:${NC}"
echo -e "     Open your browser to: ${GREEN}http://localhost:5000${NC}\n"
echo -e "  ${BOLD}4. Launch Attack Verification Test:${NC}"
echo -e "     ${YELLOW}/opt/pysiem-lite/simulate_attacks.sh${NC}\n"
