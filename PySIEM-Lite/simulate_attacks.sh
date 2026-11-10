#!/usr/bin/env bash
# ==============================================================================
# PySIEM-Lite: Live Attack Simulation & Demonstration Tool
# Generates realistic synthetic threat logs or performs active local attacks
# to trigger RULE-01 (SSH Brute Force), RULE-02 (Web Recon), and RULE-03 (Sudo Abuse).
# ==============================================================================

# Text Color Definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Script Directory and Target Log Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCK_DIR="$SCRIPT_DIR/mock_logs"
mkdir -p "$MOCK_DIR"

AUTH_LOG_REAL="/var/log/auth.log"
APACHE_LOG_REAL="/var/log/apache2/access.log"
AUTH_LOG_MOCK="$MOCK_DIR/auth.log"
APACHE_LOG_MOCK="$MOCK_DIR/access.log"

# Target log selection logic:
# If user is root and real log files exist, ask or default to active system logs;
# otherwise default safely to mock logs.
TARGET_AUTH="$AUTH_LOG_MOCK"
TARGET_APACHE="$APACHE_LOG_MOCK"

if [ -w "$AUTH_LOG_REAL" ]; then
    TARGET_AUTH="$AUTH_LOG_REAL"
fi
if [ -w "$APACHE_LOG_REAL" ]; then
    TARGET_APACHE="$APACHE_LOG_REAL"
fi

touch "$TARGET_AUTH" "$TARGET_APACHE"

# Attacker Test IPs (Non-whitelisted public-range or virtual attacker IPs)
SSH_ATTACKER_IP="198.51.100.45"
WEB_ATTACKER_IP="203.0.113.89"
SUDO_TARGET_USER="infiltrator_bob"

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
  ____        ____ ___ _____ __  __     _     _ _       
 |  _ \ _   _/ ___|_ _| ____|  \/  |   | |   (_) |_ ___ 
 | |_) | | | \___ \| ||  _| | |\/| |---| |   | | __/ _ \
 |  __/| |_| |___) | || |___| |  | |---| |___| | ||  __/
 |_|    \__, |____/___|_____|_|  |_|   |_____|_|\__\___|
        |___/        Lightweight SIEM for Kali Linux    
EOF
    echo -e "${NC}"
    echo -e "${BLUE}===================================================================${NC}"
    echo -e "${YELLOW}  Active Log Targets for Injection:${NC}"
    echo -e "   Auth Log:   ${GREEN}${TARGET_AUTH}${NC}"
    echo -e "   Access Log: ${GREEN}${TARGET_APACHE}${NC}"
    echo -e "${BLUE}===================================================================${NC}"
    echo ""
}

# ------------------------------------------------------------------------------
# Attack Scenario 1: SSH Brute Force (RULE-01)
# Threshold: >= 5 failed logins within 60s
# ------------------------------------------------------------------------------
simulate_ssh_brute_force() {
    echo -e "\n${RED}[!] Triggering RULE-01: SSH Brute Force Simulation...${NC}"
    echo -e "${CYAN}[*] Injecting 7 failed SSH authentication attempts from ${BOLD}${SSH_ATTACKER_IP}${NC}..."

    USERS=("root" "admin" "ubuntu" "test" "oracle" "postgres" "root")
    PORTS=(41234 41235 41236 41237 41238 41239 41240)

    for i in "${!USERS[@]}"; do
        USER="${USERS[$i]}"
        PORT="${PORTS[$i]}"
        TIMESTAMP=$(date "+%b %e %H:%M:%S")
        LOG_LINE="$TIMESTAMP kali sshd[$$]: Failed password for $USER from $SSH_ATTACKER_IP port $PORT ssh2"
        echo "$LOG_LINE" >> "$TARGET_AUTH"
        echo -e "  ${YELLOW}--> [AUTH.LOG]${NC} $LOG_LINE"
        sleep 0.5
    done

    echo -e "${GREEN}[+] SSH Brute Force sequence completed!${NC}"
    echo -e "${MAGENTA}[*] Check PySIEM Web Dashboard: Alert RULE-01 raised & Attacker IP ${SSH_ATTACKER_IP} auto-dropped via iptables!${NC}\n"
}

# ------------------------------------------------------------------------------
# Attack Scenario 2: Web Reconnaissance & Directory Fuzzing (RULE-02)
# Threshold: >= 10 HTTP 404/403 responses within 15s
# ------------------------------------------------------------------------------
simulate_web_recon() {
    echo -e "\n${RED}[!] Triggering RULE-02: Web Application Reconnaissance Simulation...${NC}"
    echo -e "${CYAN}[*] Injecting 14 rapid HTTP 404/403 scanning requests from ${BOLD}${WEB_ATTACKER_IP}${NC}..."

    PATHS=(
        "/admin"
        "/wp-login.php"
        "/.env"
        "/.git/config"
        "/phpmyadmin/index.php"
        "/config.json"
        "/api/v1/dump"
        "/backup.sql"
        "/shell.php"
        "/cgi-bin/test-cgi"
        "/server-status"
        "/.aws/credentials"
        "/etc/passwd"
        "/administrator"
    )

    for PATH_PROBE in "${PATHS[@]}"; do
        TIMESTAMP=$(date "+%d/%b/%Y:%H:%M:%S +0000")
        STATUS="404"
        if [[ "$PATH_PROBE" == *"env"* || "$PATH_PROBE" == *"admin"* ]]; then
            STATUS="403"
        fi
        
        LOG_LINE="$WEB_ATTACKER_IP - - [$TIMESTAMP] \"GET $PATH_PROBE HTTP/1.1\" $STATUS 342 \"-\" \"Gobuster/v3.5.0\""
        echo "$LOG_LINE" >> "$TARGET_APACHE"
        echo -e "  ${YELLOW}--> [ACCESS.LOG]${NC} HTTP $STATUS - $PATH_PROBE"
        sleep 0.2
    done

    echo -e "${GREEN}[+] Web Reconnaissance sequence completed!${NC}"
    echo -e "${MAGENTA}[*] Check PySIEM Web Dashboard: Alert RULE-02 raised & Attacker IP ${WEB_ATTACKER_IP} auto-dropped via iptables!${NC}\n"
}

# ------------------------------------------------------------------------------
# Attack Scenario 3: Suspicious Sudo Privilege Escalation (RULE-03)
# Threshold: >= 3 sudo failures within 60s
# ------------------------------------------------------------------------------
simulate_sudo_abuse() {
    echo -e "\n${RED}[!] Triggering RULE-03: Suspicious Sudo Privilege Escalation...${NC}"
    echo -e "${CYAN}[*] Injecting 4 unauthorized sudo failure attempts for user ${BOLD}${SUDO_TARGET_USER}${NC}..."

    for i in {1..4}; do
        TIMESTAMP=$(date "+%b %e %H:%M:%S")
        if [ $i -eq 1 ]; then
            LOG_LINE="$TIMESTAMP kali sudo:   $SUDO_TARGET_USER : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/$SUDO_TARGET_USER ; USER=root ; COMMAND=/bin/bash"
        else
            LOG_LINE="$TIMESTAMP kali sudo:   $SUDO_TARGET_USER : $i incorrect password attempts ; TTY=pts/1 ; PWD=/home/$SUDO_TARGET_USER ; USER=root ; COMMAND=/bin/su"
        fi
        echo "$LOG_LINE" >> "$TARGET_AUTH"
        echo -e "  ${YELLOW}--> [AUTH.LOG]${NC} $LOG_LINE"
        sleep 0.4
    done

    echo -e "${GREEN}[+] Sudo escalation abuse sequence completed!${NC}"
    echo -e "${MAGENTA}[*] Check PySIEM Web Dashboard: Alert RULE-03 raised for user ${SUDO_TARGET_USER}!${NC}\n"
}

# ------------------------------------------------------------------------------
# Attack Scenario 4: Full Multi-Stage APT Attack
# ------------------------------------------------------------------------------
simulate_multi_stage_apt() {
    echo -e "\n${RED}${BOLD}============================================================${NC}"
    echo -e "${RED}${BOLD}[*] LAUNCHING MULTI-STAGE APT CAMPAIGN SIMULATION${NC}"
    echo -e "${RED}${BOLD}============================================================${NC}"
    
    echo -e "\n${BOLD}--- PHASE 1: EXTERNAL RECONNAISSANCE ---${NC}"
    simulate_web_recon
    sleep 2

    echo -e "\n${BOLD}--- PHASE 2: CREDENTIAL BRUTE-FORCING ---${NC}"
    simulate_ssh_brute_force
    sleep 2

    echo -e "\n${BOLD}--- PHASE 3: INTERNAL PRIVILEGE ESCALATION ---${NC}"
    simulate_sudo_abuse

    echo -e "\n${GREEN}${BOLD}[✔] Full Multi-Stage APT simulation executed!${NC}"
}

# ------------------------------------------------------------------------------
# Utility: Reset Logs & Database
# ------------------------------------------------------------------------------
reset_environment() {
    echo -e "\n${YELLOW}[*] Resetting mock logs and clearing SQLite database...${NC}"
    > "$AUTH_LOG_MOCK"
    > "$APACHE_LOG_MOCK"
    if [ -f "$SCRIPT_DIR/pysiem.db" ]; then
        rm -f "$SCRIPT_DIR/pysiem.db"*
        echo -e "${GREEN}[+] Removed pysiem.db${NC}"
    fi
    echo -e "${GREEN}[+] Environment reset complete.${NC}\n"
}

# ------------------------------------------------------------------------------
# Interactive Menu
# ------------------------------------------------------------------------------
show_menu() {
    print_banner
    echo -e "${BOLD}Select Attack Simulation Scenario:${NC}"
    echo -e "  ${CYAN}[1]${NC} Simulate SSH Brute Force (RULE-01: >= 5 fails from $SSH_ATTACKER_IP)"
    echo -e "  ${CYAN}[2]${NC} Simulate Web Recon / Directory Fuzzing (RULE-02: >= 10 404s from $WEB_ATTACKER_IP)"
    echo -e "  ${CYAN}[3]${NC} Simulate Sudo Privilege Escalation Abuse (RULE-03: user $SUDO_TARGET_USER)"
    echo -e "  ${CYAN}[4]${NC} ${BOLD}Run Full Multi-Stage APT Attack Campaign (All rules sequentially)${NC}"
    echo -e "  ${CYAN}[5]${NC} Reset Mock Logs & Database"
    echo -e "  ${CYAN}[6]${NC} Exit"
    echo ""
    read -p "Enter selection [1-6]: " choice

    case $choice in
        1) simulate_ssh_brute_force ;;
        2) simulate_web_recon ;;
        3) simulate_sudo_abuse ;;
        4) simulate_multi_stage_apt ;;
        5) reset_environment ;;
        6) echo "Exiting."; exit 0 ;;
        *) echo "Invalid choice."; sleep 1; show_menu ;;
    esac
}

# Command Line Argument Routing
if [ "$1" == "--ssh" ] || [ "$1" == "1" ]; then
    simulate_ssh_brute_force
elif [ "$1" == "--web" ] || [ "$1" == "2" ]; then
    simulate_web_recon
elif [ "$1" == "--sudo" ] || [ "$1" == "3" ]; then
    simulate_sudo_abuse
elif [ "$1" == "--all" ] || [ "$1" == "4" ]; then
    simulate_multi_stage_apt
elif [ "$1" == "--reset" ] || [ "$1" == "5" ]; then
    reset_environment
else
    show_menu
fi
