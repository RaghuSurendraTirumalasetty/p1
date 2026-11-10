"""
PySIEM-Lite: Configuration Module
Contains system defaults, log paths, rule thresholds, severity scores, and network whitelists.
"""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = str(BASE_DIR / "pysiem.db")
MOCK_LOG_DIR = BASE_DIR / "mock_logs"

# Ensure mock log directory exists for testing/simulations
MOCK_LOG_DIR.mkdir(parents=True, exist_ok=True)

# Default Log Sources
# On Debian/Kali Linux:
#   Auth log: /var/log/auth.log
#   Apache access log: /var/log/apache2/access.log
DEFAULT_AUTH_LOG = "/var/log/auth.log"
DEFAULT_APACHE_LOG = "/var/log/apache2/access.log"

# Fallback / Mock paths for non-root testing or development environments
MOCK_AUTH_LOG = str(MOCK_LOG_DIR / "auth.log")
MOCK_APACHE_LOG = str(MOCK_LOG_DIR / "access.log")

# Web Server Settings
WEB_HOST = os.getenv("PYSIEM_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("PYSIEM_PORT", 5000))
SECRET_KEY = os.getenv("PYSIEM_SECRET", "pysiem-lite-super-secret-key-2026")

# Active Defense & Network Safeguards
ENABLE_AUTO_BLOCK = True
DEFAULT_BAN_DURATION = 3600  # 1 hour in seconds
BAN_CHECK_INTERVAL = 30     # Check for expired bans every 30 seconds

# Whitelist IPs that must NEVER be blocked (prevents self-lockout)
IP_WHITELIST = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "localhost"
}

# Detection Rule Definitions & Thresholds
RULES_CONFIG = {
    "RULE-01": {
        "id": "RULE-01",
        "name": "SSH Brute Force Attack",
        "target_event": "LOGIN_FAILED",
        "threshold": 5,          # >= 5 failed logins
        "time_window": 60,       # within 60 seconds
        "group_by": "source_ip",
        "base_severity": "HIGH",
        "auto_block": True,
        "description": "Multiple failed authentication attempts detected from a single source IP indicating brute-force or credential stuffing."
    },
    "RULE-02": {
        "id": "RULE-02",
        "name": "Web Reconnaissance & Directory Fuzzing",
        "target_event": "WEB_REQUEST",
        "target_statuses": [403, 404],
        "threshold": 10,         # >= 10 errors (403/404)
        "time_window": 15,       # within 15 seconds
        "group_by": "source_ip",
        "base_severity": "HIGH",
        "auto_block": True,
        "description": "Rapid succession of HTTP 404/403 responses indicating automated directory busting, vulnerability scanning, or endpoint probing."
    },
    "RULE-03": {
        "id": "RULE-03",
        "name": "Suspicious Sudo Privilege Escalation",
        "target_event": "SUDO_FAILURE",
        "threshold": 3,          # >= 3 sudo failures
        "time_window": 60,       # within 60 seconds
        "group_by": "destination_user",
        "base_severity": "HIGH",
        "auto_block": False,     # User escalation usually requires host isolation rather than remote IP ban
        "description": "Multiple unauthorized sudo attempts or pam authentication failures indicating local privilege escalation abuse."
    }
}

# Severity Weights for Dynamic Scoring
SEVERITY_LEVELS = {
    "LOW": {"color": "blue", "score": 10},
    "MEDIUM": {"color": "yellow", "score": 40},
    "HIGH": {"color": "orange", "score": 75},
    "CRITICAL": {"color": "red", "score": 95}
}
