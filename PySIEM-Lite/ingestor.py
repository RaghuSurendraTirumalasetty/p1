"""
PySIEM-Lite: Log Ingestion & Normalizer Module
Continuously tails system auth and web server log files,
parses disparate syslog and Apache formats via regex,
standardizes events into JSON-compatible dictionaries, and feeds the correlation engine.
"""

import os
import re
import time
from datetime import datetime
import threading
import logging
from typing import Dict, Any, Optional, Callable
import config
import database
from engine import engine

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] [INGESTOR] %(message)s")
logger = logging.getLogger("PySIEM-Ingestor")

# -------------------------------------------------------------
# REGEX DEFINITIONS FOR LOG PARSING
# -------------------------------------------------------------

# SSH Patterns
RE_SSH_FAILED = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+) port \d+",
    re.IGNORECASE
)
RE_SSH_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+) port \d+",
    re.IGNORECASE
)
RE_SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d\.:a-fA-F]+) port \d+",
    re.IGNORECASE
)

# Sudo Patterns
RE_SUDO_NOT_IN_SUDOERS = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:\s*user NOT in sudoers",
    re.IGNORECASE
)
RE_SUDO_INCORRECT_PASS = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:\s*(?:\d+ incorrect password attempts|authentication failure)",
    re.IGNORECASE
)
RE_SUDO_PAM_FAILURE = re.compile(
    r"sudo:\s+pam_unix\(sudo:auth\):\s+authentication failure;.*user=(?P<user>\S+)",
    re.IGNORECASE
)

# Apache Access Log Pattern (Combined & Common Log Format)
RE_APACHE_ACCESS = re.compile(
    r'^(?P<ip>[\d\.:a-fA-F]+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[0-9\.]+)?\"\s+(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?',
    re.IGNORECASE
)

# Syslog Standard Timestamp Format ("Nov 10 12:35:10")
RE_SYSLOG_TIMESTAMP = re.compile(r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")
# ISO 8601 Timestamp Format ("2026-11-10T12:35:10.123456+00:00")
RE_ISO_TIMESTAMP = re.compile(r"^(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")


class LogNormalizer:
    """Parses raw text log lines and converts them into standardized normalized events."""

    @staticmethod
    def parse_syslog_timestamp(raw_line: str) -> float:
        """Extracts timestamp from syslog headers or defaults to current time."""
        now = datetime.now()
        iso_match = RE_ISO_TIMESTAMP.search(raw_line)
        if iso_match:
            try:
                dt_str = iso_match.group("iso").replace("T", " ")
                dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
                return dt.timestamp()
            except Exception:
                pass

        sys_match = RE_SYSLOG_TIMESTAMP.search(raw_line)
        if sys_match:
            try:
                mon = sys_match.group("month")
                day = sys_match.group("day")
                t_str = sys_match.group("time")
                dt_str = f"{now.year} {mon} {day} {t_str}"
                dt = datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")
                return dt.timestamp()
            except Exception:
                pass

        return time.time()

    @staticmethod
    def parse_apache_timestamp(ts_str: str) -> float:
        """Extracts unix timestamp from Apache format e.g. 10/Nov/2026:12:35:10 +0530."""
        try:
            # Strip timezone offset if present
            clean_ts = ts_str.split()[0]
            dt = datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S")
            return dt.timestamp()
        except Exception:
            return time.time()

    @classmethod
    def normalize_auth_line(cls, line: str, source_name: str = "auth.log") -> Optional[Dict[str, Any]]:
        """Parses Linux authentication and sudo log entries."""
        line = line.strip()
        if not line:
            return None

        event_ts = cls.parse_syslog_timestamp(line)
        iso_str = datetime.fromtimestamp(event_ts).strftime("%Y-%m-%d %H:%M:%S")

        # 1. SSH Failed Password
        m_failed = RE_SSH_FAILED.search(line)
        if m_failed:
            return {
                "timestamp": event_ts,
                "timestamp_str": iso_str,
                "log_source": source_name,
                "source_ip": m_failed.group("ip"),
                "destination_user": m_failed.group("user"),
                "event_type": "LOGIN_FAILED",
                "response_code": None,
                "raw_log": line,
                "extra_data": {"protocol": "ssh", "auth_status": "failure"}
            }

        # 2. SSH Invalid User
        m_inv = RE_SSH_INVALID_USER.search(line)
        if m_inv:
            return {
                "timestamp": event_ts,
                "timestamp_str": iso_str,
                "log_source": source_name,
                "source_ip": m_inv.group("ip"),
                "destination_user": m_inv.group("user"),
                "event_type": "LOGIN_FAILED",
                "response_code": None,
                "raw_log": line,
                "extra_data": {"protocol": "ssh", "reason": "invalid_user"}
            }

        # 3. SSH Accepted Login
        m_ok = RE_SSH_ACCEPTED.search(line)
        if m_ok:
            return {
                "timestamp": event_ts,
                "timestamp_str": iso_str,
                "log_source": source_name,
                "source_ip": m_ok.group("ip"),
                "destination_user": m_ok.group("user"),
                "event_type": "LOGIN_SUCCESS",
                "response_code": None,
                "raw_log": line,
                "extra_data": {"protocol": "ssh", "auth_status": "success"}
            }

        # 4. Sudo Abuse / Failures
        m_sudo1 = RE_SUDO_NOT_IN_SUDOERS.search(line)
        if m_sudo1:
            return {
                "timestamp": event_ts,
                "timestamp_str": iso_str,
                "log_source": source_name,
                "source_ip": "127.0.0.1",
                "destination_user": m_sudo1.group("user"),
                "event_type": "SUDO_FAILURE",
                "response_code": None,
                "raw_log": line,
                "extra_data": {"reason": "user_not_in_sudoers"}
            }

        m_sudo2 = RE_SUDO_INCORRECT_PASS.search(line)
        if m_sudo2:
            return {
                "timestamp": event_ts,
                "timestamp_str": iso_str,
                "log_source": source_name,
                "source_ip": "127.0.0.1",
                "destination_user": m_sudo2.group("user"),
                "event_type": "SUDO_FAILURE",
                "response_code": None,
                "raw_log": line,
                "extra_data": {"reason": "incorrect_password_attempts"}
            }

        m_sudo3 = RE_SUDO_PAM_FAILURE.search(line)
        if m_sudo3:
            return {
                "timestamp": event_ts,
                "timestamp_str": iso_str,
                "log_source": source_name,
                "source_ip": "127.0.0.1",
                "destination_user": m_sudo3.group("user"),
                "event_type": "SUDO_FAILURE",
                "response_code": None,
                "raw_log": line,
                "extra_data": {"reason": "pam_authentication_failure"}
            }

        return None

    @classmethod
    def normalize_apache_line(cls, line: str, source_name: str = "access.log") -> Optional[Dict[str, Any]]:
        """Parses Apache web server access log lines."""
        line = line.strip()
        if not line:
            return None

        match = RE_APACHE_ACCESS.search(line)
        if not match:
            return None

        status_code = int(match.group("status"))
        event_ts = cls.parse_apache_timestamp(match.group("timestamp"))
        iso_str = datetime.fromtimestamp(event_ts).strftime("%Y-%m-%d %H:%M:%S")

        raw_user = match.group("user")
        user = raw_user if raw_user != "-" else None

        return {
            "timestamp": event_ts,
            "timestamp_str": iso_str,
            "log_source": source_name,
            "source_ip": match.group("ip"),
            "destination_user": user,
            "event_type": "WEB_REQUEST",
            "response_code": status_code,
            "raw_log": line,
            "extra_data": {
                "method": match.group("method"),
                "path": match.group("path"),
                "size": match.group("size"),
                "referrer": match.group("referrer"),
                "user_agent": match.group("user_agent")
            }
        }


class FileTailer:
    """
    Robust continuous file tailer that handles file creation,
    log rotation, truncation, and real-time event streaming.
    """

    def __init__(self, filepath: str, parser_fn: Callable[[str, str], Optional[Dict[str, Any]]], source_name: str, read_from_start: bool = False):
        self.filepath = filepath
        self.parser_fn = parser_fn
        self.source_name = source_name
        self.read_from_start = read_from_start
        self._running = False
        self._thread = None

    def _tail_worker(self):
        logger.info(f"Starting tailer worker on {self.filepath} ({self.source_name})")

        # Wait for file to exist
        while self._running and not os.path.exists(self.filepath):
            time.sleep(1.0)

        if not self._running:
            return

        try:
            with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
                if not self.read_from_start:
                    # Seek to end of file for live incoming monitoring
                    f.seek(0, os.SEEK_END)

                last_inode = os.stat(self.filepath).st_ino if os.path.exists(self.filepath) else None

                while self._running:
                    line = f.readline()
                    if line:
                        normalized = self.parser_fn(line, self.source_name)
                        if normalized:
                            # Save to SQLite database
                            event_id = database.insert_event(normalized)
                            normalized["id"] = event_id
                            # Send to correlation engine
                            engine.process_event(normalized)
                    else:
                        time.sleep(0.1)

                        # Detect log rotation or truncation
                        if os.path.exists(self.filepath):
                            curr_stat = os.stat(self.filepath)
                            if curr_stat.st_ino != last_inode:
                                logger.info(f"Log rotation detected for {self.filepath}. Reopening...")
                                f.close()
                                f = open(self.filepath, "r", encoding="utf-8", errors="replace")
                                last_inode = curr_stat.st_ino
                            elif curr_stat.st_size < f.tell():
                                logger.info(f"Log truncation detected for {self.filepath}. Rewinding to top...")
                                f.seek(0, os.SEEK_SET)
                        else:
                            # File moved/deleted during rotation
                            time.sleep(1.0)
        except Exception as ex:
            logger.error(f"Tailer error on {self.filepath}: {ex}")

    def start(self):
        """Starts tailer thread."""
        if not self._running:
            self._running = True
            self._thread = threading.Thread(target=self._tail_worker, daemon=True, name=f"Tailer-{self.source_name}")
            self._thread.start()

    def stop(self):
        """Stops tailer thread."""
        self._running = False


class IngestionManager:
    """Manages active file tailers across configured system and web log sources."""

    def __init__(self, auth_log_path: str = None, apache_log_path: str = None, read_from_start: bool = False):
        self.auth_log_path = auth_log_path or self._resolve_auth_log()
        self.apache_log_path = apache_log_path or self._resolve_apache_log()
        self.read_from_start = read_from_start
        self.tailers = []

    def _resolve_auth_log(self) -> str:
        """Determines best path for auth log with fallback."""
        if os.path.exists(config.DEFAULT_AUTH_LOG):
            return config.DEFAULT_AUTH_LOG
        if os.path.exists("/var/log/secure"):
            return "/var/log/secure"
        # Fallback to mock log
        return config.MOCK_AUTH_LOG

    def _resolve_apache_log(self) -> str:
        """Determines best path for web server log with fallback."""
        if os.path.exists(config.DEFAULT_APACHE_LOG):
            return config.DEFAULT_APACHE_LOG
        if os.path.exists("/var/log/httpd/access_log"):
            return "/var/log/httpd/access_log"
        # Fallback to mock log
        return config.MOCK_APACHE_LOG

    def start(self):
        """Initializes database and spawns log tailers."""
        database.init_db()

        # Ensure monitored files exist (touch if mock)
        for p in (self.auth_log_path, self.apache_log_path):
            if not os.path.exists(p):
                try:
                    os.makedirs(os.path.dirname(p), exist_ok=True)
                    with open(p, "a") as f:
                        pass
                except Exception:
                    pass

        t_auth = FileTailer(
            filepath=self.auth_log_path,
            parser_fn=LogNormalizer.normalize_auth_line,
            source_name=os.path.basename(self.auth_log_path),
            read_from_start=self.read_from_start
        )
        t_apache = FileTailer(
            filepath=self.apache_log_path,
            parser_fn=LogNormalizer.normalize_apache_line,
            source_name=os.path.basename(self.apache_log_path),
            read_from_start=self.read_from_start
        )

        self.tailers = [t_auth, t_apache]
        for t in self.tailers:
            t.start()

        logger.info(f"PySIEM Ingestor initialized. Monitoring:")
        logger.info(f" -> Auth Log: {self.auth_log_path}")
        logger.info(f" -> Web Log:  {self.apache_log_path}")

    def stop(self):
        """Stops all active tailers."""
        for t in self.tailers:
            t.stop()
