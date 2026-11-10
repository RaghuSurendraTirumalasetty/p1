"""
PySIEM-Lite: Multi-Event Correlation & Detection Engine
Maintains in-memory sliding time windows, evaluates security rules,
calculates dynamic severity scores, and triggers automated active defenses.
"""

import time
import logging
import threading
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional
import config
import database
from responder import responder

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] [ENGINE] %(message)s")
logger = logging.getLogger("PySIEM-Engine")

class CorrelationEngine:
    """
    Real-time sliding time-window correlation engine.
    Processes normalized events, tracks frequency velocities per entity,
    and raises priority-based security alerts.
    """

    def __init__(self):
        # Sliding windows: map of (rule_id, entity_key) -> deque of (timestamp, event_dict)
        self.windows = defaultdict(deque)
        # Alert cooldown tracking to prevent alert storms: (rule_id, entity_key) -> last_alert_time
        self.alert_cooldowns = {}
        self.cooldown_period = 30  # seconds before raising same rule alert for same entity
        self._lock = threading.Lock()

        # Sensitive paths for web recon severity escalation
        self.sensitive_endpoints = {
            ".env", "wp-login.php", "wp-config.php", "admin", "administrator",
            "phpmyadmin", ".git", "passwd", "shadow", "config.json", "id_rsa"
        }

    def _clean_expired_window(self, window: deque, time_window: float, current_time: float):
        """Removes events older than (current_time - time_window) from the deque."""
        cutoff = current_time - time_window
        while window and window[0][0] < cutoff:
            window.popleft()

    def calculate_severity(self, rule_id: str, count: int, entity: str, sample_events: List[Dict[str, Any]]) -> str:
        """
        Dynamically calculates alert severity based on event count,
        privileged targets, and attack velocity.
        """
        base_rule = config.RULES_CONFIG.get(rule_id, {})
        base_severity = base_rule.get("base_severity", "MEDIUM")

        if rule_id == "RULE-01":
            # SSH Brute Force
            # Check if targeting root or high volume
            targeted_users = {e.get("destination_user") for e in sample_events if e.get("destination_user")}
            if "root" in targeted_users or "admin" in targeted_users or count >= 10:
                return "CRITICAL"
            return "HIGH"

        elif rule_id == "RULE-02":
            # Web Application Recon
            # Check if probing sensitive endpoints
            for ev in sample_events:
                extra = ev.get("extra_data", {})
                if isinstance(extra, dict):
                    path = extra.get("path", "").lower()
                    if any(target in path for target in self.sensitive_endpoints):
                        return "CRITICAL"
            if count >= 20:
                return "CRITICAL"
            return "HIGH"

        elif rule_id == "RULE-03":
            # Sudo abuse
            if count >= 5:
                return "CRITICAL"
            return "HIGH"

        return base_severity

    def evaluate_rule_01(self, event: Dict[str, Any], current_time: float) -> Optional[Dict[str, Any]]:
        """
        RULE-01: SSH Brute Force Detection
        >= 5 failed logins within 60s from the same source IP.
        """
        if event.get("event_type") != "LOGIN_FAILED":
            return None

        ip = event.get("source_ip")
        if not ip or ip in config.IP_WHITELIST:
            return None

        rule = config.RULES_CONFIG["RULE-01"]
        window_key = ("RULE-01", ip)
        win = self.windows[window_key]

        win.append((current_time, event))
        self._clean_expired_window(win, rule["time_window"], current_time)

        if len(win) >= rule["threshold"]:
            # Check cooldown
            last_alert = self.alert_cooldowns.get(window_key, 0)
            if current_time - last_alert >= self.cooldown_period:
                self.alert_cooldowns[window_key] = current_time
                events_in_win = [ev for _, ev in win]
                severity = self.calculate_severity("RULE-01", len(win), ip, events_in_win)
                users = list({e.get("destination_user") for e in events_in_win if e.get("destination_user")})

                return {
                    "rule_id": "RULE-01",
                    "rule_name": rule["name"],
                    "source_ip": ip,
                    "destination_user": ", ".join(users) if users else "unknown",
                    "severity": severity,
                    "event_count": len(win),
                    "description": f"Detected {len(win)} failed SSH login attempts from {ip} in under {rule['time_window']}s targeting accounts: {', '.join(users) if users else 'unknown'}.",
                    "details": {
                        "time_window_seconds": rule["time_window"],
                        "threshold": rule["threshold"],
                        "targeted_accounts": users,
                        "auto_block_eligible": rule.get("auto_block", True)
                    }
                }
        return None

    def evaluate_rule_02(self, event: Dict[str, Any], current_time: float) -> Optional[Dict[str, Any]]:
        """
        RULE-02: Web Application Recon & Directory Fuzzing
        >= 10 HTTP 404/403 responses within 15s from same source IP.
        """
        if event.get("event_type") != "WEB_REQUEST":
            return None

        status_code = event.get("response_code")
        if status_code not in (403, 404):
            return None

        ip = event.get("source_ip")
        if not ip or ip in config.IP_WHITELIST:
            return None

        rule = config.RULES_CONFIG["RULE-02"]
        window_key = ("RULE-02", ip)
        win = self.windows[window_key]

        win.append((current_time, event))
        self._clean_expired_window(win, rule["time_window"], current_time)

        if len(win) >= rule["threshold"]:
            last_alert = self.alert_cooldowns.get(window_key, 0)
            if current_time - last_alert >= self.cooldown_period:
                self.alert_cooldowns[window_key] = current_time
                events_in_win = [ev for _, ev in win]
                severity = self.calculate_severity("RULE-02", len(win), ip, events_in_win)
                probed_paths = []
                for ev in events_in_win:
                    extra = ev.get("extra_data", {})
                    if isinstance(extra, dict) and "path" in extra:
                        probed_paths.append(extra["path"])

                sample_paths = list(set(probed_paths))[:6]

                return {
                    "rule_id": "RULE-02",
                    "rule_name": rule["name"],
                    "source_ip": ip,
                    "destination_user": None,
                    "severity": severity,
                    "event_count": len(win),
                    "description": f"Detected {len(win)} HTTP 403/404 scanning requests from {ip} within {rule['time_window']}s probing endpoints: {', '.join(sample_paths)}.",
                    "details": {
                        "time_window_seconds": rule["time_window"],
                        "threshold": rule["threshold"],
                        "sample_probed_paths": sample_paths,
                        "auto_block_eligible": rule.get("auto_block", True)
                    }
                }
        return None

    def evaluate_rule_03(self, event: Dict[str, Any], current_time: float) -> Optional[Dict[str, Any]]:
        """
        RULE-03: Suspicious Sudo Privilege Escalation
        >= 3 sudo authentication failures within 60s from non-root user.
        """
        if event.get("event_type") != "SUDO_FAILURE":
            return None

        user = event.get("destination_user") or "unknown_user"
        rule = config.RULES_CONFIG["RULE-03"]
        window_key = ("RULE-03", user)
        win = self.windows[window_key]

        win.append((current_time, event))
        self._clean_expired_window(win, rule["time_window"], current_time)

        if len(win) >= rule["threshold"]:
            last_alert = self.alert_cooldowns.get(window_key, 0)
            if current_time - last_alert >= self.cooldown_period:
                self.alert_cooldowns[window_key] = current_time
                events_in_win = [ev for _, ev in win]
                severity = self.calculate_severity("RULE-03", len(win), user, events_in_win)

                return {
                    "rule_id": "RULE-03",
                    "rule_name": rule["name"],
                    "source_ip": event.get("source_ip") or "127.0.0.1",
                    "destination_user": user,
                    "severity": severity,
                    "event_count": len(win),
                    "description": f"Multiple unauthorized sudo privilege escalation attempts ({len(win)} failures) by user '{user}' within {rule['time_window']}s.",
                    "details": {
                        "time_window_seconds": rule["time_window"],
                        "threshold": rule["threshold"],
                        "user": user,
                        "auto_block_eligible": False
                    }
                }
        return None

    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Primary entry point for ingested normalized events.
        Runs event across all active correlation rules.
        """
        alerts_triggered = []
        now = time.time()

        with self._lock:
            # Rule 1
            a1 = self.evaluate_rule_01(event, now)
            if a1:
                alerts_triggered.append(a1)

            # Rule 2
            a2 = self.evaluate_rule_02(event, now)
            if a2:
                alerts_triggered.append(a2)

            # Rule 3
            a3 = self.evaluate_rule_03(event, now)
            if a3:
                alerts_triggered.append(a3)

        # Handle triggered alerts & execute active defense
        for alert in alerts_triggered:
            self._handle_alert(alert)

        return alerts_triggered

    def _handle_alert(self, alert: Dict[str, Any]):
        """Persists alert and executes active defense mitigation if applicable."""
        rule_id = alert.get("rule_id")
        ip = alert.get("source_ip")
        severity = alert.get("severity")

        mitigation_status = "NONE"

        # Check if auto-block should be triggered
        rule_cfg = config.RULES_CONFIG.get(rule_id, {})
        auto_block_enabled = config.ENABLE_AUTO_BLOCK and rule_cfg.get("auto_block", False)

        # Trigger active response on CRITICAL severity or if rule auto-block is set
        if auto_block_enabled and ip and ip not in config.IP_WHITELIST:
            logger.warning(f"CRITICAL THREAT DETECTED: [{rule_id}] from {ip}. Triggering Active Defense.")
            success, status_lbl = responder.block_ip(
                ip=ip,
                reason=f"{alert.get('rule_name')} (Triggered {alert.get('event_count')} events)",
                rule_id=rule_id
            )
            mitigation_status = status_lbl if success else "FAILED"
        else:
            mitigation_status = "ALERT_ONLY"

        alert["mitigation_status"] = mitigation_status
        alert_id = database.insert_alert(alert)
        alert["id"] = alert_id

        logger.info(f"SECURITY ALERT #{alert_id} [{alert['severity']}] {alert['rule_name']} - Entity: {ip or alert.get('destination_user')} (Mitigation: {mitigation_status})")

# Global singleton engine instance
engine = CorrelationEngine()
