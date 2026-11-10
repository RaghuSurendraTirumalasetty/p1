"""
PySIEM-Lite: Active Defense & Mitigation Module
Handles automated threat containment via Linux iptables wrapper,
enforces IP whitelisting safeguards, and manages temporary ban lifecycles.
"""

import subprocess
import ipaddress
import platform
import os
import time
import logging
import threading
from typing import Dict, Any, Tuple
import config
import database

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] [RESPONDER] %(message)s")
logger = logging.getLogger("PySIEM-Responder")

class ActiveResponder:
    """
    Subprocess-driven active mitigation controller.
    Safely executes iptables rules, manages auto-block lifecycles, and prevents lockout.
    """

    def __init__(self):
        self.is_linux = platform.system() == "Linux"
        self.is_root = os.geteuid() == 0 if self.is_linux else False
        self._lock = threading.Lock()
        self._running = False
        self._unban_thread = None

        if self.is_linux and not self.is_root:
            logger.warning("ActiveResponder is NOT running as root (UID != 0). iptables commands will use 'sudo -n' or fallback to simulated defense.")

    def is_valid_public_or_external_ip(self, ip: str) -> bool:
        """Validates IP format and verifies it is not in the whitelist or loopback."""
        if not ip or ip in config.IP_WHITELIST:
            return False

        try:
            addr = ipaddress.ip_address(ip)
            # Safeguard: Do not ban loopback or multicast
            if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
                return False
            return True
        except ValueError:
            return False

    def check_iptables_rule_exists(self, ip: str) -> bool:
        """Checks if a DROP rule already exists for the given IP in iptables."""
        if not self.is_linux:
            return False

        cmd = ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"]
        if not self.is_root:
            cmd = ["sudo", "-n"] + cmd

        try:
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return res.returncode == 0
        except Exception:
            return False

    def block_ip(self, ip: str, reason: str = "Automated Defense", rule_id: str = "GENERIC", duration: int = None) -> Tuple[bool, str]:
        """
        Executes an iptables DROP rule for the specified attacker IP and records to DB.
        Returns: (success: bool, status_message: str)
        """
        with self._lock:
            if not self.is_valid_public_or_external_ip(ip):
                msg = f"Cannot block IP {ip}: Whitelisted, loopback, or invalid IP format."
                logger.info(msg)
                return False, msg

            duration = duration or config.DEFAULT_BAN_DURATION

            # Already blocked check
            if database.is_ip_blocked(ip):
                msg = f"IP {ip} is already actively blocked in PySIEM."
                logger.info(msg)
                return True, msg

            status_label = "BLOCKED"

            if self.is_linux:
                cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
                if not self.is_root:
                    cmd = ["sudo", "-n"] + cmd

                try:
                    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if res.returncode == 0:
                        logger.info(f"ACTIVE MITIGATION: Successfully executed iptables DROP rule against {ip} ({reason})")
                        status_label = "BLOCKED"
                    else:
                        err = res.stderr.strip()
                        logger.warning(f"iptables invocation failed ({err}). Falling back to SIMULATED_BLOCKED mode.")
                        status_label = "SIMULATED_BLOCKED"
                except Exception as ex:
                    logger.error(f"Error executing iptables: {ex}. Marking as SIMULATED_BLOCKED.")
                    status_label = "SIMULATED_BLOCKED"
            else:
                logger.info(f"SIMULATION (Non-Linux): iptables -I INPUT -s {ip} -j DROP for {duration}s ({reason})")
                status_label = "SIMULATED_BLOCKED"

            # Record in Database
            database.add_blocked_ip(ip=ip, reason=reason, rule_id=rule_id, duration_seconds=duration, status="ACTIVE")
            return True, status_label

    def unblock_ip(self, ip: str) -> Tuple[bool, str]:
        """
        Removes iptables DROP rule and updates database status to UNBLOCKED.
        """
        with self._lock:
            if not ip:
                return False, "Invalid IP."

            status_label = "UNBLOCKED"

            if self.is_linux:
                # Remove all matching DROP rules for this IP
                cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                if not self.is_root:
                    cmd = ["sudo", "-n"] + cmd

                try:
                    # Loop in case rule was added multiple times
                    while True:
                        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        if res.returncode != 0:
                            break
                    logger.info(f"UNBAN SUCCESS: Removed iptables DROP rule for {ip}")
                except Exception as ex:
                    logger.error(f"Failed to remove iptables rule for {ip}: {ex}")

            # Mark as unblocked in SQLite
            database.unblock_ip_in_db(ip)
            return True, "IP unblocked successfully."

    def _auto_unban_worker(self):
        """Background thread worker that removes expired temporary bans."""
        while self._running:
            try:
                expired_ips = database.get_expired_blocks()
                for ip in expired_ips:
                    logger.info(f"Ban expired for IP: {ip}. Executing automatic unban.")
                    self.unblock_ip(ip)
            except Exception as ex:
                logger.error(f"Error in auto-unban daemon: {ex}")

            time.sleep(config.BAN_CHECK_INTERVAL)

    def start_auto_unban_daemon(self):
        """Starts background worker monitoring expired bans."""
        if not self._running:
            self._running = True
            self._unban_thread = threading.Thread(target=self._auto_unban_worker, daemon=True, name="AutoUnbanThread")
            self._unban_thread.start()
            logger.info("Active defense unban background monitor started.")

    def stop_auto_unban_daemon(self):
        """Stops background monitor."""
        self._running = False

# Global singleton instance for easy import across modules
responder = ActiveResponder()
