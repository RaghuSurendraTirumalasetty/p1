"""
PySIEM-Lite: Database Management Module
Handles SQLite schema setup, thread-safe connection pooling, WAL journaling,
event storage, alert logging, and analytics aggregation queries.
"""

import sqlite3
import json
import time
from datetime import datetime
import threading
from typing import Dict, List, Any, Optional
import config

_local = threading.local()

def get_db_connection() -> sqlite3.Connection:
    """
    Returns a thread-local SQLite connection with dictionary row factories
    and WAL journal mode enabled for concurrent read/write stability.
    """
    if not hasattr(_local, "connection") or _local.connection is None:
        conn = sqlite3.connect(config.DATABASE_PATH, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for high-throughput concurrent reads and writes
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        _local.connection = conn
    return _local.connection

def init_db():
    """Initializes SQLite database schema for events, alerts, and blocked IPs."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Normalized Events Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        timestamp_str TEXT NOT NULL,
        log_source TEXT NOT NULL,
        source_ip TEXT,
        destination_user TEXT,
        event_type TEXT NOT NULL,
        response_code INTEGER,
        raw_log TEXT NOT NULL,
        extra_data TEXT
    );
    """)

    # Correlation Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        timestamp_str TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        rule_name TEXT NOT NULL,
        source_ip TEXT,
        destination_user TEXT,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        event_count INTEGER DEFAULT 1,
        mitigation_status TEXT DEFAULT 'PENDING',
        details TEXT
    );
    """)

    # Active Defense / Blocked IPs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL,
        reason TEXT NOT NULL,
        rule_id TEXT,
        blocked_at REAL NOT NULL,
        blocked_at_str TEXT NOT NULL,
        unblock_at REAL,
        status TEXT DEFAULT 'ACTIVE'
    );
    """)

    # Create Indexes for fast querying & dashboard charts
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip_address);")

    conn.commit()

def insert_event(event: Dict[str, Any]) -> int:
    """Inserts a standardized normalized event into SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()

    ts = event.get("timestamp", time.time())
    ts_str = event.get("timestamp_str", datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"))
    extra = json.dumps(event.get("extra_data", {}))

    cursor.execute("""
        INSERT INTO events (
            timestamp, timestamp_str, log_source, source_ip, 
            destination_user, event_type, response_code, raw_log, extra_data
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ts,
        ts_str,
        event.get("log_source", "unknown"),
        event.get("source_ip"),
        event.get("destination_user"),
        event.get("event_type", "UNKNOWN"),
        event.get("response_code"),
        event.get("raw_log", ""),
        extra
    ))
    conn.commit()
    return cursor.lastrowid

def insert_alert(alert: Dict[str, Any]) -> int:
    """Inserts a triggered security alert into SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()

    ts = alert.get("timestamp", time.time())
    ts_str = alert.get("timestamp_str", datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"))
    details = json.dumps(alert.get("details", {}))

    cursor.execute("""
        INSERT INTO alerts (
            timestamp, timestamp_str, rule_id, rule_name, source_ip,
            destination_user, severity, description, event_count,
            mitigation_status, details
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ts,
        ts_str,
        alert.get("rule_id", "UNKNOWN"),
        alert.get("rule_name", "Security Alert"),
        alert.get("source_ip"),
        alert.get("destination_user"),
        alert.get("severity", "MEDIUM"),
        alert.get("description", ""),
        alert.get("event_count", 1),
        alert.get("mitigation_status", "PENDING"),
        details
    ))
    conn.commit()
    return cursor.lastrowid

def update_alert_mitigation(alert_id: int, status: str):
    """Updates the mitigation status of an alert (e.g. BLOCKED, SIMULATED, NONE)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET mitigation_status = ? WHERE id = ?", (status, alert_id))
    conn.commit()

def get_recent_events(limit: int = 50, event_type: Optional[str] = None, ip: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves recent normalized events with optional filtering."""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM events WHERE 1=1"
    params = []

    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    if ip:
        query += " AND source_ip = ?"
        params.append(ip)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()

    results = []
    for r in rows:
        d = dict(r)
        if d.get("extra_data"):
            try:
                d["extra_data"] = json.loads(d["extra_data"])
            except Exception:
                pass
        results.append(d)
    return results

def get_alerts(limit: int = 50, severity: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves security alerts sorted by newest first."""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()

    results = []
    for r in rows:
        d = dict(r)
        if d.get("details"):
            try:
                d["details"] = json.loads(d["details"])
            except Exception:
                pass
        results.append(d)
    return results

def add_blocked_ip(ip: str, reason: str, rule_id: Optional[str] = None, duration_seconds: int = 3600, status: str = "ACTIVE") -> bool:
    """Records an IP address into the blocked table with expiration."""
    conn = get_db_connection()
    cursor = conn.cursor()

    now = time.time()
    unblock_at = now + duration_seconds
    now_str = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO blocked_ips (ip_address, reason, rule_id, blocked_at, blocked_at_str, unblock_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET
            reason=excluded.reason,
            rule_id=excluded.rule_id,
            blocked_at=excluded.blocked_at,
            blocked_at_str=excluded.blocked_at_str,
            unblock_at=excluded.unblock_at,
            status='ACTIVE'
    """, (ip, reason, rule_id, now, now_str, unblock_at, status))
    conn.commit()
    return True

def unblock_ip_in_db(ip: str) -> bool:
    """Sets an IP status to UNBLOCKED in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE blocked_ips SET status = 'UNBLOCKED' WHERE ip_address = ?", (ip,))
    conn.commit()
    return cursor.rowcount > 0

def get_blocked_ips(active_only: bool = True) -> List[Dict[str, Any]]:
    """Returns list of currently blocked IPs."""
    conn = get_db_connection()
    cursor = conn.cursor()

    if active_only:
        cursor.execute("SELECT * FROM blocked_ips WHERE status = 'ACTIVE' ORDER BY blocked_at DESC")
    else:
        cursor.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")

    rows = cursor.fetchall()
    return [dict(r) for r in rows]

def is_ip_blocked(ip: str) -> bool:
    """Checks whether an IP is currently marked as actively blocked."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM blocked_ips WHERE ip_address = ? AND status = 'ACTIVE' LIMIT 1", (ip,))
    return cursor.fetchone() is not None

def get_expired_blocks() -> List[str]:
    """Retrieves list of active IPs whose ban time has expired."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now = time.time()
    cursor.execute("SELECT ip_address FROM blocked_ips WHERE status = 'ACTIVE' AND unblock_at <= ?", (now,))
    rows = cursor.fetchall()
    return [r["ip_address"] for r in rows]

def get_dashboard_metrics() -> Dict[str, Any]:
    """Calculates summary KPIs and chart aggregations for the web dashboard."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Total Events
    cursor.execute("SELECT COUNT(*) as count FROM events")
    total_events = cursor.fetchone()["count"]

    # Total Alerts
    cursor.execute("SELECT COUNT(*) as count FROM alerts")
    total_alerts = cursor.fetchone()["count"]

    # Critical Alerts
    cursor.execute("SELECT COUNT(*) as count FROM alerts WHERE severity = 'CRITICAL'")
    critical_alerts = cursor.fetchone()["count"]

    # Active Blocked IPs
    cursor.execute("SELECT COUNT(*) as count FROM blocked_ips WHERE status = 'ACTIVE'")
    active_blocks = cursor.fetchone()["count"]

    # Event Breakdown by Type
    cursor.execute("SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type")
    event_distribution = {r["event_type"]: r["count"] for r in cursor.fetchall()}

    # Alerts Breakdown by Rule
    cursor.execute("SELECT rule_id, COUNT(*) as count FROM alerts GROUP BY rule_id")
    rule_distribution = {r["rule_id"]: r["count"] for r in cursor.fetchall()}

    # Recent Alerts by Severity
    cursor.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
    severity_distribution = {r["severity"]: r["count"] for r in cursor.fetchall()}

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "active_blocks": active_blocks,
        "event_distribution": event_distribution,
        "rule_distribution": rule_distribution,
        "severity_distribution": severity_distribution
    }
