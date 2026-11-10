"""
PySIEM-Lite: Analyst Web Console & REST API Module
Serves the responsive SOC dashboard, real-time analytics,
Server-Sent Events (SSE) streams, and manual active defense containment controls.
"""

import json
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
import config
import database
from responder import responder

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = config.SECRET_KEY

# Ensure database is initialized
database.init_db()


@app.route("/")
def dashboard_view():
    """Serves the primary SOC Analyst Dashboard interface."""
    return render_template("index.html")


@app.route("/health")
def health_check():
    """System health check endpoint."""
    return jsonify({
        "status": "healthy",
        "system": "PySIEM-Lite",
        "timestamp": datetime.now().isoformat()
    })


@app.route("/api/metrics", methods=["GET"])
def api_metrics():
    """Returns aggregated summary metrics and chart analytics."""
    try:
        metrics = database.get_dashboard_metrics()
        return jsonify({"success": True, "data": metrics})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500


@app.route("/api/events", methods=["GET"])
def api_events():
    """
    Returns latest normalized events.
    Supports query parameters: ?limit=50&type=LOGIN_FAILED&ip=192.168.1.100
    """
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        event_type = request.args.get("type")
        ip = request.args.get("ip")

        events = database.get_recent_events(limit=limit, event_type=event_type, ip=ip)
        return jsonify({"success": True, "count": len(events), "data": events})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    """
    Returns latest triggered security alerts.
    Supports query parameters: ?limit=50&severity=CRITICAL
    """
    try:
        limit = min(int(request.args.get("limit", 50)), 100)
        severity = request.args.get("severity")

        alerts = database.get_alerts(limit=limit, severity=severity)
        return jsonify({"success": True, "count": len(alerts), "data": alerts})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500


@app.route("/api/blocked-ips", methods=["GET"])
def api_blocked_ips():
    """Returns list of currently active and historical blocked IPs."""
    try:
        active_only = request.args.get("active_only", "true").lower() == "true"
        blocked = database.get_blocked_ips(active_only=active_only)
        return jsonify({"success": True, "count": len(blocked), "data": blocked})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500


@app.route("/api/unblock", methods=["POST"])
def api_unblock_ip():
    """
    Manually removes an active iptables block for a specific IP.
    Expects JSON body: {"ip": "1.2.3.4"}
    """
    try:
        payload = request.get_json(force=True, silent=True) or {}
        ip = payload.get("ip", "").strip()

        if not ip:
            return jsonify({"success": False, "error": "IP address is required."}), 400

        success, msg = responder.unblock_ip(ip)
        return jsonify({"success": success, "message": msg, "ip": ip})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500


@app.route("/api/block", methods=["POST"])
def api_manual_block_ip():
    """
    Allows SOC analysts to manually ban an IP via active defense.
    Expects JSON body: {"ip": "1.2.3.4", "reason": "Manual SOC Containment", "duration": 3600}
    """
    try:
        payload = request.get_json(force=True, silent=True) or {}
        ip = payload.get("ip", "").strip()
        reason = payload.get("reason", "Manual Analyst Block")
        duration = int(payload.get("duration", config.DEFAULT_BAN_DURATION))

        if not ip:
            return jsonify({"success": False, "error": "IP address is required."}), 400

        success, msg = responder.block_ip(
            ip=ip,
            reason=reason,
            rule_id="MANUAL-BAN",
            duration=duration
        )
        return jsonify({"success": success, "status": msg, "ip": ip})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500


@app.route("/api/rules", methods=["GET"])
def api_rules():
    """Returns definitions of all active detection rules."""
    return jsonify({"success": True, "rules": config.RULES_CONFIG})


@app.route("/api/stream")
def sse_stream():
    """
    Server-Sent Events (SSE) live push stream.
    Emits continuous real-time telemetry updates to connected browser sessions.
    """
    def event_stream():
        last_event_id = 0
        last_alert_id = 0

        # Prime initial IDs
        recent_evs = database.get_recent_events(limit=1)
        if recent_evs:
            last_event_id = recent_evs[0]["id"]

        recent_alts = database.get_alerts(limit=1)
        if recent_alts:
            last_alert_id = recent_alts[0]["id"]

        while True:
            time.sleep(1.0)
            conn = database.get_db_connection()
            cursor = conn.cursor()

            # Poll for new events
            cursor.execute("SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT 20", (last_event_id,))
            new_events = [dict(r) for r in cursor.fetchall()]

            # Poll for new alerts
            cursor.execute("SELECT * FROM alerts WHERE id > ? ORDER BY id ASC LIMIT 10", (last_alert_id,))
            new_alerts = [dict(r) for r in cursor.fetchall()]

            if new_events:
                last_event_id = new_events[-1]["id"]
                yield f"event: new_events\ndata: {json.dumps(new_events)}\n\n"

            if new_alerts:
                last_alert_id = new_alerts[-1]["id"]
                yield f"event: new_alerts\ndata: {json.dumps(new_alerts)}\n\n"

            # Always emit periodic heartbeat with fresh KPI metrics
            metrics = database.get_dashboard_metrics()
            yield f"event: metrics_update\ndata: {json.dumps(metrics)}\n\n"

    return Response(event_stream(), mimetype="text/event-stream")


if __name__ == "__main__":
    # Start auto-unban daemon
    responder.start_auto_unban_daemon()
    app.run(host=config.WEB_HOST, port=config.WEB_PORT, debug=False)
