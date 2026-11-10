"""
PySIEM-Lite: Unified System Orchestrator
Coordinates the log ingestion tailers, sliding-window correlation engine,
active defense mitigation daemon, and the Flask SOC web console.
"""

import sys
import os
import signal
import time
import argparse
import logging
from threading import Thread

import config
import database
from responder import responder
from ingestor import IngestionManager
from app import app

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("PySIEM-Main")


def print_banner():
    banner = r"""
  ____        ____ ___ _____ __  __     _     _ _       
 |  _ \ _   _/ ___|_ _| ____|  \/  |   | |   (_) |_ ___ 
 | |_) | | | \___ \| ||  _| | |\/| |---| |   | | __/ _ \
 |  __/| |_| |___) | || |___| |  | |---| |___| | ||  __/
 |_|    \__, |____/___|_____|_|  |_|   |_____|_|\__\___|
        |___/   Autonomous Linux SIEM & Active Defense   
    """
    print(banner)
    print("  Version: 1.0.0 | Platform: Kali Linux / Debian")
    print("  Author:  Cyber Security Architecture & Engineering")
    print("=" * 65)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="PySIEM-Lite: High-Performance Lightweight Linux SIEM & Active Defense Engine."
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use mock logs in ./mock_logs/ instead of live /var/log paths (ideal for demos & non-root runs)."
    )
    parser.add_argument(
        "--auth-log",
        type=str,
        default=None,
        help="Override path to system authentication log."
    )
    parser.add_argument(
        "--web-log",
        type=str,
        default=None,
        help="Override path to Apache access log."
    )
    parser.add_argument(
        "--backfill",
        action="store_true",
        help="Parse existing log contents from top of file before live streaming."
    )
    parser.add_argument(
        "--no-auto-block",
        action="store_true",
        help="Disable automatic iptables DROP execution (alerts will still be raised)."
    )
    parser.add_argument(
        "--port",
        type=int,
        default=config.WEB_PORT,
        help=f"Web console listening port (default: {config.WEB_PORT})."
    )
    parser.add_argument(
        "--host",
        type=str,
        default=config.WEB_HOST,
        help=f"Web console listening host (default: {config.WEB_HOST})."
    )
    return parser.parse_args()


def main():
    print_banner()
    args = parse_arguments()

    # Apply Configuration Overrides
    if args.no_auto_block:
        config.ENABLE_AUTO_BLOCK = False
        logger.info("[ACTIVE DEFENSE] Auto-blocking is DISABLED by CLI flag.")
    else:
        logger.info("[ACTIVE DEFENSE] Auto-blocking is ENABLED (iptables DROP).")

    auth_path = args.auth_log
    web_path = args.web_log

    if args.mock:
        auth_path = config.MOCK_AUTH_LOG
        web_path = config.MOCK_APACHE_LOG
        logger.info(f"[MODE] Running in MOCK LOG MODE (using {config.MOCK_LOG_DIR})")

    # Step 1: Initialize SQLite Database
    logger.info("Initializing SQLite database engine...")
    database.init_db()

    # Step 2: Start Active Defense Auto-Unban Daemon
    logger.info("Starting active defense auto-unban monitor...")
    responder.start_auto_unban_daemon()

    # Step 3: Start Log Ingestion Tailers
    logger.info("Initializing log tailers and regex normalizers...")
    ingestor = IngestionManager(
        auth_log_path=auth_path,
        apache_log_path=web_path,
        read_from_start=args.backfill
    )
    ingestor.start()

    # Step 4: Graceful Shutdown Handlers
    def handle_exit(signum, frame):
        logger.info("\nShutdown signal received. Terminating PySIEM-Lite services gracefully...")
        ingestor.stop()
        responder.stop_auto_unban_daemon()
        logger.info("PySIEM-Lite stopped successfully.")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    # Step 5: Launch Web Console
    logger.info(f"Launching SOC Analyst Web Console on http://{args.host}:{args.port}")
    print(f"\n[+] SOC Analyst Dashboard accessible at: http://localhost:{args.port}")
    print("[+] Press Ctrl+C at any time to shut down.\n")

    try:
        app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
    except Exception as ex:
        logger.error(f"Web server error: {ex}")
    finally:
        ingestor.stop()
        responder.stop_auto_unban_daemon()


if __name__ == "__main__":
    main()
