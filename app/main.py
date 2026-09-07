"""
PQ-VPN Desktop Application Launcher.

Cross-platform entry point that starts the FastAPI backend server on a
background thread and launches a native PyWebView desktop window pointing
to the dashboard UI.

Supports three modes:
    - Desktop (default):  PyWebView native window + Uvicorn backend
    - Web-only (--web):   Uvicorn server only, open browser manually
    - CLI mode (--cli):   Headless backend for scripted / Docker usage

Usage:
    python app/main.py              # Desktop window
    python app/main.py --web        # Web server only
    python app/main.py --cli        # Headless CLI mode

Requirements:
    - pywebview >= 4.0  (desktop mode)
    - uvicorn           (all modes)
    - fastapi           (all modes)
"""

from __future__ import annotations

import os
import sys
import time
import signal
import logging
import argparse
import threading
from pathlib import Path

# Add project root to path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

APP_TITLE = "PQ-VPN — Post-Quantum Secure"
APP_VERSION = "1.0.0"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
WINDOW_WIDTH = 1280
WINDOW_HEIGHT = 860


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging(verbose: bool = False) -> None:
    """Configure application logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s │ %(name)-18s │ %(levelname)-7s │ %(message)s",
        datefmt="%H:%M:%S",
    )
    # Suppress noisy uvicorn access logs in non-verbose mode
    if not verbose:
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


logger = logging.getLogger("pqvpn.launcher")


# ─────────────────────────────────────────────────────────────────────────────
# Uvicorn Server Thread
# ─────────────────────────────────────────────────────────────────────────────

_server_thread: threading.Thread | None = None
_server_started = threading.Event()


def _run_uvicorn(host: str, port: int) -> None:
    """Run the Uvicorn ASGI server in the current thread."""
    import uvicorn

    config = uvicorn.Config(
        app="app.backend.api:app",
        host=host,
        port=port,
        log_level="info",
        access_log=False,
    )
    server = uvicorn.Server(config)

    # Signal that the server is about to start
    _server_started.set()

    server.run()


def start_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Start the Uvicorn server on a background daemon thread."""
    global _server_thread
    _server_thread = threading.Thread(
        target=_run_uvicorn,
        args=(host, port),
        name="uvicorn-server",
        daemon=True,
    )
    _server_thread.start()
    _server_started.wait(timeout=10.0)
    logger.info("Backend server started at http://%s:%d", host, port)


# ─────────────────────────────────────────────────────────────────────────────
# Desktop Mode (PyWebView)
# ─────────────────────────────────────────────────────────────────────────────

def launch_desktop(host: str, port: int) -> None:
    """
    Launch the PQ-VPN desktop application window.

    Uses PyWebView to create a native frameless window embedding the
    dashboard UI. On Windows, this uses Edge Webview2; on Linux, it
    uses WebKitGTK or QtWebEngine.
    """
    try:
        import webview
    except ImportError:
        logger.error(
            "pywebview is not installed. Install with: pip install pywebview"
        )
        logger.info("Falling back to web-only mode...")
        launch_web(host, port)
        return

    # Start backend server
    start_server(host, port)

    # Small delay to let the server fully initialize
    time.sleep(1.0)

    url = f"http://{host}:{port}"
    logger.info("Launching desktop window → %s", url)

    # Create native window
    window = webview.create_window(
        title=APP_TITLE,
        url=url,
        width=WINDOW_WIDTH,
        height=WINDOW_HEIGHT,
        resizable=True,
        min_size=(960, 640),
        background_color="#0B0F19",
    )

    # Start the webview event loop (blocks until window is closed)
    webview.start(
        debug=False,
        http_server=False,
    )

    logger.info("Desktop window closed. Shutting down...")


# ─────────────────────────────────────────────────────────────────────────────
# Web-Only Mode
# ─────────────────────────────────────────────────────────────────────────────

def launch_web(host: str, port: int) -> None:
    """
    Start the server and open the dashboard in the default web browser.
    """
    import webbrowser

    start_server(host, port)
    time.sleep(1.0)

    url = f"http://{host}:{port}"
    logger.info("Opening browser → %s", url)
    webbrowser.open(url)

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        logger.info("Shutting down...")


# ─────────────────────────────────────────────────────────────────────────────
# CLI (Headless) Mode
# ─────────────────────────────────────────────────────────────────────────────

def launch_cli(host: str, port: int) -> None:
    """
    Start the server in headless mode (no GUI, no browser).
    Useful for Docker containers, CI, or scripted automation.
    """
    import uvicorn

    logger.info("Starting PQ-VPN in headless CLI mode...")
    uvicorn.run(
        "app.backend.api:app",
        host=host,
        port=port,
        log_level="info",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Parse arguments and launch the appropriate application mode."""
    parser = argparse.ArgumentParser(
        description="PQ-VPN — Post-Quantum Secure VPN Desktop Application",
    )
    parser.add_argument(
        "--web", action="store_true",
        help="Web-only mode: start server and open browser (no desktop window)",
    )
    parser.add_argument(
        "--cli", action="store_true",
        help="Headless CLI mode: start server without GUI",
    )
    parser.add_argument(
        "--host", type=str, default=DEFAULT_HOST,
        help=f"Server bind address (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"Server port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug-level logging",
    )

    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("bind management to loopback; use an explicitly configured TLS reverse proxy for remote access")
    _setup_logging(verbose=args.verbose)

    logger.info("━" * 60)
    logger.info("  PQ-VPN v%s — Hybrid Classical & Post-Quantum VPN", APP_VERSION)
    logger.info("━" * 60)

    if args.cli:
        launch_cli(args.host, args.port)
    elif args.web:
        launch_web(args.host, args.port)
    else:
        launch_desktop(args.host, args.port)


if __name__ == "__main__":
    main()
