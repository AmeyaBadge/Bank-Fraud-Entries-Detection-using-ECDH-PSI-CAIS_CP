"""
start.py — Single-command launcher for the PSI Platform V2.0
Starts all three nodes (Coordinator, Bank A, Bank B) in parallel
and streams their combined logs to one terminal with color-coded prefixes.

Usage:
    python start.py

Press Ctrl+C to stop all services cleanly.
"""

import subprocess
import threading
import sys
import io
import os
import signal
import time

# ─── ANSI color codes ─────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
COLORS = {
    "coordinator": "\033[96m",   # Cyan
    "bank_a":      "\033[93m",   # Yellow
    "bank_b":      "\033[92m",   # Green
}

LABELS = {
    "coordinator": " COORDINATOR :5000 ",
    "bank_a":      "   BANK  A   :5001 ",
    "bank_b":      "   BANK  B   :5002 ",
}

# ─── Services to launch ───────────────────────────────────────────────────────
SERVICES = [
    {"name": "coordinator", "module": "coordinator.app"},
    {"name": "bank_a",      "module": "bank_a.app"},
    {"name": "bank_b",      "module": "bank_b.app"},
]

_processes = []
_stop_event = threading.Event()


def stream_output(proc, name):
    """Read lines from a subprocess and print them with a colored label."""
    color = COLORS[name]
    label = LABELS[name]
    prefix = f"{BOLD}{color}[{label}]{RESET} "
    try:
        for line in iter(proc.stdout.readline, b""):
            if _stop_event.is_set():
                break
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                print(f"{prefix}{text}", flush=True)
    except Exception:
        pass


def launch_service(service):
    """Launch a single uvicorn service as a subprocess."""
    name   = service["name"]
    module = service["module"]
    color  = COLORS[name]
    label  = LABELS[name]

    cmd = [sys.executable, "-m", module]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,      # merge stderr into stdout
        cwd=os.path.dirname(os.path.abspath(__file__)),
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    _processes.append(proc)

    t = threading.Thread(target=stream_output, args=(proc, name), daemon=True)
    t.start()
    return proc


def shutdown_all(sig=None, frame=None):
    """Terminate all child processes on Ctrl+C."""
    if _stop_event.is_set():
        return
    _stop_event.set()
    print(f"\n{BOLD}\033[91m[  LAUNCHER  ] Shutting down all services...{RESET}")
    for proc in _processes:
        try:
            proc.terminate()
        except Exception:
            pass
    # Give them 3 seconds to exit gracefully, then force-kill
    time.sleep(3)
    for proc in _processes:
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass
    print(f"{BOLD}\033[91m[  LAUNCHER  ] All services stopped.{RESET}")
    sys.exit(0)


def main():
    # Force UTF-8 output on Windows so ANSI / Unicode prints cleanly
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    # Enable ANSI on Windows
    if sys.platform == "win32":
        os.system("color")

    SEP = "-" * 60

    # ── Banner ────────────────────────────────────────────────────────────────
    print()
    print(f"{BOLD}\033[95m{SEP}{RESET}")
    print(f"{BOLD}\033[95m   PSI Platform V2.0 -- Starting all nodes...{RESET}")
    print(f"{BOLD}\033[95m{SEP}{RESET}")
    print(f"  {COLORS['coordinator']}{BOLD}Coordinator{RESET}  ->  http://127.0.0.1:5000")
    print(f"  {COLORS['bank_a']}{BOLD}Bank A{RESET}       ->  http://127.0.0.1:5001  (login: admin / admin123)")
    print(f"  {COLORS['bank_b']}{BOLD}Bank B{RESET}       ->  http://127.0.0.1:5002  (login: admin / admin123)")
    print(f"{BOLD}\033[95m{SEP}{RESET}")
    print(f"  Press {BOLD}Ctrl+C{RESET} to stop all services.\n")

    # Register Ctrl+C handler
    signal.signal(signal.SIGINT,  shutdown_all)
    signal.signal(signal.SIGTERM, shutdown_all)

    # ── Launch all three services ─────────────────────────────────────────────
    for service in SERVICES:
        launch_service(service)
        time.sleep(0.5)   # small stagger so ports bind cleanly

    # ── Keep main thread alive ────────────────────────────────────────────────
    try:
        while not _stop_event.is_set():
            # Check if any service crashed unexpectedly
            for proc in _processes:
                if proc.poll() is not None:
                    name = SERVICES[_processes.index(proc)]["name"]
                    print(f"\n{BOLD}\033[91m[  LAUNCHER  ] '{name}' exited with code {proc.returncode}!{RESET}")
                    shutdown_all()
            time.sleep(2)
    except KeyboardInterrupt:
        shutdown_all()


if __name__ == "__main__":
    main()
