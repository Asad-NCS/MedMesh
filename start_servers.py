"""Start all MedMesh hospital servers and keep them running.

Run this in Terminal 1. Then send queries from Terminal 2 using client.py.

Usage:
    python start_servers.py
    python start_servers.py --no-overlap-guard    # disable attack protection
Press Ctrl+C to stop all servers.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

os.system("")  # enable ANSI colors on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

HERE = Path(__file__).parent

GREEN = "\033[92m"
RED   = "\033[91m"
CYAN  = "\033[96m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
RESET = "\033[0m"

SITES = [
    {"port": 8000, "data": "site_a.csv", "name": "site_a", "label": "Hospital A -- NUMS Islamabad  ", "patients": 120},
    {"port": 8001, "data": "site_b.csv", "name": "site_b", "label": "Hospital B -- Shifa Hospital  ", "patients": 80},
    {"port": 8002, "data": "site_c.csv", "name": "site_c", "label": "Hospital C -- PIMS Rawalpindi ", "patients": 60},
]


def wait_for_server(port, key="key_ana_secure_001", timeout=15):
    url = f"http://127.0.0.1:{port}/query"
    payload = json.dumps({"query": "count"}).encode("utf-8")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json", "X-API-Key": key},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2):
                return True
        except Exception:
            time.sleep(0.3)
    return False


def start_server(site, no_guard):
    cmd = [
        sys.executable, str(HERE / "server.py"),
        "--port", str(site["port"]),
        "--data", str(HERE / site["data"]),
        "--site-name", site["name"],
    ]
    if no_guard:
        cmd.append("--no-overlap-guard")
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def main():
    parser = argparse.ArgumentParser(description="Start MedMesh hospital servers")
    parser.add_argument("--no-overlap-guard", action="store_true",
                        help="Disable the differencing-attack guard on all sites")
    args = parser.parse_args()

    # Ensure site data exists.
    missing = [s["data"] for s in SITES if not (HERE / s["data"]).exists()]
    if missing:
        print("Generating site data files...")
        subprocess.run([sys.executable, str(HERE / "make_sites.py")], check=True)

    print()
    print(f"{BOLD}{CYAN}+--------------------------------------------+{RESET}")
    print(f"{BOLD}{CYAN}|   MedMesh — Hospital Servers Starting      |{RESET}")
    print(f"{BOLD}{CYAN}+--------------------------------------------+{RESET}")
    print()

    procs = []
    for site in SITES:
        proc = start_server(site, args.no_overlap_guard)
        procs.append(proc)

    # Wait for each server.
    all_ok = True
    for site in SITES:
        ok = wait_for_server(site["port"])
        status = f"{GREEN}ONLINE{RESET}" if ok else f"{RED}FAILED{RESET}"
        print(f"  {status}  {site['label']}  {CYAN}{site['patients']}{RESET} patients  "
              f"port {site['port']}")
        if not ok:
            all_ok = False

    if not all_ok:
        print(f"\n{RED}One or more servers failed to start.{RESET}")
        for p in procs:
            p.terminate()
        sys.exit(1)

    print()
    print(f"{DIM}  API key for queries: key_ana_secure_001{RESET}")
    print()
    print(f"{BOLD}  Open a second terminal and try:{RESET}")
    print()
    print(f"  {CYAN}python client.py \"mean age\" --sites 8000 8001 8002 --key key_ana_secure_001{RESET}")
    print(f"  {CYAN}python client.py \"count by sex\" --sites 8000 8001 8002 --key key_ana_secure_001{RESET}")
    print(f"  {CYAN}python client.py \"get all records\" --key key_ana_secure_001{RESET}")
    print(f"  {CYAN}python client.py \"mean age where diagnosis = rare\" --key key_ana_secure_001{RESET}")
    print(f"  {CYAN}python client.py \"mean age\"{RESET}  {DIM}(no key -- should deny){RESET}")
    print()
    print(f"{DIM}  Press Ctrl+C to stop all servers.{RESET}")
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{DIM}  Stopping servers...{RESET}")
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        time.sleep(1)
        print(f"  {GREEN}All servers stopped.{RESET}\n")


if __name__ == "__main__":
    main()
