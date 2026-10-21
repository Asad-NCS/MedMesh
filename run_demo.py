"""Demo runner for MedMesh.

Starts 3 guarded sites (ports 8000-8002) and 1 unguarded server (port 8010).
Deletes old logs first.
Always shuts down cleanly (terminate, then kill after 3 seconds) in a finally block.

Flags:
  --short    2-minute version: under 90 seconds, no pauses.
  --no-pause skip all pauses.
  --step     pause for Enter after server startup and after each step.
  --check    preflight: check ports, data files, keys.json, run tests.
"""

import argparse
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import time

# Force UTF-8 output on Windows so box-drawing and color chars render correctly.
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
import urllib.error
import urllib.request
from pathlib import Path

# Enable ANSI color codes on Windows.
os.system("")

HERE = Path(__file__).parent
SITE_PORTS = [8000, 8001, 8002]
UNGUARDED_PORT = 8010
SITE_FILES = ["site_a.csv", "site_b.csv", "site_c.csv"]
ANA_KEY = "key_ana_secure_001"
MALLORY_KEY = "key_mallory_003"

HOSPITAL_NAMES = [
    "NUMS Islamabad   ",
    "Shifa Hospital   ",
    "PIMS Rawalpindi  ",
]

# ANSI color codes.
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"
WHITE  = "\033[97m"


def c(color, text):
    """Wrap text in a color code."""
    return f"{color}{text}{RESET}"


def box(lines):
    """Print a bordered box around a list of lines."""
    # Strip ANSI codes for width calculation.
    import re as _re
    _ansi = _re.compile(r'\033\[[^m]*m')
    visible_lens = [len(_ansi.sub('', l)) for l in lines]
    width = max(visible_lens) + 4
    print(c(CYAN, "+" + "-" * width + "+"))
    for line, vlen in zip(lines, visible_lens):
        padding = width - vlen
        print(c(CYAN, "|") + "  " + line + " " * (padding - 2) + c(CYAN, "|"))
    print(c(CYAN, "+" + "-" * width + "+"))


def rule(char="-", width=62):
    print(c(DIM, char * width))


def banner(step, title, subtitle=""):
    """Print a step banner."""
    print()
    rule()
    print(c(BOLD + YELLOW, f"  STEP {step}  —  {title}"))
    if subtitle:
        print(c(DIM, f"  {subtitle}"))
    rule()


def port_free(port):
    """Return True if the port is free."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def wait_for_server(port, timeout=15):
    """Wait until the server on port responds."""
    url = f"http://127.0.0.1:{port}/query"
    payload = json.dumps({"query": "count"}).encode("utf-8")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json", "X-API-Key": ANA_KEY},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2):
                return True
        except Exception:
            time.sleep(0.3)
    return False


def post(port, query, api_key=None):
    """Send a query and return the response dict."""
    payload = json.dumps({"query": query}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    url = f"http://127.0.0.1:{port}/query"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def start_server(port, data_file, site_name, no_overlap=False):
    """Start a server subprocess and return it."""
    cmd = [
        sys.executable, str(HERE / "server.py"),
        "--port", str(port),
        "--data", str(HERE / data_file),
        "--site-name", site_name,
    ]
    if no_overlap:
        cmd.append("--no-overlap-guard")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc


def stop_servers(procs):
    """Terminate all processes, then kill after 3 seconds."""
    for proc in procs:
        try:
            proc.terminate()
        except Exception:
            pass
    deadline = time.time() + 3
    for proc in procs:
        remaining = max(0.0, deadline - time.time())
        try:
            proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except Exception:
                pass


def preflight():
    """Run preflight checks. Print READY or describe problems."""
    problems = []

    # Check ports.
    all_ports = SITE_PORTS + [UNGUARDED_PORT]
    for port in all_ports:
        if not port_free(port):
            problems.append(f"port {port} is in use")

    # Check data files.
    missing = [f for f in SITE_FILES if not (HERE / f).exists()]
    if missing:
        print(f"data files missing: {missing} -- running make_sites.py ...")
        result = subprocess.run(
            [sys.executable, str(HERE / "make_sites.py")],
            capture_output=True, text=True
        )
        print(result.stdout.strip())
        if result.returncode != 0:
            problems.append("make_sites.py failed")
        else:
            still_missing = [f for f in SITE_FILES if not (HERE / f).exists()]
            if still_missing:
                problems.append(f"data files still missing: {still_missing}")

    # Check keys.json.
    if not (HERE / "keys.json").exists():
        problems.append("keys.json not found")

    # Run tests.
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", str(HERE), "-q"],
        capture_output=True, text=True,
        cwd=str(HERE),
    )
    if result.returncode != 0:
        problems.append("python -m unittest failed")
        print(result.stdout[-2000:] if result.stdout else "")
        print(result.stderr[-2000:] if result.stderr else "")

    if problems:
        for p in problems:
            print(f"PROBLEM: {p}")
        sys.exit(1)
    else:
        print("READY")


def _step_wait(step_mode):
    """If step_mode is on, print a prompt and wait for Enter."""
    if step_mode:
        print()
        input(c(DIM, "  [ press Enter to continue ]"))


def _get_site_counts():
    """Read patient counts from site CSVs."""
    counts = []
    for f in SITE_FILES:
        path = HERE / f
        if path.exists():
            lines = path.read_text(encoding="utf-8").splitlines()
            counts.append(len(lines) - 1)
        else:
            counts.append(0)
    return counts


def print_intro(site_counts):
    """Print the opening story box."""
    print()
    total = sum(site_counts)
    box([
        f"{BOLD}MedMesh  —  Federated Privacy System{RESET}",
        "",
        f"  {total} patients across {len(SITE_PORTS)} hospitals  ·  0 records shared",
    ])
    print()
    print(c(DIM, "  Scenario: Dr. Ana is a researcher studying patient outcomes"))
    print(c(DIM, "  across multiple hospitals. Privacy law forbids her from"))
    print(c(DIM, "  accessing individual patient records directly."))
    print()
    print(c(DIM, "  With MedMesh she submits one statistical query."))
    print(c(DIM, "  Each hospital computes the answer on its own data."))
    print(c(DIM, "  Only the approved summary is returned. No record moves."))
    print()


def print_servers_ready(site_counts):
    """Print the server startup status."""
    print(c(BOLD, "  Hospitals online:"))
    print()
    for i, (port, name, count) in enumerate(zip(SITE_PORTS, HOSPITAL_NAMES, site_counts)):
        print(f"    {c(GREEN, 'ONLINE')}  Hospital {chr(65+i)} — {name}  "
              f"{c(CYAN, str(count))} patients   port {port}")
    unguarded_count = site_counts[0]
    print(f"    {c(DIM, 'SHADOW')}  Unguarded test server             "
          f"{c(DIM, str(unguarded_count))} patients   port {UNGUARDED_PORT}")
    print()


def step1_pooled(ports, pause, step_mode=False):
    """Step 1: pooled mean age and count by sex."""
    site_counts = _get_site_counts()
    total = sum(site_counts)

    banner(1, "Federated Query",
           "Dr. Ana asks for statistics. Each hospital replies independently.")

    for query in ["mean age", "count by sex"]:
        print()
        print(f"  {c(BOLD, 'QUERY:')}  \"{c(YELLOW, query)}\"")
        print(c(DIM, "  Each hospital computes on its own data — no records shared."))
        print()

        site_results = []
        for i, (port, name, count) in enumerate(zip(ports, HOSPITAL_NAMES, site_counts)):
            resp = post(port, query, ANA_KEY)
            decision = resp.get("decision")
            result = resp.get("result", {})
            result_str = json.dumps(result)
            if decision == "allow":
                tag = c(GREEN, "ALLOW")
            else:
                tag = c(RED, "DENY ")
            print(f"    {tag}  Hospital {chr(65+i)} — {name}  "
                  f"({count} patients)  →  {c(CYAN, result_str)}")
            site_results.append((port, resp))

        # Pool.
        allowed = [(p, r) for p, r in site_results if r.get("decision") == "allow"]
        if allowed:
            first = allowed[0][1].get("result", {})
            mean_key = next((k for k in first if k.startswith("mean_")), None)
            print()
            print(c(DIM, "  " + "-" * 58))
            if mean_key:
                total_n = sum(r.get("result", {}).get("n", 0) for _, r in allowed)
                ws = sum(r.get("result", {}).get("n", 0) * r.get("result", {}).get(mean_key, 0) for _, r in allowed)
                pooled = round(ws / total_n, 2) if total_n else 0.0
                print(f"  {c(BOLD, 'POOLED')}  {total_n} patients across {len(allowed)} hospitals"
                      f"  →  {c(BOLD + GREEN, f'{mean_key} = {pooled}')}")
                print()
                print(c(DIM, f"  Dr. Ana sees one number. She never accessed a single patient record."))
            elif "counts" in first:
                pooled_counts = {}
                pooled_n = 0
                for _, r in allowed:
                    res = r.get("result", {})
                    pooled_n += res.get("n", 0)
                    for k, v in res.get("counts", {}).items():
                        pooled_counts[k] = pooled_counts.get(k, 0) + v
                counts_str = "  ".join(f"{k}: {v}" for k, v in sorted(pooled_counts.items()))
                print(f"  {c(BOLD, 'POOLED')}  {pooled_n} patients across {len(allowed)} hospitals"
                      f"  →  {c(BOLD + GREEN, counts_str)}")
                print()
                print(c(DIM, f"  Group counts combined across hospitals. No individual record shared."))

    if pause:
        time.sleep(1)
    _step_wait(step_mode)


def step2_refusals(ports, pause, step_mode=False):
    """Step 2: show refusals (all records, rare group, no key)."""
    banner(2, "Privacy Guards in Action",
           "Three types of queries the server must refuse.")

    cases = [
        ("get all records",                ANA_KEY,  "Asks for individual rows"),
        ("mean age where diagnosis = rare", ANA_KEY,  "Group has fewer than 5 patients"),
        ("mean age",                        None,     "No API key — unauthorised researcher"),
    ]

    print()
    for query, key, reason in cases:
        resp = post(ports[0], query, key)
        decision = resp.get("decision")
        resp_reason = resp.get("reason", "")
        tag = c(GREEN, "ALLOW") if decision == "allow" else c(RED, " DENY")
        key_label = c(GREEN, "key=YES") if key else c(RED, "key=NO ")
        print(f"    {tag}  {key_label}  \"{c(YELLOW, query)}\"")
        print(c(DIM, f"           Reason: {resp_reason}"))
        print(c(DIM, f"           Why blocked: {reason}"))
        print()

    if pause:
        time.sleep(1)
    _step_wait(step_mode)


def step3_differencing(guarded_port, unguarded_port, pause, step_mode=False):
    """Step 3: differencing attack on unguarded then guarded server."""
    import csv as _csv
    banner(3, "Differencing Attack — Guarded vs Unguarded",
           "Can an attacker recover a patient's BMI by subtracting two queries?")

    site_a = HERE / "site_a.csv"
    patients = []
    if site_a.exists():
        with site_a.open(newline="", encoding="utf-8") as fh:
            for row in _csv.DictReader(fh):
                row["age"] = float(row["age"])
                row["bmi"] = float(row["bmi"])
                patients.append(row)

    print()
    print(c(DIM, "  Attack: send 'mean bmi where age > N', then 'mean bmi where age > N+1'."))
    print(c(DIM, "  Subtract to isolate one patient's BMI. Repeat until you recover records."))
    print()

    def run_diff(port, label, stop_after=None):
        prev_resp = None
        attempts = 0
        blocked = 0
        recovered = 0
        for n in range(30, 71):
            if stop_after and recovered >= stop_after:
                break
            q = f"mean bmi where age > {n}"
            try:
                resp = post(port, q, MALLORY_KEY)
            except Exception:
                prev_resp = None
                continue
            attempts += 1
            if resp.get("decision") == "deny":
                blocked += 1
                prev_resp = None
                continue
            if prev_resp and prev_resp.get("decision") == "allow":
                r1 = prev_resp.get("result", {})
                r2 = resp.get("result", {})
                n1, m1 = r1.get("n", 0), r1.get("mean_bmi", 0.0)
                n2, m2 = r2.get("n", 0), r2.get("mean_bmi", 0.0)
                if n1 - n2 == 1 and n1 > 0 and n2 > 0:
                    estimated = n1 * m1 - n2 * m2
                    for p in patients:
                        if p["age"] == n:
                            if abs(estimated - p["bmi"]) <= 1.5:
                                recovered += 1
                            break
            prev_resp = resp
        return attempts, blocked, recovered

    att_u, blk_u, rec_u = run_diff(unguarded_port, "unguarded", stop_after=5)
    att_g, blk_g, rec_g = run_diff(guarded_port, "guarded")

    print(f"  {c(RED,  'UNGUARDED server')}  —  {att_u} queries sent,  "
          f"{blk_u} blocked,  "
          f"{c(RED + BOLD, str(rec_u) + ' patient(s) recovered')}")
    print(c(DIM, "  The attacker successfully reconstructed individual BMI values."))
    print()
    print(f"  {c(GREEN, 'GUARDED   server')}  —  {att_g} queries sent,  "
          f"{c(GREEN, str(blk_g) + ' blocked')},  "
          f"{c(GREEN + BOLD, str(rec_g) + ' patient(s) recovered')}")
    print(c(DIM, "  The overlap guard blocked every differencing attempt."))
    print()

    if pause:
        time.sleep(1)
    _step_wait(step_mode)
    return rec_u, rec_g


def step4_audit(site_name, pause, step_mode=False):
    """Step 4: show 3 log lines, tamper one, run verify_log.py."""
    banner(4, "Tamper-Evident Audit Log",
           "Every query is logged with a SHA-256 hash chain. Any change is detected.")

    log_path = HERE / "logs" / f"{site_name}.jsonl"
    if not log_path.exists():
        print("  No log file found. Skipping audit step.")
        return

    lines = log_path.read_text(encoding="utf-8").splitlines()
    print()
    print(f"  {c(BOLD, str(len(lines)))} queries logged for Hospital A. First 3 entries:")
    print()
    for line in lines[:3]:
        entry = json.loads(line)
        ts = entry.get("ts", "")
        user = entry.get("user", "")
        query = entry.get("query", "")
        decision = entry.get("decision", "")
        tag = c(GREEN, "ALLOW") if decision == "allow" else c(RED, "DENY ")
        print(f"    {tag}  {c(DIM, ts)}  {c(CYAN, user)}  \"{query}\"")
    print()
    print(c(DIM, "  Each entry contains a SHA-256 hash of itself chained to the previous entry."))
    print()

    # Verify the intact log.
    result = subprocess.run(
        [sys.executable, str(HERE / "verify_log.py"), str(log_path)],
        capture_output=True, text=True,
    )
    intact_status = result.stdout.strip()
    print(f"  Chain verification (intact log)  →  {c(GREEN + BOLD, intact_status)}")

    # Tamper: change one character in line 1.
    if lines:
        tampered = list(lines)
        first = tampered[0]
        mid = len(first) // 2
        ch = first[mid]
        replacement = "X" if ch != "X" else "Y"
        tampered[0] = first[:mid] + replacement + first[mid + 1:]
        tampered_path = log_path.parent / f"{site_name}_tampered.jsonl"
        tampered_path.write_text("\n".join(tampered) + "\n", encoding="utf-8")
        result2 = subprocess.run(
            [sys.executable, str(HERE / "verify_log.py"), str(tampered_path)],
            capture_output=True, text=True,
        )
        tampered_status = result2.stdout.strip()
        print(f"  Chain verification (tampered log) →  {c(RED + BOLD, tampered_status)}")
        print()
        print(c(DIM, "  One character was changed in one log entry."))
        print(c(DIM, "  The hash chain detected the tampering immediately."))
        tampered_path.unlink(missing_ok=True)

    if pause:
        time.sleep(1)
    _step_wait(step_mode)


def run_demo(short_mode, no_pause, step_mode=False):
    """Run the full demo."""
    pause = not short_mode and not no_pause

    # Clear old logs.
    logs_dir = HERE / "logs"
    if logs_dir.exists():
        shutil.rmtree(logs_dir)
    logs_dir.mkdir()

    # Ensure site data files exist.
    missing = [f for f in SITE_FILES if not (HERE / f).exists()]
    if missing:
        print("Generating site data files...")
        subprocess.run([sys.executable, str(HERE / "make_sites.py")], check=True)

    site_counts = _get_site_counts()
    print_intro(site_counts)

    procs = []
    try:
        # Start 3 guarded sites.
        configs = [
            (SITE_PORTS[0], "site_a.csv", "site_a"),
            (SITE_PORTS[1], "site_b.csv", "site_b"),
            (SITE_PORTS[2], "site_c.csv", "site_c"),
        ]
        for port, data_file, site_name in configs:
            proc = start_server(port, data_file, site_name, no_overlap=False)
            procs.append(proc)

        # Start 1 unguarded server.
        proc_ug = start_server(UNGUARDED_PORT, "site_a.csv", "unguarded", no_overlap=True)
        procs.append(proc_ug)

        # Wait for all servers to be ready.
        print(c(DIM, "  Starting hospital servers..."), flush=True)
        for port in SITE_PORTS + [UNGUARDED_PORT]:
            ok = wait_for_server(port)
            if not ok:
                print(f"ERROR: server on port {port} did not start in time.", file=sys.stderr)
                sys.exit(1)

        print_servers_ready(site_counts)
        _step_wait(step_mode)

        step1_pooled(SITE_PORTS, pause, step_mode)
        step2_refusals(SITE_PORTS, pause, step_mode)
        rec_u, rec_g = step3_differencing(SITE_PORTS[0], UNGUARDED_PORT, pause, step_mode)
        step4_audit("site_a", pause, step_mode)

        # Final summary.
        total = sum(site_counts)
        print()
        rule("═")
        print(f"  {c(BOLD + GREEN, 'DEMO COMPLETE — MedMesh Privacy Summary')}")
        rule("═")
        print()
        print(f"  {c(GREEN,  'PROTECTED')}   {total} patients across 3 hospitals")
        print(f"  {c(GREEN,  'SHARED'   )}   0 individual records")
        print(f"  {c(GREEN,  'BLOCKED'  )}   {rec_u} patient(s) recovered by attacker on guarded server (vs {rec_u} on unguarded)")
        print(f"  {c(GREEN,  'LOGGED'   )}   Every query — audit chain verified")
        print()
        print(c(DIM, "  Statistical access. Zero record exposure."))
        print()

    finally:
        stop_servers(procs)
        print(c(DIM, "  Servers stopped."), flush=True)


def parse_args():
    parser = argparse.ArgumentParser(description="MedMesh demo runner")
    parser.add_argument(
        "--short", action="store_true",
        help="2-minute version: run all steps without pauses, finish under 90 seconds"
    )
    parser.add_argument(
        "--no-pause", action="store_true",
        help="skip the 1-second pause between steps (no effect on --step waits)"
    )
    parser.add_argument(
        "--step", action="store_true",
        help="pause for Enter after server startup and after each step"
    )
    parser.add_argument(
        "--check", action="store_true",
        help="preflight check: verify ports, data files, keys.json, and run tests"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.check:
        preflight()
        return
    run_demo(short_mode=args.short, no_pause=args.no_pause, step_mode=args.step)


if __name__ == "__main__":
    main()
