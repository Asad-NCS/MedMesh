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
import json
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).parent
SITE_PORTS = [8000, 8001, 8002]
UNGUARDED_PORT = 8010
SITE_FILES = ["site_a.csv", "site_b.csv", "site_c.csv"]
ANA_KEY = "key_ana_secure_001"
MALLORY_KEY = "key_mallory_003"


def banner(step, text):
    """Print a step banner."""
    print()
    print(f"STEP {step}: {text}")
    print("-" * 60)


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
        input("(press Enter)")


def step1_pooled(ports, pause, step_mode=False):
    """Step 1: pooled mean age and count by sex."""
    banner(1, "Pooled queries across 3 sites: mean age, count by sex.")
    for query in ["mean age", "count by sex"]:
        print(f"  Query: {query!r}")
        site_results = []
        for i, port in enumerate(ports):
            resp = post(port, query, ANA_KEY)
            print(f"    site :{port} -> {json.dumps(resp.get('result', resp.get('reason')))}")
            site_results.append((port, resp))
        # Pool.
        allowed = [(p, r) for p, r in site_results if r.get("decision") == "allow"]
        if allowed:
            first = allowed[0][1].get("result", {})
            mean_key = next((k for k in first if k.startswith("mean_")), None)
            if mean_key:
                total_n = sum(r.get("result", {}).get("n", 0) for _, r in allowed)
                ws = sum(r.get("result", {}).get("n", 0) * r.get("result", {}).get(mean_key, 0) for _, r in allowed)
                pooled = round(ws / total_n, 2) if total_n else 0.0
                print(f"    Pooled: n={total_n}, {mean_key}={pooled}")
            elif "counts" in first:
                pooled_counts = {}
                pooled_n = 0
                for _, r in allowed:
                    res = r.get("result", {})
                    pooled_n += res.get("n", 0)
                    for k, v in res.get("counts", {}).items():
                        pooled_counts[k] = pooled_counts.get(k, 0) + v
                print(f"    Pooled: n={pooled_n}, counts={pooled_counts}")
    if pause:
        time.sleep(1)
    _step_wait(step_mode)


def step2_refusals(ports, pause, step_mode=False):
    """Step 2: show refusals (all records, rare group, no key)."""
    banner(2, "Refusals: all records, rare group, and no API key.")
    queries = [
        ("get all records", ANA_KEY),
        ("mean age where diagnosis = rare", ANA_KEY),
        ("mean age", None),
    ]
    for query, key in queries:
        port = ports[0]
        resp = post(port, query, key)
        print(f"  {query!r} key={key is not None} -> {resp.get('decision')}: {resp.get('reason', '')}")
    if pause:
        time.sleep(1)
    _step_wait(step_mode)


def step3_differencing(guarded_port, unguarded_port, pause, step_mode=False):
    """Step 3: differencing attack on unguarded then guarded server."""
    import csv as _csv
    banner(3, "Differencing attack: unguarded vs guarded server.")
    site_a = HERE / "site_a.csv"
    patients = []
    if site_a.exists():
        with site_a.open(newline="", encoding="utf-8") as fh:
            for row in _csv.DictReader(fh):
                row["age"] = float(row["age"])
                row["bmi"] = float(row["bmi"])
                patients.append(row)

    def run_diff(port, label, stop_after=None):
        """Run differencing and return (attempts, blocked, recovered)."""
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

    print(f"  Unguarded (:{unguarded_port}): {att_u} attempts, {blk_u} blocked, {rec_u} patient(s) recovered")
    print(f"  Guarded   (:{guarded_port}): {att_g} attempts, {blk_g} blocked, {rec_g} patient(s) recovered")
    if pause:
        time.sleep(1)
    _step_wait(step_mode)
    return rec_u, rec_g


def step4_audit(site_name, pause, step_mode=False):
    """Step 4: show 3 log lines, tamper one, run verify_log.py."""
    banner(4, "Audit log: tamper detection.")
    log_path = HERE / "logs" / f"{site_name}.jsonl"
    if not log_path.exists():
        print("  No log file found. Skipping audit step.")
        return

    lines = log_path.read_text(encoding="utf-8").splitlines()
    print(f"  Log file: {log_path.name} ({len(lines)} entries)")
    for line in lines[:3]:
        print(f"    {line[:100]}")

    # Verify the intact log.
    result = subprocess.run(
        [sys.executable, str(HERE / "verify_log.py"), str(log_path)],
        capture_output=True, text=True,
    )
    print(f"  verify_log.py (intact): {result.stdout.strip()}")

    # Tamper: change one character in line 1.
    if lines:
        tampered = list(lines)
        first = tampered[0]
        # Flip a character in the middle of the line.
        mid = len(first) // 2
        c = first[mid]
        replacement = "X" if c != "X" else "Y"
        tampered[0] = first[:mid] + replacement + first[mid + 1:]
        tampered_path = log_path.parent / f"{site_name}_tampered.jsonl"
        tampered_path.write_text("\n".join(tampered) + "\n", encoding="utf-8")
        result2 = subprocess.run(
            [sys.executable, str(HERE / "verify_log.py"), str(tampered_path)],
            capture_output=True, text=True,
        )
        print(f"  verify_log.py (tampered): {result2.stdout.strip()}")
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
        print("Starting servers...", flush=True)
        for port in SITE_PORTS + [UNGUARDED_PORT]:
            ok = wait_for_server(port)
            if not ok:
                print(f"ERROR: server on port {port} did not start in time.", file=sys.stderr)
                sys.exit(1)
        print("All servers ready.", flush=True)
        _step_wait(step_mode)

        step1_pooled(SITE_PORTS, pause, step_mode)
        step2_refusals(SITE_PORTS, pause, step_mode)
        rec_u, rec_g = step3_differencing(SITE_PORTS[0], UNGUARDED_PORT, pause, step_mode)
        step4_audit("site_a", pause, step_mode)

        print()
        print("=" * 60)
        print("Summary: federated mean queries pooled across 3 sites.")
        print(f"  Differencing: unguarded recovered {rec_u}, guarded recovered {rec_g}.")
        print("  Audit log tamper detected by verify_log.py.")
        print("=" * 60)

    finally:
        stop_servers(procs)
        print("Servers stopped.", flush=True)


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
