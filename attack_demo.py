"""Attack demonstration for MedMesh.

Scenarios:
  A. Request all records from a guarded server.
  B. Tiny group query (diagnosis = rare) from a guarded server.
  C. Differencing attack: query mean bmi where age > N and age > N+1.
     Run against an unguarded server (port 8010) and a guarded one (port 8000).
     Stop after 5 recoveries on the unguarded server.
  D. Triple query (known limitation): total, age > N, age < N -> infer age == N group.

Prints a table: scenario, attempts, blocked, patients recovered.

The attacker uses API key for researcher_mallory. The CSV is used only for scoring.
"""

import csv
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

MALLORY_KEY = "key_mallory_003"
GUARDED_PORT = 8000
UNGUARDED_PORT = 8010


def post(port, query, api_key=None):
    """Send a query to the server. Returns (response_dict, error_str_or_None)."""
    payload = json.dumps({"query": query}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    url = f"http://127.0.0.1:{port}/query"
    try:
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except urllib.error.URLError as exc:
        return None, str(exc)


def load_site_a():
    """Load site_a.csv for scoring. Returns list of dicts."""
    path = Path(__file__).parent / "site_a.csv"
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        row["age"] = float(row["age"])
        row["bmi"] = float(row["bmi"])
    return rows


def scenario_a(port):
    """A. Request all records. Expect deny."""
    resp, err = post(port, "get all records", MALLORY_KEY)
    attempts = 1
    blocked = 0
    if err:
        return attempts, blocked, 0, f"error: {err}"
    if resp and resp.get("decision") == "deny":
        blocked = 1
    return attempts, blocked, 0, resp.get("reason", "") if resp else "no response"


def scenario_b(port):
    """B. Tiny group query (diagnosis = rare). Expect deny."""
    resp, err = post(port, "mean age where diagnosis = rare", MALLORY_KEY)
    attempts = 1
    blocked = 0
    if err:
        return attempts, blocked, 0, f"error: {err}"
    if resp and resp.get("decision") == "deny":
        blocked = 1
    return attempts, blocked, 0, resp.get("reason", "") if resp else "no response"


def scenario_c_port(port, patients, max_recover=5, stop_after=None):
    """C. Differencing attack on one port.

    For N in 30..70, query mean bmi where age > N and age > N+1.
    If counts differ by 1, estimate the one patient's BMI.
    Count as recovered if within 1.5 of actual BMI.
    Returns (attempts, blocked, recovered).
    """
    attempts = 0
    blocked = 0
    recovered = 0
    prev_resp = None

    for n in range(30, 71):
        if stop_after is not None and recovered >= stop_after:
            break
        query = f"mean bmi where age > {n}"
        resp, err = post(port, query, MALLORY_KEY)
        attempts += 1
        if err:
            continue
        if resp and resp.get("decision") == "deny":
            blocked += 1
            prev_resp = None
            continue

        if prev_resp is not None and prev_resp.get("decision") == "allow":
            r1 = prev_resp.get("result", {})
            r2 = resp.get("result", {}) if resp and resp.get("decision") == "allow" else None
            if r2 is None:
                prev_resp = resp
                continue
            n1 = r1.get("n", 0)
            n2 = r2.get("n", 0)
            m1 = r1.get("mean_bmi", 0.0)
            m2 = r2.get("mean_bmi", 0.0)
            if n1 - n2 == 1 and n1 > 0 and n2 > 0:
                # The patient with age == n+1 - 1 = n was removed.
                # Estimated BMI: n1*m1 - n2*m2 (approximation due to rounding).
                estimated = n1 * m1 - n2 * m2
                target_age = n  # age == n
                # Find patients with this age in the CSV for scoring.
                true_patients = [p for p in patients if p["age"] == target_age]
                for tp in true_patients:
                    true_bmi = tp["bmi"]
                    if abs(estimated - true_bmi) <= 1.5:
                        recovered += 1
                        break

        prev_resp = resp

    return attempts, blocked, recovered


def scenario_c(patients):
    """C. Differencing on unguarded then guarded server."""
    print("  Running differencing on unguarded server (port 8010)...")
    att_u, blk_u, rec_u = scenario_c_port(UNGUARDED_PORT, patients, stop_after=5)
    print("  Running differencing on guarded server (port 8000)...")
    att_g, blk_g, rec_g = scenario_c_port(GUARDED_PORT, patients)
    return att_u, blk_u, rec_u, att_g, blk_g, rec_g


def scenario_d(port, patients):
    """D. Triple query: total, age > N, age < N -> infer age == N group.

    This is a known limitation. The pairwise guard does not stop it.
    We just report the math.
    """
    n = 45
    attempts = 0
    blocked = 0

    resp_total, _ = post(port, "mean bmi", MALLORY_KEY)
    attempts += 1
    resp_gt, _ = post(port, f"mean bmi where age > {n}", MALLORY_KEY)
    attempts += 1
    resp_lt, _ = post(port, f"mean bmi where age < {n}", MALLORY_KEY)
    attempts += 1

    for r in [resp_total, resp_gt, resp_lt]:
        if r and r.get("decision") == "deny":
            blocked += 1

    note = (
        "Triple query against age == {n}: uses total, age > {n}, age < {n}. "
        "The pairwise overlap guard does not block this combination."
    ).format(n=n)

    return attempts, blocked, note


def main():
    patients = load_site_a()

    print("MedMesh attack demonstration")
    print("-" * 50)

    rows = []

    # Scenario A.
    att_a, blk_a, rec_a, note_a = scenario_a(GUARDED_PORT)
    print(f"A. get all records -> {note_a}")
    rows.append(("A: request all records", att_a, blk_a, rec_a))

    # Scenario B.
    att_b, blk_b, rec_b, note_b = scenario_b(GUARDED_PORT)
    print(f"B. tiny group (rare) -> {note_b}")
    rows.append(("B: tiny group (rare)", att_b, blk_b, rec_b))

    # Scenario C.
    att_u, blk_u, rec_u, att_g, blk_g, rec_g = scenario_c(patients)
    rows.append(("C: differencing (unguarded)", att_u, blk_u, rec_u))
    rows.append(("C: differencing (guarded)", att_g, blk_g, rec_g))

    # Scenario D.
    att_d, blk_d, note_d = scenario_d(GUARDED_PORT, patients)
    print(f"D. triple query note: {note_d}")
    rows.append(("D: triple query", att_d, blk_d, 0))

    # Print results table.
    print()
    print(f"{'Scenario':<35} {'Attempts':>8} {'Blocked':>7} {'Recovered':>9}")
    print("-" * 62)
    for scenario, att, blk, rec in rows:
        print(f"{scenario:<35} {att:>8} {blk:>7} {rec:>9}")
    print()

    if rec_u > 0:
        print(f"Unguarded server: differencing recovered {rec_u} patient(s) BMI estimate(s).")
    else:
        print("Unguarded server: no recoveries (check server is running on port 8010).")

    if rec_g == 0:
        print("Guarded server: overlap guard blocked all differencing attempts.")
    else:
        print(f"Guarded server: {rec_g} BMI estimates recovered (guard may need tuning).")

    print()
    print("Known limit: triple query (scenario D) bypasses pairwise overlap guard.")
    print("Collusion between accounts is not detected by this prototype.")


if __name__ == "__main__":
    main()
