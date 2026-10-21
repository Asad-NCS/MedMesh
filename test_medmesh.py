"""Comprehensive unit tests for MedMesh.

Covers all phases:
  - Phase 0/1: existing query logic (original 10 cases)
  - Phase 1: make_sites.py data properties
  - Phase 2: API key auth and rate limiting
  - Phase 3: audit log hash chain and verify_log.py
  - Phase 4: new filters (mean X where age > N) and overlap guard
  - Phase 5: attack scenarios (smoke tests)

Run with: python -m unittest
"""

import csv
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

# Ensure this repo is on the path.
HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from server import (
    HOST,
    MIN_N,
    PATIENTS,
    QueryHandler,
    SiteState,
    ThreadingHTTPServer,
    load_patients,
    make_handler,
    process_query,
)
from verify_log import verify


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def start_test_server(state):
    """Start a test server on an ephemeral port. Returns (server, port, thread)."""
    handler = make_handler(state)
    server = ThreadingHTTPServer((HOST, 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, thread


def post(port, query, api_key=None):
    """Send a query to a test server. Returns response dict."""
    import urllib.request
    payload = json.dumps({"query": query}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    req = urllib.request.Request(
        f"http://{HOST}:{port}/query",
        data=payload, headers=headers, method="POST",
    )
    import urllib.request as ureq
    with ureq.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def make_temp_csv(rows, tmp_dir):
    """Write a CSV to a temp file and return its Path."""
    path = Path(tmp_dir) / "patients_test.csv"
    fields = ["id", "name", "age", "sex", "bmi", "diagnosis"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return path


# ---------------------------------------------------------------------------
# Base: build a minimal patient set for tests (>= 5 per group).
# ---------------------------------------------------------------------------

def _make_patients(n=20, diag="flu"):
    """Return n synthetic patient dicts all with the given diagnosis."""
    return [
        {
            "id": str(i + 1),
            "name": f"Patient {i + 1:04d}",
            "age": float(20 + i),
            "sex": "M" if i % 2 == 0 else "F",
            "bmi": float(22.0 + i * 0.1),
            "diagnosis": diag,
        }
        for i in range(n)
    ]


def _make_mixed_patients():
    """Return 20 patients: 10 flu, 8 covid, 2 rare."""
    patients = _make_patients(10, "flu")
    for i in range(8):
        patients.append({
            "id": str(100 + i),
            "name": f"Patient {100 + i:04d}",
            "age": float(30 + i),
            "sex": "F",
            "bmi": float(25.0 + i * 0.1),
            "diagnosis": "covid",
        })
    for i in range(2):
        patients.append({
            "id": str(200 + i),
            "name": f"Patient {200 + i:04d}",
            "age": 50.0,
            "sex": "M",
            "bmi": 30.0,
            "diagnosis": "rare",
        })
    return patients


# ---------------------------------------------------------------------------
# Phase 0/1: original 10 query cases against patients.csv
# ---------------------------------------------------------------------------

class TestOriginalCases(unittest.TestCase):
    """Test that all 10 original CASES still pass."""

    CASES = [
        ("count", "allow"),
        ("mean age", "allow"),
        ("mean bmi", "allow"),
        ("count by sex", "allow"),
        ("get all records", "deny"),
        ("get patient 4", "deny"),
        ("show name and diagnosis", "deny"),
        ("mean age where diagnosis = rare", "deny"),
        ("count by diagnosis", "deny"),
        ("hello there", "deny"),
    ]

    @classmethod
    def setUpClass(cls):
        # Use a state backed by the real patients.csv.
        # Clear keys_data so the original unauthenticated queries still work.
        cls.state = SiteState(
            HERE / "patients.csv", "test_orig", overlap_guard_enabled=False
        )
        cls.state.keys_data = {}
        cls.server, cls.port, cls.thread = start_test_server(cls.state)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_cases(self):
        for query, expected in self.CASES:
            with self.subTest(query=query):
                resp = post(self.port, query, api_key=None)
                self.assertEqual(resp.get("decision"), expected, msg=f"query={query!r} response={resp}")


# ---------------------------------------------------------------------------
# Phase 2: API key auth
# ---------------------------------------------------------------------------

KEYS_DATA = {
    "researcher_ana": {"key": "key_ana_secure_001", "limit": 30},
    "researcher_bob": {"key": "key_bob_secure_002", "limit": 30},
    "researcher_mallory": {"key": "key_mallory_003", "limit": 1000},
}


class TestAPIKeyAuth(unittest.TestCase):
    """Test API key authentication."""

    @classmethod
    def setUpClass(cls):
        patients = _make_patients(20, "flu")
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = make_temp_csv(patients, tmp)
            state = SiteState(csv_path, "test_auth", overlap_guard_enabled=False)
            state.patients = patients
            state.keys_data = KEYS_DATA
            cls.server, cls.port, cls.thread = start_test_server(state)
            cls.state = state

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_good_key(self):
        resp = post(self.port, "mean age", api_key="key_ana_secure_001")
        self.assertEqual(resp.get("decision"), "allow")

    def test_bad_key(self):
        resp = post(self.port, "mean age", api_key="wrong_key")
        self.assertEqual(resp.get("decision"), "deny")
        self.assertIn("invalid or missing api key", resp.get("reason", "").lower())

    def test_no_key(self):
        resp = post(self.port, "mean age", api_key=None)
        self.assertEqual(resp.get("decision"), "deny")
        self.assertIn("invalid or missing api key", resp.get("reason", "").lower())


class TestRateLimit(unittest.TestCase):
    """Test rate limiting."""

    def test_over_limit(self):
        """A user with limit=1 should be denied on the second request."""
        patients = _make_patients(20, "flu")
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = make_temp_csv(patients, tmp)
            state = SiteState(csv_path, "test_rate", overlap_guard_enabled=False)
            state.patients = patients
            state.keys_data = {"user_tight": {"key": "tight_key", "limit": 1}}
            server, port, thread = start_test_server(state)
            try:
                resp1 = post(port, "mean age", api_key="tight_key")
                self.assertEqual(resp1.get("decision"), "allow")
                resp2 = post(port, "mean age", api_key="tight_key")
                self.assertEqual(resp2.get("decision"), "deny")
                self.assertIn("rate limit", resp2.get("reason", "").lower())
            finally:
                server.shutdown()


# ---------------------------------------------------------------------------
# Phase 3: audit log
# ---------------------------------------------------------------------------

class TestAuditLog(unittest.TestCase):
    """Test the tamper-evident audit log and verify_log.py."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _make_state(self):
        patients = _make_patients(20, "flu")
        csv_path = make_temp_csv(patients, self.tmp_path)
        state = SiteState(csv_path, "test_log", overlap_guard_enabled=False)
        state.patients = patients
        state.keys_data = {}
        # Override log path to tmp dir.
        (self.tmp_path / "logs").mkdir(exist_ok=True)
        state._log_path = self.tmp_path / "logs" / "test_log.jsonl"
        state._prev_hash = "0"
        return state, self.tmp_path / "logs" / "test_log.jsonl"

    def test_log_created(self):
        state, log_path = self._make_state()
        state.append_log("ana", "mean age", "allow", "")
        self.assertTrue(log_path.exists())
        lines = log_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertIn("entry_hash", entry)
        self.assertIn("prev_hash", entry)
        self.assertEqual(entry["prev_hash"], "0")

    def test_chain_valid(self):
        state, log_path = self._make_state()
        state.append_log("ana", "mean age", "allow", "")
        state.append_log("bob", "count", "allow", "")
        state.append_log("mallory", "get all records", "deny", "records")
        ok, broken = verify(log_path)
        self.assertTrue(ok)
        self.assertIsNone(broken)

    def test_tamper_detected(self):
        state, log_path = self._make_state()
        state.append_log("ana", "mean age", "allow", "")
        state.append_log("bob", "count", "allow", "")
        # Tamper line 1.
        lines = log_path.read_text(encoding="utf-8").splitlines()
        mid = len(lines[0]) // 2
        c = lines[0][mid]
        replacement = "X" if c != "X" else "Y"
        lines[0] = lines[0][:mid] + replacement + lines[0][mid + 1:]
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ok, broken = verify(log_path)
        self.assertFalse(ok)
        self.assertEqual(broken, 1)


# ---------------------------------------------------------------------------
# Phase 4: new filters and overlap guard
# ---------------------------------------------------------------------------

class TestNewFilters(unittest.TestCase):
    """Test mean X where age > N and mean X where age < N."""

    @classmethod
    def setUpClass(cls):
        # 20 patients ages 20..39 all flu.
        cls.patients = _make_patients(20, "flu")
        cls.state = SiteState.__new__(SiteState)
        # Manually init enough fields.
        cls.state.patients = cls.patients
        cls.state.site_name = "test_filters"
        cls.state.overlap_guard_enabled = False
        cls.state.keys_data = {}
        import threading
        from collections import defaultdict
        cls.state._rate_lock = threading.Lock()
        cls.state._rate_counts = defaultdict(list)
        cls.state._overlap_lock = threading.Lock()
        cls.state._seen_sets = []
        cls.state._log_lock = threading.Lock()
        cls.state._prev_hash = "0"
        logs_dir = HERE / "logs"
        logs_dir.mkdir(exist_ok=True)
        cls.state._log_path = logs_dir / "test_filters.jsonl"

    def test_mean_age_gt(self):
        resp = process_query("mean bmi where age > 25", self.state)
        self.assertEqual(resp.get("decision"), "allow")
        self.assertIn("n", resp.get("result", {}))

    def test_mean_age_lt(self):
        resp = process_query("mean bmi where age < 35", self.state)
        self.assertEqual(resp.get("decision"), "allow")

    def test_mean_age_gt_too_few(self):
        # age > 99 should have 0 patients.
        resp = process_query("mean bmi where age > 99", self.state)
        self.assertEqual(resp.get("decision"), "deny")
        self.assertIn("5 patients", resp.get("reason", ""))

    def test_mean_where_diag(self):
        resp = process_query("mean age where diagnosis = flu", self.state)
        self.assertEqual(resp.get("decision"), "allow")


class TestOverlapGuard(unittest.TestCase):
    """Test the overlap guard."""

    def _make_state(self, overlap_enabled):
        """Create a SiteState with a deterministic patient set."""
        import threading
        from collections import defaultdict
        state = SiteState.__new__(SiteState)
        # 40 patients ages 20..59.
        patients = []
        for i in range(40):
            patients.append({
                "id": str(i + 1),
                "name": f"Patient {i + 1:04d}",
                "age": float(20 + i),
                "sex": "M" if i % 2 == 0 else "F",
                "bmi": float(22.0 + i * 0.5),
                "diagnosis": "flu",
            })
        state.patients = patients
        state.site_name = "test_overlap"
        state.overlap_guard_enabled = overlap_enabled
        state.keys_data = {}
        state._rate_lock = threading.Lock()
        state._rate_counts = defaultdict(list)
        state._overlap_lock = threading.Lock()
        state._seen_sets = []
        state._log_lock = threading.Lock()
        state._prev_hash = "0"
        logs_dir = HERE / "logs"
        logs_dir.mkdir(exist_ok=True)
        state._log_path = logs_dir / "test_overlap.jsonl"
        return state

    def test_overlap_guard_blocks_close_query(self):
        """mean bmi where age > N, then age > N+1 should be denied (guarded)."""
        state = self._make_state(overlap_enabled=True)
        resp1 = process_query("mean bmi where age > 30", state)
        self.assertEqual(resp1.get("decision"), "allow")
        resp2 = process_query("mean bmi where age > 31", state)
        self.assertEqual(resp2.get("decision"), "deny")
        self.assertIn("too similar", resp2.get("reason", "").lower())

    def test_overlap_guard_allows_unguarded(self):
        """Same pair should be allowed on an unguarded server."""
        state = self._make_state(overlap_enabled=False)
        resp1 = process_query("mean bmi where age > 30", state)
        self.assertEqual(resp1.get("decision"), "allow")
        resp2 = process_query("mean bmi where age > 31", state)
        self.assertEqual(resp2.get("decision"), "allow")

    def test_overlap_guard_exact_repeat_allowed(self):
        """Exact repeat of a query set should be allowed."""
        state = self._make_state(overlap_enabled=True)
        resp1 = process_query("mean bmi where age > 30", state)
        self.assertEqual(resp1.get("decision"), "allow")
        resp2 = process_query("mean bmi where age > 30", state)
        self.assertEqual(resp2.get("decision"), "allow")


# ---------------------------------------------------------------------------
# Phase 1: make_sites.py data properties
# ---------------------------------------------------------------------------

class TestMakeSites(unittest.TestCase):
    """Verify site CSVs have correct shape after running make_sites.py."""

    @classmethod
    def setUpClass(cls):
        import subprocess
        result = subprocess.run(
            [sys.executable, str(HERE / "make_sites.py")],
            capture_output=True, text=True, cwd=str(HERE),
        )
        cls.make_result = result

    def _load(self, filename):
        path = HERE / filename
        self.assertTrue(path.exists(), f"{filename} not found")
        with path.open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        for row in rows:
            row["age"] = float(row["age"])
            row["bmi"] = float(row["bmi"])
        return rows

    def test_make_sites_runs(self):
        self.assertEqual(self.make_result.returncode, 0, self.make_result.stderr)

    def test_site_a_count(self):
        rows = self._load("site_a.csv")
        self.assertEqual(len(rows), 120)

    def test_site_b_count(self):
        rows = self._load("site_b.csv")
        self.assertEqual(len(rows), 80)

    def test_site_c_count(self):
        rows = self._load("site_c.csv")
        self.assertEqual(len(rows), 60)

    def test_rare_exactly_2_per_site(self):
        for fname in ["site_a.csv", "site_b.csv", "site_c.csv"]:
            rows = self._load(fname)
            rare = [r for r in rows if r["diagnosis"] == "rare"]
            self.assertEqual(len(rare), 2, f"{fname} has {len(rare)} rare patients")

    def test_non_rare_groups_at_least_5(self):
        """Each non-rare diagnosis must have at least 5 patients per site."""
        from collections import Counter
        for fname in ["site_a.csv", "site_b.csv", "site_c.csv"]:
            rows = self._load(fname)
            counts = Counter(r["diagnosis"] for r in rows if r["diagnosis"] != "rare")
            for diag, count in counts.items():
                self.assertGreaterEqual(count, 5, f"{fname} {diag} has {count} patients")

    def test_age_range(self):
        for fname in ["site_a.csv", "site_b.csv", "site_c.csv"]:
            rows = self._load(fname)
            for row in rows:
                self.assertGreaterEqual(row["age"], 18)
                self.assertLessEqual(row["age"], 90)

    def test_columns(self):
        rows = self._load("site_a.csv")
        expected = {"id", "name", "age", "sex", "bmi", "diagnosis"}
        self.assertEqual(set(rows[0].keys()), expected)

    def test_bmi_one_decimal(self):
        rows = self._load("site_a.csv")
        for row in rows:
            val = float(row["bmi"])
            self.assertEqual(round(val, 1), val)

    def test_name_format(self):
        rows = self._load("site_a.csv")
        for row in rows:
            self.assertTrue(row["name"].startswith("Patient "), f"bad name: {row['name']}")


# ---------------------------------------------------------------------------
# Phase 3: verify_log integration test
# ---------------------------------------------------------------------------

class TestVerifyLog(unittest.TestCase):
    """Integration test for verify_log.py via subprocess."""

    def test_verify_intact(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "test.jsonl"
            # Build a 3-entry log.
            prev = "0"
            lines = []
            for i in range(3):
                entry = {
                    "ts": "2026-01-01T00:00:00Z",
                    "site": "test",
                    "user": "ana",
                    "query": f"query {i}",
                    "decision": "allow",
                    "reason": "",
                    "prev_hash": prev,
                }
                content = json.dumps(entry, sort_keys=True)
                h = hashlib.sha256((content + prev).encode()).hexdigest()
                entry["entry_hash"] = h
                lines.append(json.dumps(entry))
                prev = h
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(HERE / "verify_log.py"), str(log_path)],
                capture_output=True, text=True,
            )
            self.assertIn("OK", result.stdout)
            self.assertEqual(result.returncode, 0)

    def test_verify_tampered(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "test_tampered.jsonl"
            prev = "0"
            lines = []
            for i in range(3):
                entry = {
                    "ts": "2026-01-01T00:00:00Z",
                    "site": "test",
                    "user": "ana",
                    "query": f"query {i}",
                    "decision": "allow",
                    "reason": "",
                    "prev_hash": prev,
                }
                content = json.dumps(entry, sort_keys=True)
                h = hashlib.sha256((content + prev).encode()).hexdigest()
                entry["entry_hash"] = h
                lines.append(json.dumps(entry))
                prev = h
            # Tamper line 1.
            mid = len(lines[0]) // 2
            c = lines[0][mid]
            replacement = "X" if c != "X" else "Y"
            lines[0] = lines[0][:mid] + replacement + lines[0][mid + 1:]
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(HERE / "verify_log.py"), str(log_path)],
                capture_output=True, text=True,
            )
            self.assertIn("1", result.stdout)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
