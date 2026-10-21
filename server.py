"""Institution server: allow statistical summaries, deny disclosive queries.

Flags:
  --port N         listen port (default 8000)
  --data PATH      CSV file (default patients.csv next to this script)
  --site-name NAME label used in audit log (default "default")
  --no-overlap-guard  disable the per-site overlap guard

API keys:
  Requests must include X-API-Key header matching keys.json.
  Missing or wrong key gets deny with reason "invalid or missing API key".
  Over rate limit gets deny with reason "rate limit exceeded".

Audit log:
  Each request appended to logs/<site-name>.jsonl as a JSON line.
  Fields: ts, site, user, query, decision, reason, prev_hash, entry_hash.
  entry_hash = SHA-256(entry JSON content + prev_hash).

Overlap guard:
  Per site, across all users, remember patient-id sets behind each
  allowed query. A new query with set S is denied if some prior set P
  exists with S != P and |symmetric_difference(S, P)| < MIN_N.
  An exact repeat of an earlier query set is allowed.
"""

import argparse
import csv
import hashlib
import json
import re
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MIN_N = 5
HOST = "127.0.0.1"
PORT = 8000
DATA_PATH = Path(__file__).with_name("patients.csv")
NUMERIC_COLUMNS = {"age", "bmi"}
GROUP_COLUMNS = {"sex", "diagnosis"}
IDENTIFYING_COLUMNS = {"id", "name"}

MEAN_WHERE_DIAG = re.compile(r"mean (\w+) where diagnosis = (\w+)")
MEAN_WHERE_AGE_GT = re.compile(r"mean (\w+) where age > (\d+)")
MEAN_WHERE_AGE_LT = re.compile(r"mean (\w+) where age < (\d+)")
MEAN_SIMPLE = re.compile(r"mean (\w+)")
COUNT_BY = re.compile(r"count by (\w+)")

# Keys file path relative to this script.
KEYS_PATH = Path(__file__).with_name("keys.json")


def load_patients(path=DATA_PATH):
    """Load CSV and cast numeric columns."""
    with Path(path).open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        row["age"] = float(row["age"])
        row["bmi"] = float(row["bmi"])
    return rows


# Module-level PATIENTS for backward compatibility with test_queries.py.
PATIENTS = load_patients()


def load_keys():
    """Load API keys from keys.json. Returns empty dict if file missing."""
    if not KEYS_PATH.exists():
        return {}
    with KEYS_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


def deny(reason):
    return {"decision": "deny", "reason": reason}


def allow(result):
    return {"decision": "allow", "result": result}


def normalize(text):
    return " ".join(str(text).strip().lower().split())


def asks_for_records(query):
    if query.startswith("show ") or query.startswith("get "):
        return True
    markers = ("record", "export", "dump", "select ", "row", "delete", "drop ")
    return any(marker in query for marker in markers)


def mean_result(column, rows):
    average = sum(row[column] for row in rows) / len(rows)
    return allow({"n": len(rows), f"mean_{column}": round(average, 2)})


def patient_ids(rows):
    """Return frozenset of patient id strings for overlap checking."""
    return frozenset(str(row["id"]) for row in rows)


class SiteState:
    """Holds per-site mutable state: patients, keys, rate limiter, overlap guard, log."""

    def __init__(self, data_path, site_name, overlap_guard_enabled):
        self.patients = load_patients(data_path)
        self.site_name = site_name
        self.overlap_guard_enabled = overlap_guard_enabled
        self.keys_data = load_keys()
        self._rate_lock = threading.Lock()
        # rate_counts[user] = [timestamp, ...]
        self._rate_counts = defaultdict(list)
        self._overlap_lock = threading.Lock()
        # List of frozensets of patient ids from previous allowed queries.
        self._seen_sets = []
        self._log_lock = threading.Lock()
        self._prev_hash = "0"
        logs_dir = Path(__file__).parent / "logs"
        logs_dir.mkdir(exist_ok=True)
        self._log_path = logs_dir / f"{site_name}.jsonl"

    def check_key(self, key_value):
        """Return (user, deny_response_or_None)."""
        if not self.keys_data:
            # No keys file: allow all with user "anonymous".
            return "anonymous", None
        if not key_value:
            return None, deny("invalid or missing API key")
        for user, info in self.keys_data.items():
            if info.get("key") == key_value:
                return user, None
        return None, deny("invalid or missing API key")

    def check_rate(self, user):
        """Return deny_response_or_None. Drops timestamps older than 60s."""
        if not self.keys_data:
            return None
        user_info = self.keys_data.get(user, {})
        limit = user_info.get("limit")
        if limit is None:
            return None
        now = time.time()
        with self._rate_lock:
            stamps = self._rate_counts[user]
            # Keep only the last 60 seconds.
            stamps[:] = [t for t in stamps if now - t < 60]
            if len(stamps) >= limit:
                return deny("rate limit exceeded")
            stamps.append(now)
        return None

    def check_overlap(self, new_set):
        """Return deny_response_or_None based on overlap guard."""
        if not self.overlap_guard_enabled:
            return None
        with self._overlap_lock:
            for prior in self._seen_sets:
                if new_set == prior:
                    # Exact repeat is fine.
                    return None
                diff = new_set.symmetric_difference(prior)
                if len(diff) < MIN_N:
                    return deny("too similar to an earlier query")
            self._seen_sets.append(new_set)
        return None

    def record_set(self, new_set):
        """Record a new patient-id set (after guard passed)."""
        if not self.overlap_guard_enabled:
            return
        with self._overlap_lock:
            if new_set not in self._seen_sets:
                self._seen_sets.append(new_set)

    def append_log(self, user, query, decision, reason):
        """Append a tamper-evident JSON line to the audit log."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry = {
            "ts": ts,
            "site": self.site_name,
            "user": user if user else "",
            "query": query,
            "decision": decision,
            "reason": reason if reason else "",
            "prev_hash": self._prev_hash,
        }
        content = json.dumps(entry, sort_keys=True)
        entry_hash = hashlib.sha256((content + self._prev_hash).encode("utf-8")).hexdigest()
        entry["entry_hash"] = entry_hash
        line = json.dumps(entry)
        with self._log_lock:
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self._prev_hash = entry_hash


def process_query(text, state):
    """Evaluate a query against the site state. Returns response dict."""
    patients = state.patients
    query = normalize(text)
    if not query:
        return deny("query is not an allowed statistical summary")
    if asks_for_records(query):
        return deny("query asks for individual patient records")

    # mean X where diagnosis = Y
    where_diag = MEAN_WHERE_DIAG.fullmatch(query)
    if where_diag:
        column, value = where_diag.groups()
        if column in IDENTIFYING_COLUMNS:
            return deny("query asks for individual patient records")
        if column not in NUMERIC_COLUMNS:
            return deny("query is not an allowed statistical summary")
        matched = [row for row in patients if row["diagnosis"].lower() == value]
        if len(matched) < MIN_N:
            return deny("result covers fewer than 5 patients")
        ids = patient_ids(matched)
        overlap_resp = state.check_overlap(ids)
        if overlap_resp:
            return overlap_resp
        state.record_set(ids)
        return mean_result(column, matched)

    # mean X where age > N
    where_age_gt = MEAN_WHERE_AGE_GT.fullmatch(query)
    if where_age_gt:
        column, threshold_str = where_age_gt.groups()
        if column in IDENTIFYING_COLUMNS:
            return deny("query asks for individual patient records")
        if column not in NUMERIC_COLUMNS:
            return deny("query is not an allowed statistical summary")
        threshold = int(threshold_str)
        matched = [row for row in patients if row["age"] > threshold]
        if len(matched) < MIN_N:
            return deny("result covers fewer than 5 patients")
        ids = patient_ids(matched)
        overlap_resp = state.check_overlap(ids)
        if overlap_resp:
            return overlap_resp
        state.record_set(ids)
        return mean_result(column, matched)

    # mean X where age < N
    where_age_lt = MEAN_WHERE_AGE_LT.fullmatch(query)
    if where_age_lt:
        column, threshold_str = where_age_lt.groups()
        if column in IDENTIFYING_COLUMNS:
            return deny("query asks for individual patient records")
        if column not in NUMERIC_COLUMNS:
            return deny("query is not an allowed statistical summary")
        threshold = int(threshold_str)
        matched = [row for row in patients if row["age"] < threshold]
        if len(matched) < MIN_N:
            return deny("result covers fewer than 5 patients")
        ids = patient_ids(matched)
        overlap_resp = state.check_overlap(ids)
        if overlap_resp:
            return overlap_resp
        state.record_set(ids)
        return mean_result(column, matched)

    # mean X (simple)
    mean_match = MEAN_SIMPLE.fullmatch(query)
    if mean_match:
        column = mean_match.group(1)
        if column in IDENTIFYING_COLUMNS:
            return deny("query asks for individual patient records")
        if column not in NUMERIC_COLUMNS:
            return deny("query is not an allowed statistical summary")
        if len(patients) < MIN_N:
            return deny("result covers fewer than 5 patients")
        ids = patient_ids(patients)
        overlap_resp = state.check_overlap(ids)
        if overlap_resp:
            return overlap_resp
        state.record_set(ids)
        return mean_result(column, patients)

    if query == "count":
        if len(patients) < MIN_N:
            return deny("result covers fewer than 5 patients")
        return allow({"n": len(patients)})

    count_match = COUNT_BY.fullmatch(query)
    if count_match:
        column = count_match.group(1)
        if column in IDENTIFYING_COLUMNS:
            return deny("query asks for individual patient records")
        if column not in GROUP_COLUMNS:
            return deny("query is not an allowed statistical summary")
        from collections import Counter
        counts = Counter(row[column] for row in patients)
        if any(count < MIN_N for count in counts.values()):
            return deny("result covers fewer than 5 patients")
        ids = patient_ids(patients)
        overlap_resp = state.check_overlap(ids)
        if overlap_resp:
            return overlap_resp
        state.record_set(ids)
        return allow({"n": len(patients), "counts": dict(sorted(counts.items()))})

    return deny("query is not an allowed statistical summary")


def make_handler(state):
    """Return a BaseHTTPRequestHandler class bound to the given SiteState."""

    class QueryHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/query":
                self._send(404, deny("query is not an allowed statistical summary"))
                return
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            api_key_value = self.headers.get("X-API-Key", "")

            # Parse request body.
            try:
                body = json.loads(raw.decode("utf-8"))
                query_text = body["query"]
            except (json.JSONDecodeError, KeyError, TypeError, UnicodeDecodeError):
                resp = deny("query is not an allowed statistical summary")
                state.append_log("", "", resp["decision"], resp.get("reason", ""))
                self._send(200, resp)
                return

            # Auth check.
            user, auth_resp = state.check_key(api_key_value)
            if auth_resp:
                state.append_log(user, query_text, auth_resp["decision"], auth_resp.get("reason", ""))
                self._send(200, auth_resp)
                return

            # Rate limit check.
            rate_resp = state.check_rate(user)
            if rate_resp:
                state.append_log(user, query_text, rate_resp["decision"], rate_resp.get("reason", ""))
                self._send(200, rate_resp)
                return

            # Process the query.
            response = process_query(query_text, state)
            reason = response.get("reason", "")
            state.append_log(user, query_text, response["decision"], reason)
            self._send(200, response)

        def _send(self, status, payload):
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt, *args):
            return

    return QueryHandler


# Keep old-style QueryHandler for test_queries.py compatibility.
# test_queries.py does:  from server import HOST, PATIENTS, QueryHandler, ThreadingHTTPServer
# The default QueryHandler uses the module-level PATIENTS (patients.csv).
_default_state = None


def _get_default_state():
    global _default_state
    if _default_state is None:
        _default_state = SiteState(DATA_PATH, "default", overlap_guard_enabled=True)
        # Patch its patients to use the module-level PATIENTS list so
        # test_queries.py's response_is_safe() (which uses PATIENTS) sees the same data.
        _default_state.patients = PATIENTS
        # Clear keys so the legacy test_queries.py (unauthenticated) still passes.
        _default_state.keys_data = {}
    return _default_state


QueryHandler = make_handler(_get_default_state())


def serve(port=PORT, data_path=DATA_PATH, site_name="default", overlap_guard=True):
    """Start a blocking server."""
    state = SiteState(data_path, site_name, overlap_guard)
    handler_class = make_handler(state)
    server = ThreadingHTTPServer((HOST, port), handler_class)
    print(f"listening on http://{HOST}:{port} site={site_name}", flush=True)
    server.serve_forever()


def _parse_args():
    parser = argparse.ArgumentParser(description="MedMesh institution server")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--data", type=str, default=str(DATA_PATH))
    parser.add_argument("--site-name", type=str, default="default")
    parser.add_argument("--no-overlap-guard", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    serve(
        port=args.port,
        data_path=Path(args.data),
        site_name=args.site_name,
        overlap_guard=not args.no_overlap_guard,
    )
