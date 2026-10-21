"""Institution server: allow statistical summaries, deny disclosive queries."""

import argparse
import csv
import hashlib
import json
import re
import threading
import time
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from auth import load_keys
from audit import AuditLog
from guard import OverlapGuard

MIN_N = 5
HOST = "127.0.0.1"
PORT = 8000
DATA_PATH = Path(__file__).with_name("patients.csv")
NUMERIC_COLUMNS = {"age", "bmi"}
GROUP_COLUMNS = {"sex", "diagnosis"}
IDENTIFYING_COLUMNS = {"id", "name"}

MEAN_WHERE = re.compile(r"mean (\w+) where (\w+) = (\w+)")
MEAN_WHERE_AGE_GT = re.compile(r"mean (\w+) where age > (\d+)")
MEAN_WHERE_AGE_LT = re.compile(r"mean (\w+) where age < (\d+)")
MEAN_SIMPLE = re.compile(r"mean (\w+)")
COUNT_BY = re.compile(r"count by (\w+)")

# Keys file path relative to this script.
KEYS_PATH = Path(__file__).with_name("keys.json")


def load_patients(path=DATA_PATH):
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        row["age"] = float(row["age"])
        row["bmi"] = float(row["bmi"])
    return rows


PATIENTS = load_patients()


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
        self.patients = load_patients(Path(data_path))
        self.site_name = site_name
        self.overlap_guard_enabled = overlap_guard_enabled
        self.keys_data = load_keys(KEYS_PATH)
        self._rate_lock = threading.Lock()
        # _rate_counts[user] = [timestamp, ...]
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

    # mean X where age > N  (new filter -- checked before generic MEAN_WHERE)
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

    # mean X where age < N  (new filter -- checked before generic MEAN_WHERE)
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

    where_match = MEAN_WHERE.fullmatch(query)
    if where_match:
        column, field, value = where_match.groups()
        if column in IDENTIFYING_COLUMNS or field in IDENTIFYING_COLUMNS:
            return deny("query asks for individual patient records")
        if column not in NUMERIC_COLUMNS or field != "diagnosis":
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
    """Return a BaseHTTPRequestHandler class bound to the given SiteState.

    Used by test_medmesh.py and by serve() when launching named sites.
    """

    class _BoundHandler(BaseHTTPRequestHandler):
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

    return _BoundHandler


# Module-level QueryHandler for test_queries.py compatibility.
# test_queries.py does: from server import HOST, PATIENTS, QueryHandler, ThreadingHTTPServer
# It uses no API keys so we create a keyless default state once on first use.
_compat_state = None


def _get_compat_state():
    global _compat_state
    if _compat_state is None:
        _compat_state = SiteState(DATA_PATH, "default", overlap_guard_enabled=False)
        # Override with module-level PATIENTS (same object test_queries.py imports).
        _compat_state.patients = PATIENTS
        # Clear keys so unauthenticated test_queries.py requests pass.
        _compat_state.keys_data = {}
    return _compat_state


class QueryHandler(BaseHTTPRequestHandler):
    """Top-level QueryHandler using module-level PATIENTS and no API keys.

    Kept as a real top-level class so test_queries.py can import it directly.
    """

    def do_POST(self):
        state = _get_compat_state()
        if self.path != "/query":
            self._send(404, deny("query is not an allowed statistical summary"))
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
            query = body["query"]
        except (json.JSONDecodeError, KeyError, TypeError, UnicodeDecodeError):
            self._send(200, deny("query is not an allowed statistical summary"))
            return
        self._send(200, process_query(query, state))

    def _send(self, status, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        return


def serve(port=PORT, data_path=DATA_PATH, site_name="default", overlap_guard=True):
    """Start a blocking server."""
    state = SiteState(data_path, site_name, overlap_guard)
    handler_class = make_handler(state)
    server = ThreadingHTTPServer((HOST, port), handler_class)
    print(f"listening on http://{HOST}:{port}", flush=True)
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
