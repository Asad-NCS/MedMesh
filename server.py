"""Institution server: allow statistical summaries, deny disclosive queries."""

import csv
import json
import re
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MIN_N = 5
HOST = "127.0.0.1"
PORT = 8000
DATA_PATH = Path(__file__).with_name("patients.csv")
NUMERIC_COLUMNS = {"age", "bmi"}
GROUP_COLUMNS = {"sex", "diagnosis"}
IDENTIFYING_COLUMNS = {"id", "name"}

MEAN_WHERE = re.compile(r"mean (\w+) where (\w+) = (\w+)")
MEAN_SIMPLE = re.compile(r"mean (\w+)")
COUNT_BY = re.compile(r"count by (\w+)")


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


def process_query(text):
    query = normalize(text)
    if not query:
        return deny("query is not an allowed statistical summary")
    if asks_for_records(query):
        return deny("query asks for individual patient records")

    where_match = MEAN_WHERE.fullmatch(query)
    if where_match:
        column, field, value = where_match.groups()
        if column in IDENTIFYING_COLUMNS or field in IDENTIFYING_COLUMNS:
            return deny("query asks for individual patient records")
        if column not in NUMERIC_COLUMNS or field != "diagnosis":
            return deny("query is not an allowed statistical summary")
        matched = [row for row in PATIENTS if row["diagnosis"].lower() == value]
        if len(matched) < MIN_N:
            return deny("result covers fewer than 5 patients")
        return mean_result(column, matched)

    mean_match = MEAN_SIMPLE.fullmatch(query)
    if mean_match:
        column = mean_match.group(1)
        if column in IDENTIFYING_COLUMNS:
            return deny("query asks for individual patient records")
        if column not in NUMERIC_COLUMNS:
            return deny("query is not an allowed statistical summary")
        if len(PATIENTS) < MIN_N:
            return deny("result covers fewer than 5 patients")
        return mean_result(column, PATIENTS)

    if query == "count":
        if len(PATIENTS) < MIN_N:
            return deny("result covers fewer than 5 patients")
        return allow({"n": len(PATIENTS)})

    count_match = COUNT_BY.fullmatch(query)
    if count_match:
        column = count_match.group(1)
        if column in IDENTIFYING_COLUMNS:
            return deny("query asks for individual patient records")
        if column not in GROUP_COLUMNS:
            return deny("query is not an allowed statistical summary")
        counts = Counter(row[column] for row in PATIENTS)
        if any(count < MIN_N for count in counts.values()):
            return deny("result covers fewer than 5 patients")
        return allow({"n": len(PATIENTS), "counts": dict(sorted(counts.items()))})

    return deny("query is not an allowed statistical summary")


class QueryHandler(BaseHTTPRequestHandler):
    def do_POST(self):
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
        self._send(200, process_query(query))

    def _send(self, status, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        return


def serve(port=PORT):
    server = ThreadingHTTPServer((HOST, port), QueryHandler)
    print(f"listening on http://{HOST}:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    serve()
