"""Run allowed and denied queries against the privacy-check server."""

import json
import threading
import urllib.request

from server import HOST, PATIENTS, QueryHandler, ThreadingHTTPServer

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


def post(port, query):
    payload = json.dumps({"query": query}).encode("utf-8")
    request = urllib.request.Request(
        f"http://{HOST}:{port}/query",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def response_is_safe(body):
    text = json.dumps(body)
    if "name" in text or "id" in text:
        return False
    result = body.get("result")
    if isinstance(result, list):
        return False
    return not _contains_row(result)


def _contains_row(value):
    if isinstance(value, list):
        return any(isinstance(item, dict) or _contains_row(item) for item in value)
    if isinstance(value, dict):
        if "name" in value or "id" in value:
            return True
        return any(_contains_row(item) for item in value.values())
    if isinstance(value, str):
        return any(patient["name"] == value for patient in PATIENTS)
    return False


def main():
    server = ThreadingHTTPServer((HOST, 0), QueryHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    failures = 0
    try:
        for query, expected in CASES:
            body = post(port, query)
            decision = body.get("decision")
            ok = decision == expected
            if ok and expected == "allow":
                ok = response_is_safe(body)
            status = "PASS" if ok else "FAIL"
            print(f"{status}  {query!r} -> {decision} (expected {expected})")
            if not ok:
                failures += 1
                print(json.dumps(body, indent=2))
    finally:
        server.shutdown()

    if failures:
        print(f"\n{failures} query check(s) failed")
        raise SystemExit(1)
    print(f"\n{len(CASES)} query checks passed")


if __name__ == "__main__":
    main()
