"""Researcher client: send one query to one or more sites and combine results.

Usage:
  python client.py "mean age"
  python client.py "mean age" --sites 8000 8001 8002
  python client.py "mean age" --sites 8000 8001 8002 --key my_api_key

API key can also be set via env var MEDMESH_KEY.
"""

import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8000/query"


def send_query(query, url=DEFAULT_URL, api_key=None):
    """Send query to one server. Returns parsed response dict."""
    payload = json.dumps({"query": query}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    request = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def pool_results(site_results):
    """Combine a list of (port, response) tuples into a pooled result.

    Returns (pooled_dict, excluded_ports).
    """
    allowed = [(port, r) for port, r in site_results if r.get("decision") == "allow"]
    denied_ports = [port for port, r in site_results if r.get("decision") != "allow"]

    if not allowed:
        return None, denied_ports

    # Determine what kind of result.
    first_result = allowed[0][1].get("result", {})

    # If result has 'counts' key -> count by query.
    if "counts" in first_result:
        pooled_counts = {}
        pooled_n = 0
        for _, r in allowed:
            res = r.get("result", {})
            pooled_n += res.get("n", 0)
            for key, val in res.get("counts", {}).items():
                pooled_counts[key] = pooled_counts.get(key, 0) + val
        return {"n": pooled_n, "counts": dict(sorted(pooled_counts.items()))}, denied_ports

    # If result has a mean_* key -> mean query.
    mean_key = next((k for k in first_result if k.startswith("mean_")), None)
    if mean_key:
        total_n = 0
        weighted_sum = 0.0
        for _, r in allowed:
            res = r.get("result", {})
            n = res.get("n", 0)
            m = res.get(mean_key, 0.0)
            total_n += n
            weighted_sum += n * m
        pooled_mean = round(weighted_sum / total_n, 2) if total_n > 0 else 0.0
        return {"n": total_n, mean_key: pooled_mean}, denied_ports

    # Fallback: sum up n.
    pooled_n = sum(r.get("result", {}).get("n", 0) for _, r in allowed)
    return {"n": pooled_n}, denied_ports


def parse_args(argv):
    """Simple argument parser without argparse to stay stdlib-safe."""
    args = argv[1:]
    if not args:
        print('usage: python client.py "query" [--sites PORT ...] [--key KEY]',
              file=sys.stderr)
        sys.exit(1)
    query = args[0]
    ports = []
    api_key = None
    i = 1
    while i < len(args):
        if args[i] == "--sites":
            i += 1
            while i < len(args) and not args[i].startswith("--"):
                ports.append(int(args[i]))
                i += 1
        elif args[i] == "--key":
            i += 1
            if i < len(args):
                api_key = args[i]
                i += 1
        else:
            i += 1
    return query, ports, api_key


def main():
    query, ports, api_key = parse_args(sys.argv)

    # Fall back to env var for API key.
    if api_key is None:
        api_key = os.environ.get("MEDMESH_KEY")

    if not ports:
        # Single-server mode (backward compatible).
        try:
            body = send_query(query, api_key=api_key)
        except urllib.error.URLError as exc:
            print(f"could not reach server: {exc.reason}", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(body, indent=2))
        return

    # Multi-site mode.
    site_results = []
    for port in ports:
        url = f"http://127.0.0.1:{port}/query"
        try:
            resp = send_query(query, url=url, api_key=api_key)
        except urllib.error.URLError as exc:
            print(f"  site :{port} -> could not reach: {exc.reason}")
            continue
        decision = resp.get("decision", "?")
        result_info = json.dumps(resp.get("result") or resp.get("reason", ""), indent=None)
        print(f"  site :{port} -> {decision}: {result_info}")
        site_results.append((port, resp))

    if not site_results:
        print("no sites responded")
        sys.exit(1)

    pooled, excluded = pool_results(site_results)

    if excluded:
        print(f"Partial result, excluded sites: {excluded}")

    if pooled is None:
        # All sites denied.
        reasons = set()
        for _, r in site_results:
            reasons.add(r.get("reason", "denied"))
        print(f"All sites denied. Reasons: {', '.join(sorted(reasons))}")
        return

    print(f"Pooled result: {json.dumps(pooled)}")


if __name__ == "__main__":
    main()
