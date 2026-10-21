"""Researcher client: send one query and print the server's decision."""

import json
import sys
import urllib.error
import urllib.request

SERVER_URL = "http://127.0.0.1:8000/query"


def send_query(query, url=SERVER_URL):
    payload = json.dumps({"query": query}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        return json.loads(response.read().decode("utf-8"))


def main():
    if len(sys.argv) != 2:
        print('usage: python client.py "mean age"', file=sys.stderr)
        sys.exit(1)
    try:
        body = send_query(sys.argv[1])
    except urllib.error.URLError as exc:
        print(f"could not reach server: {exc.reason}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(body, indent=2))


if __name__ == "__main__":
    main()
