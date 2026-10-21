"""Verify the tamper-evident chain of a MedMesh audit log.

Usage:
  python verify_log.py logs/site_a.jsonl

Prints OK if the chain is intact, or the first broken line number.
"""

import hashlib
import json
import sys
from pathlib import Path


def verify(path):
    """Verify the hash chain in a .jsonl log file.

    Returns (ok, broken_line_number). broken_line_number is None if ok.
    """
    prev_hash = "0"
    line_num = 0
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.rstrip("\n")
            if not raw:
                continue
            line_num += 1
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                return False, line_num

            stored_hash = entry.get("entry_hash", "")
            stored_prev = entry.get("prev_hash", "")

            if stored_prev != prev_hash:
                return False, line_num

            # Recompute entry_hash.
            check_entry = {k: v for k, v in entry.items() if k != "entry_hash"}
            content = json.dumps(check_entry, sort_keys=True)
            expected = hashlib.sha256((content + prev_hash).encode("utf-8")).hexdigest()

            if expected != stored_hash:
                return False, line_num

            prev_hash = stored_hash

    if line_num == 0:
        print("log is empty")
        return True, None
    return True, None


def main():
    if len(sys.argv) != 2:
        print("usage: python verify_log.py <logfile>", file=sys.stderr)
        sys.exit(1)
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"file not found: {path}", file=sys.stderr)
        sys.exit(1)
    ok, broken_line = verify(path)
    if ok:
        print("OK")
    else:
        print(f"chain broken at line {broken_line}")
        sys.exit(1)


if __name__ == "__main__":
    main()
