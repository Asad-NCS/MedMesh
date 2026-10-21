"""Hash-chained audit log for MedMesh.

Each request is appended to logs/<site-name>.jsonl as a JSON line.
Fields: ts, site, user, query, decision, reason, prev_hash, entry_hash.
entry_hash = SHA-256(sorted JSON of all fields except entry_hash + prev_hash).

Tamper detection: verify_log.py reads the file and recomputes each hash.
"""

import hashlib
import json
import threading
import time
from pathlib import Path


class AuditLog:
    """Append-only tamper-evident log for one site."""

    def __init__(self, logs_dir, site_name):
        self._site_name = site_name
        logs_dir = Path(logs_dir)
        logs_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = logs_dir / f"{site_name}.jsonl"
        self._lock = threading.Lock()
        self._prev_hash = "0"

    @property
    def log_path(self):
        return self._log_path

    def append(self, user, query, decision, reason):
        """Append a tamper-evident JSON line."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry = {
            "ts": ts,
            "site": self._site_name,
            "user": user if user else "",
            "query": query,
            "decision": decision,
            "reason": reason if reason else "",
            "prev_hash": self._prev_hash,
        }
        content = json.dumps(entry, sort_keys=True)
        entry_hash = hashlib.sha256(
            (content + self._prev_hash).encode("utf-8")
        ).hexdigest()
        entry["entry_hash"] = entry_hash
        line = json.dumps(entry)
        with self._lock:
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self._prev_hash = entry_hash
