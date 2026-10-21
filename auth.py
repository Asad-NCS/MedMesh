"""API key authentication and per-user rate limiting for MedMesh.

Keys are loaded from keys.json next to server.py:
  {
    "researcher_ana": {"key": "key_ana_secure_001", "limit": 30},
    ...
  }

If keys.json is missing, all requests are allowed as user "anonymous".
"""

import json
import threading
import time
from collections import defaultdict
from pathlib import Path


def _deny(reason):
    """Return a standard deny response dict."""
    return {"decision": "deny", "reason": reason}


def load_keys(path):
    """Load API keys from a JSON file. Returns empty dict if file missing."""
    p = Path(path)
    if not p.exists():
        return {}
    with p.open(encoding="utf-8") as fh:
        return json.load(fh)


class AuthState:
    """Holds per-site authentication and rate-limit state."""

    def __init__(self, keys_data=None):
        self.keys_data = keys_data if keys_data is not None else {}
        self._rate_lock = threading.Lock()
        # _rate_counts[user] = [timestamp, ...]
        self._rate_counts = defaultdict(list)

    def check_key(self, key_value):
        """Return (user, deny_response_or_None).

        If no keys are configured, all requests pass as "anonymous".
        """
        if not self.keys_data:
            return "anonymous", None
        if not key_value:
            return None, _deny("invalid or missing API key")
        for user, info in self.keys_data.items():
            if info.get("key") == key_value:
                return user, None
        return None, _deny("invalid or missing API key")

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
                return _deny("rate limit exceeded")
            stamps.append(now)
        return None
