"""Overlap guard for MedMesh.

Per site, across all users, the server remembers the patient-id frozensets
behind each allowed query.  A new query with set S is denied if some prior
set P exists with S != P and |symmetric_difference(S, P)| < min_n.
An exact repeat of an earlier query set is allowed.
"""

import threading

_MIN_N = 5


def _deny(reason):
    return {"decision": "deny", "reason": reason}


class OverlapGuard:
    """Thread-safe overlap guard for one site."""

    def __init__(self, enabled=True, min_n=_MIN_N):
        self._enabled = enabled
        self._min_n = min_n
        self._lock = threading.Lock()
        self._seen_sets = []

    def check(self, new_set):
        """Return deny_response_or_None before recording a new query set.

        Returns None if the set is safe to release.
        Returns a deny dict if the set is too similar to a prior set.
        An exact repeat is always allowed.
        """
        if not self._enabled:
            return None
        with self._lock:
            for prior in self._seen_sets:
                if new_set == prior:
                    return None
                diff = new_set.symmetric_difference(prior)
                if len(diff) < self._min_n:
                    return _deny("too similar to an earlier query")
        return None

    def record(self, new_set):
        """Record a new patient-id set after the guard check has passed."""
        if not self._enabled:
            return
        with self._lock:
            if new_set not in self._seen_sets:
                self._seen_sets.append(new_set)
