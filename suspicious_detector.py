from typing import List, Dict, Optional
from collections import defaultdict

class SuspiciousDetector:
    """Detects suspicious activity from parsed Apache log entries."""

    def __init__(self):
        self._ip_failures = defaultdict(int)  # Track failed logins per IP
        self._alerts: List[str] = []

    def analyse(self, logs: List[Dict[str, str]]) -> None:
        """
        Analyse a list of parsed logs for suspicious patterns.
        Stores alert messages internally.
        """
        for entry in logs:
            if alert := self._detect(entry):
                self._alerts.append(alert)

    def _detect(self, entry: Dict[str, str]) -> Optional[str]:
        """
        Internal method that checks one log entry for suspicious signs.
        Returns an alert message if suspicious, else None.
        """
        ip = entry["ip"]
        path = entry["path"]
        status = entry["status"]

        # Brute force detection: multiple 403s or 401s from same IP
        if status in ("401", "403"):
            self._ip_failures[ip] += 1
            if self._ip_failures[ip] >= 5:
                return f"⚠️  Possible brute force attack from {ip} ({self._ip_failures[ip]} failed attempts)"

        # Sensitive path access
        if any(suspicious in path.lower() for suspicious in ["/admin", "/login", "/config", "/etc/passwd"]):
            return f"⚠️  Suspicious path access: {ip} tried to access {path}"

        # Repeated 404s might indicate scanning/probing
        if status == "404":
            return f"⚠️  404 Not Found from {ip} for {path} — could be probing"

        return None

    @property
    def alerts(self) -> List[str]:
        """Returns all alerts generated during analysis."""
        return self._alerts.copy()

    def clear(self) -> None:
        """Clears stored alert history and IP state."""
        self._ip_failures.clear()
        self._alerts.clear()
