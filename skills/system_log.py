"""
System log analyzer skill.

Analyzes OS / syslog-style logs to surface:
- Authentication failures and potential brute-force attacks
- Service crash / restart events
- Kernel errors and OOM events
- SSH and sudo activity
- Hourly event distribution
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import List, Optional

from utils.log_parser import LogEntry, LogLevel, LogParser


# ---------------------------------------------------------------------------
# Keyword patterns for system event classification
# ---------------------------------------------------------------------------

_AUTH_FAILURE_PATTERNS = re.compile(
    r"authentication failure|failed password|invalid user|"
    r"connection closed by|did not receive identification|"
    r"refused connect|pam_unix.*failure",
    re.IGNORECASE,
)

_AUTH_SUCCESS_PATTERNS = re.compile(
    r"accepted password|accepted publickey|session opened|"
    r"new session",
    re.IGNORECASE,
)

_SERVICE_CRASH_PATTERNS = re.compile(
    r"segfault|core dumped|killed|oom.killer|"
    r"out of memory|process .* exited|start job failed|"
    r"failed to start|service entered failed",
    re.IGNORECASE,
)

_KERNEL_ERROR_PATTERNS = re.compile(
    r"kernel panic|call trace|bug:|general protection|"
    r"hardware error|mce:.*error|nmi:|unhandled irq",
    re.IGNORECASE,
)

_SUDO_PATTERNS = re.compile(r"\bsudo\b|\bsu\b.*to\s+\w+", re.IGNORECASE)

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(
    r"(?:invalid\s+user|for\s+(?:invalid\s+user\s+)?|user\s+)([A-Za-z0-9_\-\.]+)",
    re.IGNORECASE,
)


class SystemLogAnalyzer:
    """
    Skill for analyzing system / OS logs (syslog, journald, auth.log, kern.log, etc.).

    Detection categories:

    - **auth_failures** – failed login attempts; repeated IPs flagged as brute-force
    - **auth_successes** – successful logins
    - **service_crashes** – service failures / OOM kills
    - **kernel_errors** – kernel panics, MCE errors, etc.
    - **sudo_events** – privilege escalation events
    - **brute_force_ips** – IPs with ≥ *brute_force_threshold* failures
    """

    def __init__(self, brute_force_threshold: int = 5, top_n: int = 10):
        """
        Parameters
        ----------
        brute_force_threshold:
            Minimum number of auth failures from a single IP to flag as brute-force.
        top_n:
            Number of top items returned in frequency summaries.
        """
        self.brute_force_threshold = brute_force_threshold
        self.top_n = top_n
        self._parser = LogParser()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, lines) -> dict:
        """
        Analyze an iterable of system log lines.

        Returns a dict with keys:
        ``total``, ``by_level``, ``auth_failures``, ``auth_successes``,
        ``service_crashes``, ``kernel_errors``, ``sudo_events``,
        ``brute_force_ips``, ``top_sources``, ``hourly_trend``.
        """
        entries = self._parser.parse_lines(lines)
        return self._analyze_entries(entries)

    def analyze_file(self, path: str) -> dict:
        """Analyze a system log file at *path*."""
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return self.analyze(fh)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _analyze_entries(self, entries: List[LogEntry]) -> dict:
        total = len(entries)
        by_level: Counter = Counter()
        auth_failures: list = []
        auth_successes: list = []
        service_crashes: list = []
        kernel_errors: list = []
        sudo_events: list = []
        ip_failure_counts: Counter = Counter()
        sources: Counter = Counter()
        hourly: Counter = Counter()

        for entry in entries:
            by_level[entry.level.value] += 1

            if entry.timestamp:
                hour_key = entry.timestamp.strftime("%Y-%m-%d %H:00")
                hourly[hour_key] += 1

            if entry.source:
                sources[entry.source] += 1

            msg = entry.message
            record = {
                "time": self._fmt_ts(entry.timestamp),
                "source": entry.source,
                "message": msg[:300],
            }

            if _AUTH_FAILURE_PATTERNS.search(msg):
                ip = self._extract_ip(msg)
                user = self._extract_user(msg)
                rec = {**record, "ip": ip, "user": user}
                auth_failures.append(rec)
                if ip:
                    ip_failure_counts[ip] += 1

            elif _AUTH_SUCCESS_PATTERNS.search(msg):
                ip = self._extract_ip(msg)
                user = self._extract_user(msg)
                auth_successes.append({**record, "ip": ip, "user": user})

            if _SERVICE_CRASH_PATTERNS.search(msg):
                service_crashes.append(record)

            if _KERNEL_ERROR_PATTERNS.search(msg):
                kernel_errors.append(record)

            if _SUDO_PATTERNS.search(msg) or "sudo" in entry.source.lower():
                sudo_events.append(record)

        brute_force_ips = {
            ip: count
            for ip, count in ip_failure_counts.most_common()
            if count >= self.brute_force_threshold
        }

        return {
            "total": total,
            "by_level": dict(by_level),
            "auth_failures": auth_failures[: self.top_n],
            "auth_failure_count": len(auth_failures),
            "auth_successes": auth_successes[: self.top_n],
            "auth_success_count": len(auth_successes),
            "service_crashes": service_crashes[: self.top_n],
            "service_crash_count": len(service_crashes),
            "kernel_errors": kernel_errors[: self.top_n],
            "kernel_error_count": len(kernel_errors),
            "sudo_events": sudo_events[: self.top_n],
            "sudo_event_count": len(sudo_events),
            "brute_force_ips": brute_force_ips,
            "top_sources": dict(sources.most_common(self.top_n)),
            "hourly_trend": dict(sorted(hourly.items())),
        }

    @staticmethod
    def _extract_ip(text: str) -> str:
        m = _IP_RE.search(text)
        return m.group() if m else ""

    @staticmethod
    def _extract_user(text: str) -> str:
        m = _USER_RE.search(text)
        return m.group(1) if m else ""

    @staticmethod
    def _fmt_ts(ts: Optional[datetime]) -> str:
        return ts.isoformat() if ts else ""
