"""
Business log analyzer skill.

Analyzes structured application / business logs to surface:
- Error rates and error summaries
- Slow request / latency anomalies
- Most frequent error messages
- Hourly activity trends
"""

from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import List, Optional

from utils.log_parser import LogEntry, LogLevel, LogParser


class BusinessLogAnalyzer:
    """
    Skill for analyzing business / application logs.

    Supported log formats (auto-detected via :class:`~utils.log_parser.LogParser`):
    - JSON lines (recommended – richest data)
    - Common app log  ``2024-01-01 12:00:00 [LEVEL] source: message``
    - Apache / Nginx combined access log
    - Plain text with embedded level keywords
    """

    # Latency extraction: looks for patterns like "elapsed=123ms", "duration: 45ms",
    # "took 200ms", "latency=1.5s"
    _LATENCY_RE = re.compile(
        r"(?:elapsed|duration|latency|took|time)[=:\s]+(\d+(?:\.\d+)?)\s*(ms|s|µs|us)?",
        re.IGNORECASE,
    )

    # HTTP status code extraction
    _STATUS_RE = re.compile(r"\bstatus[=:\s]+(\d{3})\b", re.IGNORECASE)

    def __init__(self, slow_threshold_ms: float = 1000.0, top_n: int = 10):
        """
        Parameters
        ----------
        slow_threshold_ms:
            Requests with latency above this value (milliseconds) are flagged as slow.
        top_n:
            Number of top items to show in frequency-based summaries.
        """
        self.slow_threshold_ms = slow_threshold_ms
        self.top_n = top_n
        self._parser = LogParser()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, lines) -> dict:
        """
        Analyze an iterable of log lines.

        Returns a result dict with keys:
        ``total``, ``by_level``, ``error_rate``, ``errors``,
        ``slow_requests``, ``latency_stats``, ``hourly_trend``,
        ``top_sources``, ``top_errors``.
        """
        entries = self._parser.parse_lines(lines)
        return self._analyze_entries(entries)

    def analyze_file(self, path: str) -> dict:
        """Analyze a log file at *path*."""
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return self.analyze(fh)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _analyze_entries(self, entries: List[LogEntry]) -> dict:
        total = len(entries)
        by_level: Counter = Counter()
        errors: list = []
        latencies: list = []
        slow_requests: list = []
        hourly: Counter = Counter()
        sources: Counter = Counter()
        error_messages: Counter = Counter()

        for entry in entries:
            by_level[entry.level.value] += 1

            if entry.timestamp:
                hour_key = entry.timestamp.strftime("%Y-%m-%d %H:00")
                hourly[hour_key] += 1

            if entry.source:
                sources[entry.source] += 1

            if entry.is_error():
                errors.append({"time": self._fmt_ts(entry.timestamp),
                                "level": entry.level.value,
                                "source": entry.source,
                                "message": entry.message[:200]})
                error_messages[self._normalize_error(entry.message)] += 1

            latency = self._extract_latency_ms(entry)
            if latency is not None:
                latencies.append(latency)
                if latency >= self.slow_threshold_ms:
                    slow_requests.append({
                        "time": self._fmt_ts(entry.timestamp),
                        "latency_ms": latency,
                        "message": entry.message[:200],
                    })

        error_count = by_level.get("ERROR", 0) + by_level.get("CRITICAL", 0)
        error_rate = round(error_count / total * 100, 2) if total else 0.0

        latency_stats: dict = {}
        if latencies:
            latency_stats = {
                "count": len(latencies),
                "min_ms": round(min(latencies), 2),
                "max_ms": round(max(latencies), 2),
                "mean_ms": round(statistics.mean(latencies), 2),
                "p50_ms": round(statistics.median(latencies), 2),
                "p95_ms": round(self._percentile(latencies, 95), 2),
                "p99_ms": round(self._percentile(latencies, 99), 2),
            }

        return {
            "total": total,
            "by_level": dict(by_level),
            "error_rate_pct": error_rate,
            "errors": errors[: self.top_n],
            "slow_requests": slow_requests[: self.top_n],
            "latency_stats": latency_stats,
            "hourly_trend": dict(sorted(hourly.items())),
            "top_sources": dict(sources.most_common(self.top_n)),
            "top_errors": dict(error_messages.most_common(self.top_n)),
        }

    def _extract_latency_ms(self, entry: LogEntry) -> Optional[float]:
        # JSON extra fields first
        for key in ("duration", "elapsed", "latency", "response_time", "duration_ms"):
            if key in entry.extra:
                try:
                    val = float(entry.extra[key])
                    # Heuristic: if field name suggests ms, use directly; else assume seconds
                    if "ms" in key:
                        return val
                    return val * 1000 if val < 1000 else val
                except (TypeError, ValueError):
                    pass

        m = self._LATENCY_RE.search(entry.message)
        if not m:
            return None
        val = float(m.group(1))
        unit = (m.group(2) or "ms").lower()
        if unit in ("s",):
            return val * 1000
        if unit in ("µs", "us"):
            return val / 1000
        return val  # ms

    @staticmethod
    def _normalize_error(message: str) -> str:
        """Strip volatile parts (numbers, UUIDs) to group similar errors."""
        normalized = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                             "<uuid>", message, flags=re.IGNORECASE)
        normalized = re.sub(r"\b\d+\b", "<N>", normalized)
        return normalized[:120]

    @staticmethod
    def _percentile(data: list, pct: float) -> float:
        sorted_data = sorted(data)
        k = (len(sorted_data) - 1) * pct / 100
        lo, hi = int(k), min(int(k) + 1, len(sorted_data) - 1)
        return sorted_data[lo] + (sorted_data[hi] - sorted_data[lo]) * (k - lo)

    @staticmethod
    def _fmt_ts(ts: Optional[datetime]) -> str:
        return ts.isoformat() if ts else ""
