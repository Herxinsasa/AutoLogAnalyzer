"""
Resource statistics log analyzer skill.

Analyzes logs that contain CPU / memory / disk / network metrics to surface:
- Peak and average resource utilization
- Threshold breaches (high CPU, low memory, disk near full, etc.)
- Sustained high-utilization periods
- Per-metric time-series statistics
"""

from __future__ import annotations

import re
import statistics
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from utils.log_parser import LogEntry, LogLevel, LogParser


# ---------------------------------------------------------------------------
# Metric extraction patterns
# ---------------------------------------------------------------------------

# Generic: key=value or "key: value" where value has an optional unit
_KV_RE = re.compile(
    r"(?P<key>[a-zA-Z_][a-zA-Z0-9_%\-]*)[\s:=]+(?P<val>\d+(?:\.\d+)?)"
    r"\s*(?P<unit>%|mb|gb|kb|bytes?|b|ms|s|bps|kbps|mbps)?",
    re.IGNORECASE,
)

# Metric name aliases → canonical name
_METRIC_ALIASES: Dict[str, str] = {
    # CPU
    "cpu": "cpu_pct",
    "cpu_usage": "cpu_pct",
    "cpu_percent": "cpu_pct",
    "cpu_utilization": "cpu_pct",
    "us": "cpu_pct",
    # Memory
    "mem": "mem_pct",
    "memory": "mem_pct",
    "mem_usage": "mem_pct",
    "memory_usage": "mem_pct",
    "mem_percent": "mem_pct",
    "mem_used_pct": "mem_pct",
    "mem_free": "mem_free_mb",
    "free": "mem_free_mb",
    "available": "mem_avail_mb",
    "used": "mem_used_mb",
    # Disk
    "disk": "disk_pct",
    "disk_usage": "disk_pct",
    "disk_used": "disk_pct",
    "disk_free": "disk_free_gb",
    # Network
    "rx": "net_rx_kbps",
    "tx": "net_tx_kbps",
    "network_in": "net_rx_kbps",
    "network_out": "net_tx_kbps",
    "bandwidth": "net_rx_kbps",
    # Load average
    "load": "load_avg",
    "load_avg": "load_avg",
    "load_average": "load_avg",
    "load1": "load_avg",
}

# Default alert thresholds
_DEFAULT_THRESHOLDS: Dict[str, Tuple[float, str]] = {
    "cpu_pct": (85.0, "CPU usage above 85%"),
    "mem_pct": (90.0, "Memory usage above 90%"),
    "disk_pct": (90.0, "Disk usage above 90%"),
    "load_avg": (4.0, "Load average above 4.0"),
}


class ResourceLogAnalyzer:
    """
    Skill for analyzing resource / performance metric logs.

    Supports any log format where numeric metrics are embedded as key=value
    pairs or in structured JSON.  Common examples::

        2024-01-01 12:00:00 cpu=72.3% mem=45.1% disk=60% load=1.2
        {"timestamp":"2024-01-01T12:00:00","cpu_percent":72.3,"mem_usage":45.1}

    Detection capabilities:

    - Per-metric descriptive statistics (min, max, mean, p95, p99)
    - Threshold-breach alerts
    - Sustained high-utilization windows (consecutive samples above threshold)
    - Top *n* busiest time slots per metric
    """

    def __init__(
        self,
        thresholds: Optional[Dict[str, float]] = None,
        sustained_window: int = 5,
        top_n: int = 10,
    ):
        """
        Parameters
        ----------
        thresholds:
            Dict mapping canonical metric name → alert threshold value.
            Defaults to :data:`_DEFAULT_THRESHOLDS`.
        sustained_window:
            Number of consecutive samples above threshold to flag as
            a "sustained high utilization" event.
        top_n:
            Number of top items returned in summaries.
        """
        self.thresholds: Dict[str, float] = {
            k: v for k, (v, _) in _DEFAULT_THRESHOLDS.items()
        }
        if thresholds:
            self.thresholds.update(thresholds)
        self.sustained_window = sustained_window
        self.top_n = top_n
        self._parser = LogParser()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, lines) -> dict:
        """
        Analyze an iterable of resource log lines.

        Returns a dict with keys:
        ``total``, ``metrics``, ``alerts``, ``sustained_alerts``,
        ``hourly_trend``, ``top_busy_slots``.
        """
        entries = self._parser.parse_lines(lines)
        return self._analyze_entries(entries)

    def analyze_file(self, path: str) -> dict:
        """Analyze a resource log file at *path*."""
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return self.analyze(fh)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _analyze_entries(self, entries: List[LogEntry]) -> dict:
        total = len(entries)

        # metric_name → list of (timestamp, value) samples
        metric_series: Dict[str, List[Tuple[Optional[datetime], float]]] = defaultdict(list)
        alerts: list = []
        hourly: defaultdict = defaultdict(lambda: defaultdict(list))

        for entry in entries:
            metrics = self._extract_metrics(entry)
            for metric, value in metrics.items():
                metric_series[metric].append((entry.timestamp, value))

                if entry.timestamp:
                    hour_key = entry.timestamp.strftime("%Y-%m-%d %H:00")
                    hourly[hour_key][metric].append(value)

                threshold = self.thresholds.get(metric)
                if threshold is not None and value >= threshold:
                    _, desc = _DEFAULT_THRESHOLDS.get(
                        metric, (threshold, f"{metric} above {threshold}")
                    )
                    alerts.append({
                        "time": self._fmt_ts(entry.timestamp),
                        "metric": metric,
                        "value": value,
                        "threshold": threshold,
                        "description": desc,
                        "message": entry.message[:200],
                    })

        # Descriptive stats per metric
        metric_stats: dict = {}
        for metric, samples in metric_series.items():
            values = [v for _, v in samples]
            metric_stats[metric] = self._describe(values)

        # Sustained high-utilization detection
        sustained_alerts = self._detect_sustained(metric_series)

        # Hourly summary: mean of each metric per hour
        hourly_trend: dict = {}
        for hour, metrics_map in sorted(hourly.items()):
            hourly_trend[hour] = {
                m: round(statistics.mean(vals), 2)
                for m, vals in metrics_map.items()
            }

        # Top busy slots: hours with highest average CPU/mem
        top_busy = self._top_busy_slots(hourly_trend)

        return {
            "total": total,
            "metrics": metric_stats,
            "alerts": alerts[: self.top_n],
            "alert_count": len(alerts),
            "sustained_alerts": sustained_alerts,
            "hourly_trend": hourly_trend,
            "top_busy_slots": top_busy,
        }

    def _extract_metrics(self, entry: LogEntry) -> Dict[str, float]:
        metrics: Dict[str, float] = {}

        # JSON-sourced numeric fields first
        for key, value in entry.extra.items():
            try:
                fval = float(value)
            except (TypeError, ValueError):
                continue
            canonical = _METRIC_ALIASES.get(key.lower(), key.lower())
            metrics[canonical] = fval

        # Text extraction via key=value regex
        for m in _KV_RE.finditer(entry.message):
            key = m.group("key").lower()
            canonical = _METRIC_ALIASES.get(key)
            if canonical is None:
                continue  # only track known metrics to avoid noise
            try:
                value = float(m.group("val"))
            except ValueError:
                continue
            unit = (m.group("unit") or "").lower()
            value = self._normalize_unit(value, unit, canonical)
            metrics[canonical] = value

        return metrics

    @staticmethod
    def _normalize_unit(value: float, unit: str, metric: str) -> float:
        """Convert raw values to canonical units (percent or MB/GB/Kbps)."""
        if unit in ("gb",):
            if "mb" in metric:
                return value * 1024
        if unit in ("kb",):
            if "mb" in metric:
                return value / 1024
        return value

    def _detect_sustained(
        self, metric_series: Dict[str, List[Tuple[Optional[datetime], float]]]
    ) -> list:
        sustained: list = []
        for metric, samples in metric_series.items():
            threshold = self.thresholds.get(metric)
            if threshold is None:
                continue
            window: list = []
            for ts, value in samples:
                if value >= threshold:
                    window.append((ts, value))
                    if len(window) == self.sustained_window:
                        sustained.append({
                            "metric": metric,
                            "threshold": threshold,
                            "samples": self.sustained_window,
                            "start": self._fmt_ts(window[0][0]),
                            "end": self._fmt_ts(window[-1][0]),
                            "peak": max(v for _, v in window),
                            "mean": round(statistics.mean(v for _, v in window), 2),
                        })
                        window = []  # reset to avoid overlapping alerts
                else:
                    window = []
        return sustained

    def _top_busy_slots(self, hourly_trend: dict) -> list:
        """Return top-N hours ranked by average CPU + memory utilization."""
        scores: list = []
        for hour, metrics in hourly_trend.items():
            score = metrics.get("cpu_pct", 0) + metrics.get("mem_pct", 0)
            scores.append((hour, score, metrics))
        scores.sort(key=lambda x: x[1], reverse=True)
        return [
            {"hour": h, "score": round(s, 2), "metrics": m}
            for h, s, m in scores[: self.top_n]
        ]

    @staticmethod
    def _describe(values: list) -> dict:
        if not values:
            return {}
        return {
            "count": len(values),
            "min": round(min(values), 2),
            "max": round(max(values), 2),
            "mean": round(statistics.mean(values), 2),
            "p50": round(statistics.median(values), 2),
            "p95": round(ResourceLogAnalyzer._percentile(values, 95), 2),
            "p99": round(ResourceLogAnalyzer._percentile(values, 99), 2),
        }

    @staticmethod
    def _percentile(data: list, pct: float) -> float:
        sorted_data = sorted(data)
        k = (len(sorted_data) - 1) * pct / 100
        lo, hi = int(k), min(int(k) + 1, len(sorted_data) - 1)
        return sorted_data[lo] + (sorted_data[hi] - sorted_data[lo]) * (k - lo)

    @staticmethod
    def _fmt_ts(ts: Optional[datetime]) -> str:
        return ts.isoformat() if ts else ""
