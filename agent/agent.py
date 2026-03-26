"""
AutoLogAnalyzer agent.

Orchestrates the three analysis skills (business, system, resource) and
produces a unified, human-readable report.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from enum import Enum
from typing import Optional

from skills.business_log import BusinessLogAnalyzer
from skills.resource_log import ResourceLogAnalyzer
from skills.system_log import SystemLogAnalyzer


class LogType(Enum):
    """Supported log categories."""

    BUSINESS = "business"
    SYSTEM = "system"
    RESOURCE = "resource"
    AUTO = "auto"  # auto-detect


# Heuristic patterns used when log_type=AUTO
_BUSINESS_KEYWORDS = {"elapsed", "duration", "latency", "request", "response", "http", "api"}
_SYSTEM_KEYWORDS = {"sshd", "kernel", "systemd", "auth", "pam", "sudo", "cron", "syslog"}
_RESOURCE_KEYWORDS = {"cpu", "mem", "disk", "load", "network", "rx", "tx", "bandwidth"}


class AutoLogAnalyzerAgent:
    """
    Top-level agent that dispatches log files to the appropriate analyzer skill.

    Usage::

        agent = AutoLogAnalyzerAgent()
        result = agent.analyze_file("app.log", log_type=LogType.AUTO)
        agent.print_report(result)

    The agent can also analyze raw text lines::

        result = agent.analyze_lines(lines, log_type=LogType.SYSTEM)
    """

    def __init__(
        self,
        slow_threshold_ms: float = 1000.0,
        brute_force_threshold: int = 5,
        resource_thresholds: Optional[dict] = None,
        top_n: int = 10,
    ):
        self._business = BusinessLogAnalyzer(
            slow_threshold_ms=slow_threshold_ms, top_n=top_n
        )
        self._system = SystemLogAnalyzer(
            brute_force_threshold=brute_force_threshold, top_n=top_n
        )
        self._resource = ResourceLogAnalyzer(
            thresholds=resource_thresholds, top_n=top_n
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_file(self, path: str, log_type: LogType = LogType.AUTO) -> dict:
        """
        Analyze the log file at *path*.

        Parameters
        ----------
        path:
            Filesystem path to the log file.
        log_type:
            Category of the log. Use :attr:`LogType.AUTO` to let the agent
            detect it automatically from the file name and content.
        """
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Log file not found: {path}")

        if log_type == LogType.AUTO:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                sample = fh.read(4096)
            log_type = self._detect_type(os.path.basename(path), sample)

        analyzer = self._get_analyzer(log_type)
        result = analyzer.analyze_file(path)
        return self._wrap(result, log_type, source=path)

    def analyze_lines(self, lines, log_type: LogType = LogType.BUSINESS) -> dict:
        """Analyze an iterable of log lines."""
        analyzer = self._get_analyzer(log_type)
        result = analyzer.analyze(lines)
        return self._wrap(result, log_type, source="<lines>")

    def print_report(self, result: dict) -> None:
        """Print a human-readable report to stdout."""
        _print_report(result)

    def to_json(self, result: dict, indent: int = 2) -> str:
        """Serialize the analysis result to a JSON string."""
        return json.dumps(result, indent=indent, default=str)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_analyzer(self, log_type: LogType):
        return {
            LogType.BUSINESS: self._business,
            LogType.SYSTEM: self._system,
            LogType.RESOURCE: self._resource,
        }[log_type]

    @staticmethod
    def _detect_type(filename: str, sample: str) -> LogType:
        """Heuristic log-type detection from file name and content sample."""
        lower_name = filename.lower()
        lower_sample = sample.lower()

        # File name hints
        if any(kw in lower_name for kw in ("syslog", "auth", "kern", "secure", "messages")):
            return LogType.SYSTEM
        if any(kw in lower_name for kw in ("resource", "cpu", "metric", "perf", "monitor")):
            return LogType.RESOURCE

        # Content heuristics – count keyword hits
        scores = {LogType.BUSINESS: 0, LogType.SYSTEM: 0, LogType.RESOURCE: 0}
        for kw in _BUSINESS_KEYWORDS:
            scores[LogType.BUSINESS] += lower_sample.count(kw)
        for kw in _SYSTEM_KEYWORDS:
            scores[LogType.SYSTEM] += lower_sample.count(kw)
        for kw in _RESOURCE_KEYWORDS:
            scores[LogType.RESOURCE] += lower_sample.count(kw)

        return max(scores, key=scores.get)

    @staticmethod
    def _wrap(result: dict, log_type: LogType, source: str) -> dict:
        return {
            "meta": {
                "source": source,
                "log_type": log_type.value,
                "analyzed_at": datetime.now().isoformat(),
            },
            "result": result,
        }


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

_SEP = "=" * 68
_SUB = "-" * 68


def _print_report(data: dict) -> None:
    meta = data.get("meta", {})
    result = data.get("result", {})

    print(_SEP)
    print("  AutoLogAnalyzer Report")
    print(_SEP)
    print(f"  Source   : {meta.get('source', 'N/A')}")
    print(f"  Log Type : {meta.get('log_type', 'N/A')}")
    print(f"  Analyzed : {meta.get('analyzed_at', 'N/A')}")
    print(_SEP)

    log_type = meta.get("log_type", "")

    if log_type == LogType.BUSINESS.value:
        _print_business(result)
    elif log_type == LogType.SYSTEM.value:
        _print_system(result)
    elif log_type == LogType.RESOURCE.value:
        _print_resource(result)
    else:
        # Generic fallback
        print(json.dumps(result, indent=2, default=str))

    print(_SEP)


def _print_business(r: dict) -> None:
    print(f"  Total log entries : {r.get('total', 0)}")
    print(f"  Error rate        : {r.get('error_rate_pct', 0):.2f}%")
    print()
    _print_dict_table("Log Level Distribution", r.get("by_level", {}))
    _print_latency(r.get("latency_stats", {}))
    _print_list_section("Top Errors (sample)", r.get("errors", []),
                        fields=["time", "level", "source", "message"])
    _print_dict_table("Top Error Patterns", r.get("top_errors", {}))
    _print_list_section("Slow Requests (sample)", r.get("slow_requests", []),
                        fields=["time", "latency_ms", "message"])


def _print_system(r: dict) -> None:
    print(f"  Total log entries       : {r.get('total', 0)}")
    print(f"  Auth failures           : {r.get('auth_failure_count', 0)}")
    print(f"  Auth successes          : {r.get('auth_success_count', 0)}")
    print(f"  Service crash events    : {r.get('service_crash_count', 0)}")
    print(f"  Kernel error events     : {r.get('kernel_error_count', 0)}")
    print(f"  Sudo / priv-esc events  : {r.get('sudo_event_count', 0)}")
    print()
    bf = r.get("brute_force_ips", {})
    if bf:
        print("  !! BRUTE-FORCE IPs DETECTED !!")
        for ip, cnt in bf.items():
            print(f"     {ip:20s}  {cnt} failures")
        print()
    _print_list_section("Auth Failures (sample)", r.get("auth_failures", []),
                        fields=["time", "ip", "user", "message"])
    _print_list_section("Service Crashes (sample)", r.get("service_crashes", []),
                        fields=["time", "source", "message"])
    _print_list_section("Kernel Errors (sample)", r.get("kernel_errors", []),
                        fields=["time", "source", "message"])


def _print_resource(r: dict) -> None:
    print(f"  Total log entries : {r.get('total', 0)}")
    print(f"  Alert count       : {r.get('alert_count', 0)}")
    print()
    metrics = r.get("metrics", {})
    if metrics:
        print("  Per-Metric Statistics:")
        print(f"  {'Metric':<20} {'Count':>6} {'Min':>8} {'Mean':>8} {'Max':>8} "
              f"{'P95':>8} {'P99':>8}")
        print("  " + _SUB)
        for name, stats in sorted(metrics.items()):
            print(f"  {name:<20} {stats.get('count', 0):>6} "
                  f"{stats.get('min', 0):>8.2f} {stats.get('mean', 0):>8.2f} "
                  f"{stats.get('max', 0):>8.2f} {stats.get('p95', 0):>8.2f} "
                  f"{stats.get('p99', 0):>8.2f}")
        print()
    _print_list_section("Resource Alerts (sample)", r.get("alerts", []),
                        fields=["time", "metric", "value", "threshold", "description"])
    sus = r.get("sustained_alerts", [])
    if sus:
        print("  Sustained High-Utilization Events:")
        for s in sus:
            print(f"    {s.get('metric')}: {s.get('mean')} (peak {s.get('peak')}) "
                  f"for {s.get('samples')} consecutive samples "
                  f"[{s.get('start')} – {s.get('end')}]")
        print()


def _print_dict_table(title: str, data: dict) -> None:
    if not data:
        return
    print(f"  {title}:")
    for k, v in data.items():
        print(f"    {str(k):<40}  {v}")
    print()


def _print_latency(stats: dict) -> None:
    if not stats:
        return
    print("  Latency Statistics (ms):")
    for k, v in stats.items():
        print(f"    {k:<12}: {v}")
    print()


def _print_list_section(title: str, items: list, fields: list) -> None:
    if not items:
        return
    print(f"  {title}:")
    print(_SUB)
    for item in items:
        parts = []
        for f in fields:
            val = item.get(f, "")
            if val not in (None, ""):
                parts.append(f"{f}={val}")
        print("  " + "  ".join(parts))
    print()
