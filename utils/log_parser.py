"""
Log parser utilities for AutoLogAnalyzer.

Provides common log entry parsing and normalization for all analyzer skills.
"""

import re
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class LogLevel(Enum):
    """Standard log severity levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_string(cls, value: str) -> "LogLevel":
        """Parse a log level from a string, case-insensitive."""
        normalized = value.strip().upper()
        aliases = {
            "WARN": "WARNING",
            "ERR": "ERROR",
            "CRIT": "CRITICAL",
            "FATAL": "CRITICAL",
            "TRACE": "DEBUG",
        }
        normalized = aliases.get(normalized, normalized)
        try:
            return cls(normalized)
        except ValueError:
            return cls.UNKNOWN


@dataclass
class LogEntry:
    """Represents a single parsed log entry."""

    raw: str
    timestamp: Optional[datetime] = None
    level: LogLevel = LogLevel.UNKNOWN
    source: str = ""
    message: str = ""
    extra: dict = field(default_factory=dict)

    def is_error(self) -> bool:
        return self.level in (LogLevel.ERROR, LogLevel.CRITICAL)

    def is_warning(self) -> bool:
        return self.level == LogLevel.WARNING


class LogParser:
    """
    Multi-format log parser that auto-detects common log formats.

    Supported formats:
    - JSON lines
    - Standard syslog  (e.g. ``Mar 26 10:00:00 host sshd: msg``)
    - Common app log   (e.g. ``2024-01-01 12:00:00 [INFO] source: msg``)
    - Apache/Nginx combined access log
    - Bare text lines (fallback)
    """

    # ISO / app-style: 2024-01-01 12:00:00.123 [LEVEL] source: message
    _APP_RE = re.compile(
        r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)"
        r"(?:\s+\[?(?P<level>[A-Z]+)\]?)?"
        r"(?:\s+(?P<source>\S+))?"
        r":\s*(?P<message>.*)"
    )

    # Syslog: Mar 26 10:00:00 hostname process[pid]: message
    _SYSLOG_RE = re.compile(
        r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
        r"\s+(?P<host>\S+)\s+(?P<source>\S+?)(?:\[\d+\])?:\s*(?P<message>.*)"
    )

    # Resource/CSV style: timestamp,metric,value,...
    _CSV_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^,]*),(.+)$")

    # Apache combined log
    _APACHE_RE = re.compile(
        r'(?P<host>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
        r'"(?P<request>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    )

    # Timestamp patterns used for generic extraction
    _TS_PATTERNS = [
        ("%Y-%m-%dT%H:%M:%S.%f", re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+")),
        ("%Y-%m-%dT%H:%M:%S", re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")),
        ("%Y-%m-%d %H:%M:%S.%f", re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+")),
        ("%Y-%m-%d %H:%M:%S", re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")),
        ("%b %d %H:%M:%S", re.compile(r"[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}")),
    ]

    def parse_line(self, line: str) -> LogEntry:
        """Parse a single log line and return a :class:`LogEntry`."""
        line = line.rstrip("\n\r")

        entry = (
            self._try_json(line)
            or self._try_apache(line)
            or self._try_app(line)
            or self._try_syslog(line)
            or self._try_csv(line)
            or LogEntry(raw=line, message=line)
        )

        # Fallback timestamp extraction if not already set
        if entry.timestamp is None:
            entry.timestamp = self._extract_timestamp(line)

        # Fallback level extraction if unknown
        if entry.level == LogLevel.UNKNOWN:
            entry.level = self._extract_level(line)

        return entry

    def parse_lines(self, lines) -> list:
        """Parse an iterable of lines and return a list of :class:`LogEntry`."""
        return [self.parse_line(line) for line in lines if line.strip()]

    # ------------------------------------------------------------------
    # Format-specific parsers
    # ------------------------------------------------------------------

    def _try_json(self, line: str) -> Optional[LogEntry]:
        if not line.startswith("{"):
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        ts = None
        for key in ("timestamp", "time", "ts", "@timestamp", "date"):
            if key in data:
                ts = self._parse_ts_string(str(data[key]))
                break

        level_str = ""
        for key in ("level", "severity", "log_level", "loglevel"):
            if key in data:
                level_str = str(data[key])
                break

        source = str(data.get("logger", data.get("source", data.get("service", ""))))
        message = str(data.get("message", data.get("msg", data.get("text", ""))))

        extra = {k: v for k, v in data.items()
                 if k not in ("timestamp", "time", "ts", "@timestamp", "date",
                              "level", "severity", "log_level", "loglevel",
                              "logger", "source", "service", "message", "msg", "text")}

        return LogEntry(
            raw=line,
            timestamp=ts,
            level=LogLevel.from_string(level_str) if level_str else LogLevel.UNKNOWN,
            source=source,
            message=message,
            extra=extra,
        )

    def _try_app(self, line: str) -> Optional[LogEntry]:
        m = self._APP_RE.match(line)
        if not m:
            return None
        ts = self._parse_ts_string(m.group("ts").replace(",", "."))
        level_str = m.group("level") or ""
        return LogEntry(
            raw=line,
            timestamp=ts,
            level=LogLevel.from_string(level_str) if level_str else LogLevel.UNKNOWN,
            source=m.group("source") or "",
            message=m.group("message") or "",
        )

    def _try_syslog(self, line: str) -> Optional[LogEntry]:
        m = self._SYSLOG_RE.match(line)
        if not m:
            return None
        ts_str = m.group("ts")
        # Syslog has no year; use current year
        ts = self._parse_ts_string(ts_str, fmt="%b %d %H:%M:%S")
        if ts is not None:
            ts = ts.replace(year=datetime.now().year)
        return LogEntry(
            raw=line,
            timestamp=ts,
            level=self._extract_level(m.group("message")),
            source=m.group("source"),
            message=m.group("message"),
            extra={"host": m.group("host")},
        )

    def _try_csv(self, line: str) -> Optional[LogEntry]:
        m = self._CSV_RE.match(line)
        if not m:
            return None
        ts = self._parse_ts_string(m.group(1).strip())
        rest = m.group(2)
        parts = [p.strip() for p in rest.split(",")]
        return LogEntry(
            raw=line,
            timestamp=ts,
            level=LogLevel.UNKNOWN,
            message=rest,
            extra={"fields": parts},
        )

    def _try_apache(self, line: str) -> Optional[LogEntry]:
        m = self._APACHE_RE.match(line)
        if not m:
            return None
        ts = self._parse_ts_string(m.group("ts"), fmt="%d/%b/%Y:%H:%M:%S %z")
        status = int(m.group("status"))
        level = LogLevel.ERROR if status >= 500 else (
            LogLevel.WARNING if status >= 400 else LogLevel.INFO
        )
        return LogEntry(
            raw=line,
            timestamp=ts,
            level=level,
            source=m.group("host"),
            message=m.group("request"),
            extra={"status": status, "size": m.group("size")},
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_ts_string(self, value: str, fmt: Optional[str] = None) -> Optional[datetime]:
        if fmt:
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                return None
        for fmt_candidate, _ in self._TS_PATTERNS:
            try:
                return datetime.strptime(value, fmt_candidate)
            except ValueError:
                continue
        return None

    def _extract_timestamp(self, line: str) -> Optional[datetime]:
        for fmt, pattern in self._TS_PATTERNS:
            m = pattern.search(line)
            if m:
                ts = self._parse_ts_string(m.group(), fmt=fmt)
                if ts is not None:
                    return ts
        return None

    def _extract_level(self, text: str) -> LogLevel:
        upper = text.upper()
        for level in (LogLevel.CRITICAL, LogLevel.ERROR, LogLevel.WARNING,
                      LogLevel.INFO, LogLevel.DEBUG):
            if level.value in upper:
                return level
        # Common aliases
        if "FATAL" in upper:
            return LogLevel.CRITICAL
        if "WARN" in upper:
            return LogLevel.WARNING
        if "ERR" in upper:
            return LogLevel.ERROR
        return LogLevel.UNKNOWN
