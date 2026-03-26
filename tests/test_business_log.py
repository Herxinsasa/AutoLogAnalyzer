"""Tests for BusinessLogAnalyzer."""

import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from skills.business_log import BusinessLogAnalyzer


# ---------------------------------------------------------------------------
# Sample log lines
# ---------------------------------------------------------------------------

BUSINESS_LOGS_TEXT = [
    "2024-01-01 10:00:00 [INFO] api.orders: Request received",
    "2024-01-01 10:00:01 [INFO] api.orders: Request processed elapsed=120ms",
    "2024-01-01 10:00:02 [ERROR] api.orders: Database connection failed",
    "2024-01-01 10:00:03 [WARNING] api.orders: Retry attempt 1",
    "2024-01-01 10:00:04 [ERROR] api.payments: Payment timeout elapsed=2500ms",
    "2024-01-01 10:00:05 [INFO] api.auth: User login successful",
    "2024-01-01 10:00:06 [CRITICAL] api.db: Connection pool exhausted",
    "2024-01-01 10:00:07 [INFO] api.orders: elapsed=800ms status=200",
    "2024-01-01 10:00:08 [INFO] api.orders: elapsed=1200ms status=200",
]

BUSINESS_LOGS_JSON = [
    '{"timestamp":"2024-01-01T10:00:00","level":"INFO","logger":"api","message":"start","duration_ms":50}',
    '{"timestamp":"2024-01-01T10:00:01","level":"ERROR","logger":"api","message":"fail","duration_ms":3000}',
    '{"timestamp":"2024-01-01T10:00:02","level":"INFO","logger":"api","message":"ok","duration_ms":200}',
]


class TestBusinessLogAnalyzer:
    def setup_method(self):
        self.analyzer = BusinessLogAnalyzer(slow_threshold_ms=1000.0, top_n=10)

    def test_total_count(self):
        result = self.analyzer.analyze(BUSINESS_LOGS_TEXT)
        assert result["total"] == len(BUSINESS_LOGS_TEXT)

    def test_by_level_contains_error(self):
        result = self.analyzer.analyze(BUSINESS_LOGS_TEXT)
        assert result["by_level"].get("ERROR", 0) >= 2

    def test_by_level_contains_critical(self):
        result = self.analyzer.analyze(BUSINESS_LOGS_TEXT)
        assert result["by_level"].get("CRITICAL", 0) >= 1

    def test_error_rate_positive(self):
        result = self.analyzer.analyze(BUSINESS_LOGS_TEXT)
        assert result["error_rate_pct"] > 0

    def test_errors_list_not_empty(self):
        result = self.analyzer.analyze(BUSINESS_LOGS_TEXT)
        assert len(result["errors"]) > 0

    def test_errors_have_required_keys(self):
        result = self.analyzer.analyze(BUSINESS_LOGS_TEXT)
        for err in result["errors"]:
            assert "time" in err
            assert "level" in err
            assert "message" in err

    def test_slow_requests_detected(self):
        result = self.analyzer.analyze(BUSINESS_LOGS_TEXT)
        # elapsed=2500ms and elapsed=1200ms should be slow
        assert len(result["slow_requests"]) >= 2

    def test_slow_request_has_latency_ms(self):
        result = self.analyzer.analyze(BUSINESS_LOGS_TEXT)
        for req in result["slow_requests"]:
            assert "latency_ms" in req
            assert req["latency_ms"] >= 1000.0

    def test_latency_stats_computed(self):
        result = self.analyzer.analyze(BUSINESS_LOGS_TEXT)
        stats = result["latency_stats"]
        assert stats  # non-empty
        assert "mean_ms" in stats
        assert "p95_ms" in stats
        assert stats["max_ms"] >= stats["mean_ms"] >= stats["min_ms"]

    def test_hourly_trend_present(self):
        result = self.analyzer.analyze(BUSINESS_LOGS_TEXT)
        assert len(result["hourly_trend"]) > 0

    def test_top_sources_present(self):
        result = self.analyzer.analyze(BUSINESS_LOGS_TEXT)
        assert len(result["top_sources"]) > 0

    def test_json_log_parsing(self):
        result = self.analyzer.analyze(BUSINESS_LOGS_JSON)
        assert result["total"] == 3
        assert result["by_level"].get("ERROR", 0) == 1

    def test_empty_input(self):
        result = self.analyzer.analyze([])
        assert result["total"] == 0
        assert result["error_rate_pct"] == 0.0

    def test_no_errors_zero_error_rate(self):
        lines = [
            "2024-01-01 10:00:00 [INFO] svc: all good",
            "2024-01-01 10:00:01 [INFO] svc: still good",
        ]
        result = self.analyzer.analyze(lines)
        assert result["error_rate_pct"] == 0.0
        assert result["errors"] == []

    def test_top_n_limits_results(self):
        analyzer = BusinessLogAnalyzer(slow_threshold_ms=0.0, top_n=3)
        lines = [
            f"2024-01-01 10:00:{i:02d} [ERROR] svc: error {i} elapsed={i}ms"
            for i in range(20)
        ]
        result = analyzer.analyze(lines)
        assert len(result["errors"]) <= 3
        assert len(result["slow_requests"]) <= 3

    def test_latency_in_seconds(self):
        lines = ["2024-01-01 10:00:00 [INFO] svc: request took 2.5s"]
        result = self.analyzer.analyze(lines)
        stats = result["latency_stats"]
        assert stats
        # 2.5 s = 2500 ms
        assert abs(stats["mean_ms"] - 2500) < 1

    def test_apache_log_format(self):
        lines = [
            '192.168.1.1 - - [01/Jan/2024:10:00:00 +0000] "GET /api/v1 HTTP/1.1" 200 1234',
            '192.168.1.2 - - [01/Jan/2024:10:00:01 +0000] "POST /api/v1 HTTP/1.1" 500 0',
        ]
        result = self.analyzer.analyze(lines)
        assert result["total"] == 2
        assert result["by_level"].get("ERROR", 0) >= 1
