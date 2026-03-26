"""Tests for ResourceLogAnalyzer."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from skills.resource_log import ResourceLogAnalyzer


# ---------------------------------------------------------------------------
# Sample log lines
# ---------------------------------------------------------------------------

RESOURCE_LOGS_TEXT = [
    "2024-01-01 10:00:00 cpu=72.3% mem=45.1% disk=60% load=1.2",
    "2024-01-01 10:01:00 cpu=80.0% mem=50.0% disk=61% load=1.5",
    "2024-01-01 10:02:00 cpu=90.0% mem=88.0% disk=62% load=2.0",
    "2024-01-01 10:03:00 cpu=91.0% mem=91.0% disk=63% load=2.5",  # mem threshold breach
    "2024-01-01 10:04:00 cpu=95.0% mem=93.0% disk=64% load=3.0",  # cpu+mem breach
    "2024-01-01 10:05:00 cpu=92.0% mem=92.0% disk=65% load=3.5",  # cpu+mem breach
    "2024-01-01 10:06:00 cpu=88.0% mem=91.0% disk=66% load=4.0",  # 5th consecutive cpu>=85%
    "2024-01-01 11:00:00 cpu=20.0% mem=30.0% disk=60% load=0.5",
    "2024-01-01 11:01:00 cpu=22.0% mem=31.0% disk=60% load=0.6",
]

RESOURCE_LOGS_JSON = [
    '{"timestamp":"2024-01-01T10:00:00","cpu_percent":50.0,"mem_usage":40.0}',
    '{"timestamp":"2024-01-01T10:01:00","cpu_percent":95.0,"mem_usage":92.0}',
    '{"timestamp":"2024-01-01T10:02:00","cpu_percent":30.0,"mem_usage":35.0}',
]


class TestResourceLogAnalyzer:
    def setup_method(self):
        self.analyzer = ResourceLogAnalyzer(top_n=10)

    def test_total_count(self):
        result = self.analyzer.analyze(RESOURCE_LOGS_TEXT)
        assert result["total"] == len(RESOURCE_LOGS_TEXT)

    def test_cpu_metric_collected(self):
        result = self.analyzer.analyze(RESOURCE_LOGS_TEXT)
        assert "cpu_pct" in result["metrics"]

    def test_mem_metric_collected(self):
        result = self.analyzer.analyze(RESOURCE_LOGS_TEXT)
        assert "mem_pct" in result["metrics"]

    def test_disk_metric_collected(self):
        result = self.analyzer.analyze(RESOURCE_LOGS_TEXT)
        assert "disk_pct" in result["metrics"]

    def test_cpu_stats_correct_range(self):
        result = self.analyzer.analyze(RESOURCE_LOGS_TEXT)
        stats = result["metrics"]["cpu_pct"]
        assert stats["min"] <= stats["mean"] <= stats["max"]
        assert stats["max"] >= 95.0

    def test_mem_stats_correct_range(self):
        result = self.analyzer.analyze(RESOURCE_LOGS_TEXT)
        stats = result["metrics"]["mem_pct"]
        assert stats["min"] <= stats["mean"] <= stats["max"]

    def test_alerts_generated_for_threshold_breach(self):
        result = self.analyzer.analyze(RESOURCE_LOGS_TEXT)
        # cpu=90%+ should trigger alerts (threshold 85%)
        assert result["alert_count"] > 0

    def test_alert_has_required_fields(self):
        result = self.analyzer.analyze(RESOURCE_LOGS_TEXT)
        for alert in result["alerts"]:
            assert "metric" in alert
            assert "value" in alert
            assert "threshold" in alert
            assert "description" in alert

    def test_sustained_alert_detected(self):
        # Lines 2-6 all have cpu>=90%, with default sustained_window=5, expect alert
        result = self.analyzer.analyze(RESOURCE_LOGS_TEXT)
        # There should be sustained alerts for cpu_pct and/or mem_pct
        assert len(result["sustained_alerts"]) > 0

    def test_sustained_alert_fields(self):
        result = self.analyzer.analyze(RESOURCE_LOGS_TEXT)
        for sa in result["sustained_alerts"]:
            assert "metric" in sa
            assert "start" in sa
            assert "end" in sa
            assert "peak" in sa

    def test_hourly_trend_present(self):
        result = self.analyzer.analyze(RESOURCE_LOGS_TEXT)
        assert len(result["hourly_trend"]) >= 2  # 10:00 and 11:00

    def test_top_busy_slots_ordered(self):
        result = self.analyzer.analyze(RESOURCE_LOGS_TEXT)
        slots = result["top_busy_slots"]
        assert len(slots) > 0
        # First slot should have a higher score than last
        if len(slots) > 1:
            assert slots[0]["score"] >= slots[-1]["score"]

    def test_json_log_parsing(self):
        result = self.analyzer.analyze(RESOURCE_LOGS_JSON)
        assert result["total"] == 3
        # cpu_pct or cpu_percent should be tracked
        metrics = result["metrics"]
        assert any("cpu" in k for k in metrics)

    def test_empty_input(self):
        result = self.analyzer.analyze([])
        assert result["total"] == 0
        assert result["metrics"] == {}
        assert result["alerts"] == []

    def test_custom_thresholds(self):
        analyzer = ResourceLogAnalyzer(thresholds={"cpu_pct": 50.0})
        lines = [
            "2024-01-01 10:00:00 cpu=60% mem=30%",
            "2024-01-01 10:01:00 cpu=40% mem=30%",
        ]
        result = analyzer.analyze(lines)
        # cpu=60% should trigger with threshold=50
        cpu_alerts = [a for a in result["alerts"] if a["metric"] == "cpu_pct"]
        assert len(cpu_alerts) >= 1

    def test_stats_have_percentiles(self):
        result = self.analyzer.analyze(RESOURCE_LOGS_TEXT)
        for metric, stats in result["metrics"].items():
            assert "p95" in stats
            assert "p99" in stats
            assert stats["p99"] >= stats["p95"]

    def test_result_has_required_keys(self):
        result = self.analyzer.analyze(RESOURCE_LOGS_TEXT)
        for key in ("total", "metrics", "alerts", "alert_count",
                    "sustained_alerts", "hourly_trend", "top_busy_slots"):
            assert key in result, f"Missing key: {key}"
