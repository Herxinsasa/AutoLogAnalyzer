"""Tests for AutoLogAnalyzerAgent (integration)."""

import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from agent.agent import AutoLogAnalyzerAgent, LogType


BUSINESS_LINES = [
    "2024-01-01 10:00:00 [INFO] api: started elapsed=50ms",
    "2024-01-01 10:00:01 [ERROR] api: failed elapsed=3000ms",
    "2024-01-01 10:00:02 [INFO] api: ok elapsed=200ms",
]

SYSTEM_LINES = [
    "Mar 26 10:00:00 host sshd: Failed password for user x from 1.2.3.4",
    "Mar 26 10:00:01 host sshd: Accepted password for alice from 10.0.0.1",
]

RESOURCE_LINES = [
    "2024-01-01 10:00:00 cpu=90% mem=50% disk=60%",
    "2024-01-01 10:01:00 cpu=20% mem=30% disk=60%",
]


class TestAutoLogAnalyzerAgent:
    def setup_method(self):
        self.agent = AutoLogAnalyzerAgent()

    def test_analyze_lines_business(self):
        result = self.agent.analyze_lines(BUSINESS_LINES, log_type=LogType.BUSINESS)
        assert result["meta"]["log_type"] == "business"
        assert result["result"]["total"] == 3

    def test_analyze_lines_system(self):
        result = self.agent.analyze_lines(SYSTEM_LINES, log_type=LogType.SYSTEM)
        assert result["meta"]["log_type"] == "system"
        assert result["result"]["total"] == 2

    def test_analyze_lines_resource(self):
        result = self.agent.analyze_lines(RESOURCE_LINES, log_type=LogType.RESOURCE)
        assert result["meta"]["log_type"] == "resource"
        assert result["result"]["total"] == 2

    def test_meta_has_required_keys(self):
        result = self.agent.analyze_lines(BUSINESS_LINES, log_type=LogType.BUSINESS)
        assert "source" in result["meta"]
        assert "log_type" in result["meta"]
        assert "analyzed_at" in result["meta"]

    def test_to_json_is_valid(self):
        import json
        result = self.agent.analyze_lines(BUSINESS_LINES, log_type=LogType.BUSINESS)
        json_str = self.agent.to_json(result)
        parsed = json.loads(json_str)
        assert parsed["meta"]["log_type"] == "business"

    def test_analyze_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            self.agent.analyze_file("/nonexistent/path/to/log.log")

    def test_analyze_file_business(self, tmp_path):
        log_file = tmp_path / "app.log"
        log_file.write_text("\n".join(BUSINESS_LINES), encoding="utf-8")
        result = self.agent.analyze_file(str(log_file), log_type=LogType.BUSINESS)
        assert result["result"]["total"] == 3

    def test_analyze_file_system(self, tmp_path):
        log_file = tmp_path / "syslog"
        log_file.write_text("\n".join(SYSTEM_LINES), encoding="utf-8")
        result = self.agent.analyze_file(str(log_file), log_type=LogType.SYSTEM)
        assert result["result"]["total"] == 2

    def test_auto_detect_syslog_filename(self, tmp_path):
        log_file = tmp_path / "syslog"
        log_file.write_text("\n".join(SYSTEM_LINES), encoding="utf-8")
        result = self.agent.analyze_file(str(log_file), log_type=LogType.AUTO)
        assert result["meta"]["log_type"] == "system"

    def test_auto_detect_resource_filename(self, tmp_path):
        log_file = tmp_path / "cpu_metrics.log"
        log_file.write_text("\n".join(RESOURCE_LINES), encoding="utf-8")
        result = self.agent.analyze_file(str(log_file), log_type=LogType.AUTO)
        assert result["meta"]["log_type"] == "resource"

    def test_print_report_does_not_raise(self, capsys):
        result = self.agent.analyze_lines(BUSINESS_LINES, log_type=LogType.BUSINESS)
        self.agent.print_report(result)
        captured = capsys.readouterr()
        assert "AutoLogAnalyzer" in captured.out

    def test_print_report_system(self, capsys):
        result = self.agent.analyze_lines(SYSTEM_LINES, log_type=LogType.SYSTEM)
        self.agent.print_report(result)
        captured = capsys.readouterr()
        assert "system" in captured.out

    def test_print_report_resource(self, capsys):
        result = self.agent.analyze_lines(RESOURCE_LINES, log_type=LogType.RESOURCE)
        self.agent.print_report(result)
        captured = capsys.readouterr()
        assert "resource" in captured.out
