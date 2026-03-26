"""Tests for SystemLogAnalyzer."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from skills.system_log import SystemLogAnalyzer


# ---------------------------------------------------------------------------
# Sample log lines
# ---------------------------------------------------------------------------

SYSLOG_LINES = [
    "Mar 26 10:00:00 myhost sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
    "Mar 26 10:00:01 myhost sshd[1234]: Failed password for invalid user root from 192.168.1.100 port 22 ssh2",
    "Mar 26 10:00:02 myhost sshd[1234]: Failed password for invalid user test from 192.168.1.100 port 22 ssh2",
    "Mar 26 10:00:03 myhost sshd[1234]: Failed password for invalid user ubuntu from 192.168.1.100 port 22 ssh2",
    "Mar 26 10:00:04 myhost sshd[1234]: Failed password for invalid user user from 192.168.1.100 port 22 ssh2",
    "Mar 26 10:00:05 myhost sshd[1234]: Failed password for invalid user pi from 192.168.1.101 port 22 ssh2",
    "Mar 26 10:00:06 myhost sshd[5678]: Accepted password for alice from 10.0.0.1 port 44322 ssh2",
    "Mar 26 10:00:07 myhost sshd[5678]: session opened for user alice by (uid=0)",
    "Mar 26 10:00:08 myhost kernel: Out of memory: Kill process 4321 (java) score 987 or sacrifice child",
    "Mar 26 10:00:09 myhost sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls",
    "Mar 26 10:00:10 myhost kernel: general protection fault: 0000 [#1] SMP PTI",
    "Mar 26 10:00:11 myhost systemd[1]: start job failed to start for unit nginx.service",
]


class TestSystemLogAnalyzer:
    def setup_method(self):
        self.analyzer = SystemLogAnalyzer(brute_force_threshold=5, top_n=10)

    def test_total_count(self):
        result = self.analyzer.analyze(SYSLOG_LINES)
        assert result["total"] == len(SYSLOG_LINES)

    def test_auth_failures_detected(self):
        result = self.analyzer.analyze(SYSLOG_LINES)
        assert result["auth_failure_count"] >= 5

    def test_auth_success_detected(self):
        result = self.analyzer.analyze(SYSLOG_LINES)
        assert result["auth_success_count"] >= 1

    def test_brute_force_ip_flagged(self):
        result = self.analyzer.analyze(SYSLOG_LINES)
        bf = result["brute_force_ips"]
        assert "192.168.1.100" in bf
        assert bf["192.168.1.100"] >= 5

    def test_ip_below_threshold_not_brute_force(self):
        result = self.analyzer.analyze(SYSLOG_LINES)
        bf = result["brute_force_ips"]
        # 192.168.1.101 only has 1 failure
        assert "192.168.1.101" not in bf

    def test_service_crash_detected(self):
        result = self.analyzer.analyze(SYSLOG_LINES)
        # OOM kill + failed to start
        assert result["service_crash_count"] >= 1

    def test_kernel_error_detected(self):
        result = self.analyzer.analyze(SYSLOG_LINES)
        assert result["kernel_error_count"] >= 1

    def test_sudo_event_detected(self):
        result = self.analyzer.analyze(SYSLOG_LINES)
        assert result["sudo_event_count"] >= 1

    def test_auth_failure_has_ip(self):
        result = self.analyzer.analyze(SYSLOG_LINES)
        failures = result["auth_failures"]
        assert any(f.get("ip") for f in failures)

    def test_auth_failure_has_user(self):
        result = self.analyzer.analyze(SYSLOG_LINES)
        failures = result["auth_failures"]
        assert any(f.get("user") for f in failures)

    def test_top_sources_present(self):
        result = self.analyzer.analyze(SYSLOG_LINES)
        assert len(result["top_sources"]) > 0

    def test_hourly_trend_present(self):
        result = self.analyzer.analyze(SYSLOG_LINES)
        assert len(result["hourly_trend"]) > 0

    def test_empty_input(self):
        result = self.analyzer.analyze([])
        assert result["total"] == 0
        assert result["auth_failure_count"] == 0
        assert result["brute_force_ips"] == {}

    def test_no_security_events(self):
        lines = [
            "Mar 26 10:00:00 myhost cron[1]: started",
            "Mar 26 10:00:01 myhost cron[1]: finished job",
        ]
        result = self.analyzer.analyze(lines)
        assert result["auth_failure_count"] == 0
        assert result["kernel_error_count"] == 0
        assert result["brute_force_ips"] == {}

    def test_custom_brute_force_threshold(self):
        analyzer = SystemLogAnalyzer(brute_force_threshold=2)
        lines = [
            "Mar 26 10:00:00 h sshd: Failed password for user a from 1.2.3.4",
            "Mar 26 10:00:01 h sshd: Failed password for user b from 1.2.3.4",
        ]
        result = analyzer.analyze(lines)
        assert "1.2.3.4" in result["brute_force_ips"]

    def test_result_has_required_keys(self):
        result = self.analyzer.analyze(SYSLOG_LINES)
        for key in ("total", "by_level", "auth_failures", "auth_failure_count",
                    "auth_successes", "auth_success_count", "service_crashes",
                    "service_crash_count", "kernel_errors", "kernel_error_count",
                    "sudo_events", "sudo_event_count", "brute_force_ips",
                    "top_sources", "hourly_trend"):
            assert key in result, f"Missing key: {key}"
