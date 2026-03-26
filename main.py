#!/usr/bin/env python3
"""
AutoLogAnalyzer – main entry point.

Usage
-----
    python main.py <log_file> [--type business|system|resource|auto]
                              [--json]
                              [--slow-threshold-ms 1000]
                              [--brute-force-threshold 5]

Examples
--------
    python main.py /var/log/syslog --type system
    python main.py app.log --type business --slow-threshold-ms 500
    python main.py metrics.log --type resource --json
    python main.py unknown.log --type auto
"""

import argparse
import sys

from agent import AutoLogAnalyzerAgent
from agent.agent import LogType


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="autologanalyzer",
        description="Automatic log analyzer supporting business, system, and resource logs.",
    )
    p.add_argument("log_file", help="Path to the log file to analyze.")
    p.add_argument(
        "--type",
        dest="log_type",
        choices=[t.value for t in LogType],
        default=LogType.AUTO.value,
        help="Log type to analyze (default: auto-detect).",
    )
    p.add_argument(
        "--json",
        dest="output_json",
        action="store_true",
        default=False,
        help="Output raw JSON instead of a human-readable report.",
    )
    p.add_argument(
        "--slow-threshold-ms",
        type=float,
        default=1000.0,
        metavar="MS",
        help="Latency threshold in ms to flag a request as slow (default: 1000).",
    )
    p.add_argument(
        "--brute-force-threshold",
        type=int,
        default=5,
        metavar="N",
        help="Min auth failures per IP to flag as brute-force (default: 5).",
    )
    p.add_argument(
        "--top-n",
        type=int,
        default=10,
        metavar="N",
        help="Number of top items to show in summaries (default: 10).",
    )
    return p


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    agent = AutoLogAnalyzerAgent(
        slow_threshold_ms=args.slow_threshold_ms,
        brute_force_threshold=args.brute_force_threshold,
        top_n=args.top_n,
    )

    try:
        log_type = LogType(args.log_type)
        result = agent.analyze_file(args.log_file, log_type=log_type)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.output_json:
        print(agent.to_json(result))
    else:
        agent.print_report(result)

    return 0


if __name__ == "__main__":
    sys.exit(main())
