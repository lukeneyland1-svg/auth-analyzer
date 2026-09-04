#!/usr/bin/env python3
"""
auth_analyzer.py — Linux auth.log security analyzer

Parses SSH/sudo authentication logs, classifies each event by severity,
and detects brute-force login patterns by IP address.

Usage:
    python3 auth_analyzer.py --log /var/log/auth.log
    python3 auth_analyzer.py --log /var/log/auth.log --min-attempts 3 --json
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

LOG_LINE_PATTERN = re.compile(r"^(\S+)\s+(\S+)\s+([^:]+):\s*(.*)$")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SEVERITY_RULES = {
    "critical": [
        "failed password",
        "authentication failure",
        "invalid user",
        "too many authentication",
        "possible break-in attempt",
    ],
    "high": [
        "connection closed by",
        "bad protocol",
        "did not receive identification",
        "unable to negotiate",
        "disconnect",
        "refused connect",
    ],
    "medium": [
        "accepted password",
        "accepted publickey",
        "sudo",
        "session opened",
        "session closed",
        "new user",
        "new group",
    ],
}


@dataclass
class LogEntry:
    timestamp: Optional[datetime]
    host: str
    process: str
    message: str
    severity: str
    ip: Optional[str]


def classify_severity(message: str) -> str:
    """Classify a log message's severity based on keyword matching."""
    lower = message.lower()
    for severity, keywords in SEVERITY_RULES.items():
        if any(keyword in lower for keyword in keywords):
            return severity
    return "low"


def extract_ip(message: str) -> Optional[str]:
    """Pull the first IPv4 address out of a message, if present."""
    match = IP_PATTERN.search(message)
    return match.group(0) if match else None


def parse_line(line: str) -> Optional[LogEntry]:
    """Parse one raw auth.log line into a LogEntry, or None if it doesn't match."""
    line = line.strip()
    if not line:
        return None

    match = LOG_LINE_PATTERN.match(line)
    if not match:
        return None

    timestamp_raw, host, process, message = match.groups()

    try:
        timestamp = datetime.fromisoformat(timestamp_raw)
    except ValueError:
        timestamp = None

    return LogEntry(
        timestamp=timestamp,
        host=host,
        process=process,
        message=message,
        severity=classify_severity(message),
        ip=extract_ip(message),
    )


def parse_log_file(path: Path) -> list[LogEntry]:
    """Read a log file and parse every line into LogEntry objects."""
    entries = []
    with path.open("r", errors="replace") as f:
        for line in f:
            entry = parse_line(line)
            if entry:
                entries.append(entry)
    return entries


def detect_brute_force(entries: list[LogEntry], min_attempts: int) -> dict:
    """Group critical/high-severity events by IP and flag IPs over the threshold."""
    events_by_ip: dict[str, list[LogEntry]] = defaultdict(list)

    for entry in entries:
        if entry.ip and entry.severity in ("critical", "high"):
            events_by_ip[entry.ip].append(entry)

    flagged = {}
    for ip, attempts in events_by_ip.items():
        if len(attempts) >= min_attempts:
            timestamps = [a.timestamp for a in attempts if a.timestamp]
            flagged[ip] = {
                "attempts": len(attempts),
                "first_seen": min(timestamps).isoformat() if timestamps else None,
                "last_seen": max(timestamps).isoformat() if timestamps else None,
            }
    return flagged


def summarize(entries: list[LogEntry]) -> dict:
    """Count entries by severity level."""
    counts: dict = defaultdict(int)
    for entry in entries:
        counts[entry.severity] += 1
    return dict(counts)


def print_report(entries: list[LogEntry], flagged: dict) -> None:
    """Print a human-readable report to the console."""
    counts = summarize(entries)

    print("=" * 50)
    print("AUTH LOG SECURITY REPORT")
    print("=" * 50)
    print(f"Total events parsed: {len(entries)}\n")

    print("By severity:")
    for severity in ("critical", "high", "medium", "low"):
        print(f"  {severity:10s} {counts.get(severity, 0)}")

    print(f"\nBrute-force candidates ({len(flagged)} IPs flagged):")
    if not flagged:
        print("  None detected.")
    else:
        for ip, info in sorted(flagged.items(), key=lambda x: -x[1]["attempts"]):
            print(
                f"  {ip:16s} {info['attempts']} failed attempts "
                f"(first: {info['first_seen']}, last: {info['last_seen']})"
            )
    print("=" * 50)


def build_json_report(entries: list[LogEntry], flagged: dict) -> dict:
    """Build a JSON-serializable report."""
    return {
        "total_events": len(entries),
        "severity_counts": summarize(entries),
        "brute_force_flags": flagged,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze a Linux auth.log for security events.")
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("/var/log/auth.log"),
        help="Path to the auth log file (default: /var/log/auth.log)",
    )
    parser.add_argument(
        "--min-attempts",
        type=int,
        default=5,
        help="Minimum failed attempts from one IP to flag as brute-force (default: 5)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of a human-readable report",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write JSON output to a file instead of stdout (implies --json)",
    )
    args = parser.parse_args()

    if not args.log.exists():
        print(f"Error: log file not found: {args.log}", file=sys.stderr)
        sys.exit(1)

    entries = parse_log_file(args.log)
    flagged = detect_brute_force(entries, args.min_attempts)

    if args.json or args.output:
        report = build_json_report(entries, flagged)
        output_text = json.dumps(report, indent=2)
        if args.output:
            args.output.write_text(output_text)
            print(f"Report written to {args.output}")
        else:
            print(output_text)
    else:
        print_report(entries, flagged)


if __name__ == "__main__":
    main()
