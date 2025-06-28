#!/usr/bin/env python3

"""
Python-Log-Analyser: A script designed to monitor log files for suspicious security patterns
and trigger alerts.
"""

import os
import json
import argparse
from log_generator import generate_logs
from log_parser import ApacheLogParser
from suspicious_detector import SuspiciousDetector

def save_json(data, file_path):
    """Save data to a JSON file."""
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"✅ Parsed logs saved to {file_path}")

def save_report(alerts, total_lines, output_path="log_report.txt"):
    """Save a basic summary report to a .txt file."""
    with open(output_path, 'w', encoding='utf-8') as f:  # <- added encoding
        f.write("=== Log Summary Report ===\n")
        f.write(f"Total log entries parsed: {total_lines}\n")
        f.write(f"Total suspicious alerts: {len(alerts)}\n\n")
        f.write("Suspicious Activity:\n")
        if alerts:
            for alert in alerts:
                f.write(f"- {alert}\n")
        else:
            f.write("None detected.\n")
    print(f"✅ Report saved to {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Choose log file source")
    parser.add_argument("--logfile", help="Path to existing log file")
    parser.add_argument("--generate", action="store_true", help="Generate a test log file")
    parser.add_argument("--lines", type=int, default=50, help="Number of lines for synthetic log file")
    args = parser.parse_args()

    # Determine file path
    if args.generate:
        print("📄 Generating fake log file...")
        generate_logs(args.lines)
        file_path = "access.log"
    elif args.logfile:
        file_path = args.logfile
        if not os.path.exists(file_path):
            print(f"❌ Error: file {file_path} not found")
            return
    else:
        print("❌ Error: provide either --logfile or --generate")
        return

    print(f"📥 Reading from {file_path}...")

    # Parse logs
    parser = ApacheLogParser()
    parser.parse_file(file_path)
    logs = parser.logs
    print(f"✅ Parsed {len(logs)} valid log entries")

    # Save parsed logs as JSON
    save_json(logs, "parsed_logs.json")

    # Analyse for suspicious activity
    detector = SuspiciousDetector()
    detector.analyse(logs)

    # Save report
    save_report(detector.alerts, total_lines=len(logs))

if __name__ == "__main__":
    main()
