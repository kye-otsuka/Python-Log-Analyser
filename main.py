# Shebang
#!/usr/bin/env python3

"""
Python-Log-Analyser: A script designed to monitor log files for suspicious security patterns
and trigger alerts.

This project demonstrates practical skills in log parsing, pattern matching using regular expressions,
and basic alerting, crucial for roles in Security Operations Centres (SOC) and Security Analysis.
"""

# imports
import os
from log_generator import generate_logs
from log_parser import ApacheLogParser
from suspicious_detector import SuspiciousDetector
import argparse

def main():
    parser = argparse.ArgumentParser(description="choose log file source")
    parser.add_argument("--logfile", help="path to existing log file") 
    parser.add_argument("--generate", action="store_true", help="generate a test log file called config file")
    parser.add_argument("--lines", type=int, default=50, help="number of lines for synthetic log file")

    args = parser.parse_args()

    if args.generate:
        print("generating fake log files")
        generate_logs(args.lines)
        file_path = "access.log"
    elif args.logfile:
        file_path = args.logfile
        if not os.path.exists(file_path):
            print(f"Error: file {file_path} found")
            return
    else:
        print("Error: provide either --logfile or --generate")
        return
    

    with open(file_path, "r") as f:
        logs = f.readlines()
        print(f"read {len(logs)} lines from {file_path}")
    

if __name__ == "__main__":
    main()

