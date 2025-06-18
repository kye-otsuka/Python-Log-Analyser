# 1. Shebang (Optional, for Linux/macOS execution)
#!/usr/bin/env python3

# 2. Module Docstring (Highly Recommended!)
"""
Python-Log-Analyser: A script to monitor log files for suspicious security patterns
and trigger alerts.

This script demonstrates log parsing, pattern matching using regular expressions,
and basic alerting for security incidents.
"""

# 3. Standard Library Imports (Start with these essentials)
import re          # For regular expressions, crucial for parsing log lines.
import datetime    # For working with timestamps and time windows for alerts.
import time        # For pauses in continuous monitoring (if implemented).
import os          # For basic operating system interactions (e.g., file paths, if needed).

# 4. Third-Party Library Imports (Add as you expand)
# import smtplib   # If you implement email alerts.
# import json      # If logs are in JSON format.
# import csv       # If logs are in CSV format.
# import collections # For more advanced data structures like deque for time windows.

# 5. Global Constants / Configuration (If applicable, or move to a separate config file later)
LOG_FILE_PATH = "path/to/your/sample.log"  # !!! REMEMBER TO CHANGE THIS !!!
ALERT_THRESHOLD_COUNT = 5  # e.g., 5 failed logins
ALERT_TIME_WINDOW_MINUTES = 1 # within 1 minute
ALERT_LOG_PATH = "security_alerts.log" # Where to write alerts

# 6. Core Functions (Your main logic will go here)

def parse_log_line(line):
    """
    Parses a single log line using regex to extract relevant information.
    Returns a dictionary or tuple of parsed data, or None if parsing fails.
    """
    # Example for Apache Common Log Format. You'll adapt this!
    # e.g., 127.0.0.1 - - [10/Jun/2025:10:30:00 +0100] "GET /index.html HTTP/1.1" 200 1234
    log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] "(.*?)" (\d+) (\d+|-)')
    match = log_pattern.match(line)
    if match:
        ip_address = match.group(1)
        timestamp_str = match.group(2)
        request = match.group(3)
        status_code = match.group(4)
        
        # Convert timestamp string to datetime object for easier comparison
        # Example format: 10/Jun/2025:10:30:00 +0100
        try:
            # Need to handle timezone offset if present, or simplify for now
            dt_object = datetime.datetime.strptime(timestamp_str.split(' ')[0], "%d/%b/%Y:%H:%M:%S")
            return {'ip': ip_address, 'timestamp': dt_object, 'request': request, 'status': status_code}
        except ValueError:
            return None # Handle unparseable timestamps
    return None

# Placeholder for your detection logic (e.g., tracking failed attempts)
failed_attempts_tracker = {} # Dictionary to store IP -> list of timestamps

def detect_suspicious_activity(parsed_data):
    """
    Checks parsed log data for suspicious patterns.
    Returns an alert message (string) if a pattern is detected, otherwise None.
    """
    if parsed_data and parsed_data['status'] in ['401', '403'] and '/login' in parsed_data['request']:
        ip = parsed_data['ip']
        current_time = parsed_data['timestamp']

        if ip not in failed_attempts_tracker:
            failed_attempts_tracker[ip] = []
        
        failed_attempts_tracker[ip].append(current_time)

        # Clean up old attempts outside the window
        # Only keep attempts within the defined time window
        threshold_time = current_time - datetime.timedelta(minutes=ALERT_TIME_WINDOW_MINUTES)
        failed_attempts_tracker[ip] = [
            ts for ts in failed_attempts_tracker[ip] if ts >= threshold_time
        ]

        if len(failed_attempts_tracker[ip]) >= ALERT_THRESHOLD_COUNT:
            # Clear/reset for this IP after alerting to prevent repeated alerts for same burst
            # Or implement a cooldown period for more advanced logic
            del failed_attempts_tracker[ip] 
            return f"BRUTE-FORCE ALERT: IP {ip} detected with {ALERT_THRESHOLD_COUNT} or more failed logins in {ALERT_TIME_WINDOW_MINUTES} minute(s)."
    return None

def send_alert(message):
    """
    Placeholder for sending an alert (e.g., print to console, write to file).
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_message = f"[{timestamp}] ALERT: {message}"
    print(alert_message) # Print to console
    
    # Also write to a dedicated alert log file
    try:
        with open(ALERT_LOG_PATH, 'a') as f:
            f.write(alert_message + "\n")
    except IOError as e:
        print(f"Error writing to alert log file: {e}")

# 7. Main Execution Block (The entry point of your script)

if __name__ == "__main__":
    print(f"Starting Log Analyser for: {LOG_FILE_PATH}")
    print(f"Alerting Threshold: {ALERT_THRESHOLD_COUNT} attempts in {ALERT_TIME_WINDOW_MINUTES} minute(s)")
    
    try:
        # Initial read (you'll adapt this for continuous monitoring later)
        with open(LOG_FILE_PATH, 'r') as log_file:
            for line_num, line in enumerate(log_file):
                parsed_data = parse_log_line(line)
                if parsed_data:
                    alert = detect_suspicious_activity(parsed_data)
                    if alert:
                        send_alert(alert)
                # Optional: Add a small delay if processing huge files to prevent CPU spike
                # time.sleep(0.001)

    except FileNotFoundError:
        print(f"ERROR: Log file not found at '{LOG_FILE_PATH}'. Please check the path.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    print("Log Analyser finished initial scan.")
    # For continuous monitoring, you'd put the log file reading in a loop here.