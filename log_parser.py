import re
from typing import List, Dict, Optional

class ApacheLogParser:
    """A parser for Apache log files with in-memory storage."""
    
    def __init__(self):
        self._parsed_logs: List[Dict[str, str]] = []
        self._pattern = re.compile(
            r'^'
            # IP Address (IPv4 only)
            r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
            
            # Remote identity (usually '-', ignored)
            r'\S+ \S+ '
            
            # Timestamp (inside square brackets)
            r'\[(?P<datetime>[^\]]+)\] '
            
            # HTTP Request Line (method + path + protocol)
            r'"'
            # HTTP Method (strictly validated)
            r'(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) '
            
            # Request Path (supports paths, queries, fragments)
            r'(?P<path>'
                r'(?:/[^\s?#]*)?'    # Path segment (e.g., /home)
                r'(?:\?[^\s#]*)?'    # Optional query (?foo=bar)
                r'(?:#\S*)?'         # Optional fragment (#section)
            r') '
            
            # HTTP Protocol (ignored)
            r'\S+" '
            
            # Response Status Code (3 digits)
            r'(?P<status>\d{3}) '
            
            # Response Size (bytes or '-' if empty)
            r'(?P<size>\d+|-)'
            r'$'
        )

    def parse_file(self, file_path: str) -> None:
        """Parse an entire log file and store results in memory."""
        with open(file_path, 'r') as file:
            for line in file:
                if parsed := self._parse_line(line.strip()):
                    self._parsed_logs.append(parsed)

    def _parse_line(self, line: str) -> Optional[Dict[str, str]]:
        """Internal method to parse a single line."""
        if not line:
            return None
        if match := self._pattern.match(line):
            return match.groupdict()
        return None

    @property
    def logs(self) -> List[Dict[str, str]]:
        """Get all parsed logs (returns a copy to prevent modification)."""
        return self._parsed_logs.copy()

    def clear(self) -> None:
        """Clear all stored logs."""
        self._parsed_logs.clear()