#!/usr/bin/env python3
"""
Intelligent Log Processor - Multi-format log parser and analyzer
Automatically detects log formats and extracts fields without hardcoding
"""

import re
import json
import csv
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict, Counter
import argparse
import logging


class LogParser:
    """Intelligent log parser with automatic format detection"""
    
    # Common timestamp patterns (most specific first)
    TIMESTAMP_PATTERNS = [
        # ISO 8601: 2024-12-15T10:30:45.123Z
        (r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{3,6})?(?:Z|[+-]\d{2}:?\d{2})?', 
         '%Y-%m-%dT%H:%M:%S', 'iso8601'),
        
        # Windows Event Log: 12/15/2024 10:30:45 AM
        (r'\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?',
         '%m/%d/%Y %I:%M:%S %p', 'windows'),
        
        # Syslog: Dec 15 10:30:45
        (r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
         '%b %d %H:%M:%S', 'syslog'),
        
        # Apache/Common Log: 15/Dec/2024:10:30:45 +0000
        (r'\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}',
         '%d/%b/%Y:%H:%M:%S %z', 'apache'),
        
        # RFC 2822: Mon, 15 Dec 2024 10:30:45 GMT
        (r'(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}',
         '%a, %d %b %Y %H:%M:%S', 'rfc2822'),
        
        # Unix timestamp: 1702637445
        (r'\b1[0-9]{9}\b', 'timestamp', 'unix'),
        
        # Generic: 2024-12-15 10:30:45
        (r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}',
         '%Y-%m-%d %H:%M:%S', 'generic'),
    ]
    
    # Log format detection patterns
    FORMAT_SIGNATURES = {
        'windows_event': [
            r'EventID|EventRecordID|TimeCreated',
            r'Information|Warning|Error|Critical',
            r'Provider\s+Name'
        ],
        'syslog': [
            r'<\d+>',  # Priority
            r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}',
            r'systemd|kernel|sshd|cron'
        ],
        'apache_access': [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
            r'GET|POST|PUT|DELETE|HEAD',
            r'HTTP/\d\.\d',
            r'\"\s+\d{3}\s+'  # Status code
        ],
        'iis': [
            r'#Software:\s+Microsoft',
            r'#Fields:',
            r's-ip\s+cs-method\s+cs-uri-stem'
        ],
        'powershell': [
            r'CommandLine|ScriptBlock|ParameterBinding',
            r'HostApplication|HostName|EngineVersion',
            r'RunspaceId|PipelineId'
        ],
        'json': [
            r'^\s*\{.*\}\s*$',
            r'"timestamp"|"time"|"@timestamp"',
            r'"level"|"severity"'
        ]
    }
    
    # Common field name patterns
    FIELD_PATTERNS = {
        'timestamp': r'time(?:stamp)?|date|when|created|logged',
        'level': r'level|severity|priority|type',
        'source': r'source|logger|origin|from',
        'message': r'message|msg|text|description|details',
        'user': r'user(?:name)?|account|identity|subject',
        'host': r'host(?:name)?|computer|machine|system',
        'ip': r'(?:ip|address|remote|client)',
        'process': r'process(?:id)?|pid|program',
        'event_id': r'event(?:_?id)?|code',
    }
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.detected_format = None
        self.field_mapping = {}
        
    def detect_format(self, lines: List[str]) -> str:
        """
        Automatically detect log format
        
        Args:
            lines: Sample lines from log file
            
        Returns:
            Detected format name
        """
        sample = '\n'.join(lines[:50])  # Check first 50 lines
        
        scores = defaultdict(int)
        
        for format_name, patterns in self.FORMAT_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, sample, re.IGNORECASE):
                    scores[format_name] += 1
        
        if scores:
            detected = max(scores.items(), key=lambda x: x[1])[0]
            self.logger.info(f"Detected format: {detected} (confidence: {scores[detected]})")
            return detected
        
        self.logger.warning("Could not detect specific format, using generic parser")
        return 'generic'
    
    def extract_timestamp(self, line: str) -> Optional[Tuple[datetime, str]]:
        """
        Extract timestamp from line using pattern matching
        
        Args:
            line: Log line
            
        Returns:
            Tuple of (datetime object, format type) or None
        """
        for pattern, date_format, format_type in self.TIMESTAMP_PATTERNS:
            match = re.search(pattern, line)
            if match:
                timestamp_str = match.group(0)
                try:
                    # Handle special cases
                    if format_type == 'unix':
                        dt = datetime.fromtimestamp(int(timestamp_str))
                        return (dt, format_type)
                    elif format_type == 'iso8601':
                        # Handle various ISO formats
                        for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%S.%f',
                                   '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S',
                                   '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S']:
                            try:
                                dt = datetime.strptime(timestamp_str.replace('Z', '').split('+')[0].split('-', 3)[-1] if '+' in timestamp_str or timestamp_str.endswith('Z') else timestamp_str, fmt)
                                return (dt, format_type)
                            except:
                                continue
                    else:
                        dt = datetime.strptime(timestamp_str, date_format)
                        # Add current year for syslog
                        if format_type == 'syslog' and dt.year == 1900:
                            dt = dt.replace(year=datetime.now().year)
                        return (dt, format_type)
                except Exception as e:
                    continue
        
        return None
    
    def extract_key_value_pairs(self, line: str) -> Dict[str, str]:
        """
        Extract key=value or key:value pairs from line
        
        Args:
            line: Log line
            
        Returns:
            Dictionary of extracted fields
        """
        fields = {}
        
        # Pattern: key=value or key="value" or key: value
        patterns = [
            r'(\w+)=([^\s;,]+)',  # key=value
            r'(\w+)="([^"]*)"',    # key="value"
            r'(\w+):\s*([^\s;,]+)', # key: value
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                key, value = match.groups()
                # Normalize field names
                normalized_key = self._normalize_field_name(key)
                fields[normalized_key] = value
        
        return fields
    
    def _normalize_field_name(self, field_name: str) -> str:
        """
        Normalize field name to standard categories
        
        Args:
            field_name: Original field name
            
        Returns:
            Normalized field name
        """
        field_lower = field_name.lower()
        
        for standard_name, pattern in self.FIELD_PATTERNS.items():
            if re.search(pattern, field_lower, re.IGNORECASE):
                return standard_name
        
        # Return cleaned original if no match
        return re.sub(r'[^a-z0-9_]', '_', field_lower)
    
    def parse_json_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse JSON log line"""
        try:
            data = json.loads(line)
            # Normalize field names
            normalized = {}
            for key, value in data.items():
                normalized_key = self._normalize_field_name(key)
                normalized[normalized_key] = value
            return normalized
        except json.JSONDecodeError:
            return None
    
    def parse_delimited_line(self, line: str, delimiter: str = None) -> Dict[str, str]:
        """
        Parse delimited log line (CSV, TSV, etc.)
        
        Args:
            line: Log line
            delimiter: Field delimiter (auto-detect if None)
            
        Returns:
            Dictionary of fields
        """
        if delimiter is None:
            # Auto-detect delimiter
            for delim in ['\t', ',', '|', ';']:
                if delim in line:
                    delimiter = delim
                    break
        
        if delimiter:
            parts = line.split(delimiter)
            # Create generic field names
            return {f'field_{i}': part.strip() for i, part in enumerate(parts)}
        
        return {}
    
    def parse_windows_event(self, line: str) -> Dict[str, Any]:
        """Parse Windows Event Log format"""
        fields = {}
        
        # Extract common Windows Event fields
        patterns = {
            'event_id': r'EventID[:\s]+(\d+)',
            'level': r'Level[:\s]+(\w+)',
            'source': r'(?:Source|Provider)[:\s]+([^\n,]+)',
            'message': r'Message[:\s]+(.+?)(?:\n|$)',
            'user': r'User[:\s]+([^\n,]+)',
            'computer': r'Computer[:\s]+([^\n,]+)',
        }
        
        for field, pattern in patterns.items():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                fields[field] = match.group(1).strip()
        
        return fields
    
    def parse_syslog(self, line: str) -> Dict[str, Any]:
        """Parse Syslog format"""
        fields = {}
        
        # Syslog format: <priority>timestamp hostname process[pid]: message
        syslog_pattern = r'(?:<(\d+)>)?(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:\[]+)(?:\[(\d+)\])?:\s*(.+)'
        
        match = re.match(syslog_pattern, line)
        if match:
            priority, timestamp, hostname, process, pid, message = match.groups()
            fields['priority'] = priority
            fields['host'] = hostname
            fields['process'] = process
            fields['pid'] = pid
            fields['message'] = message
        
        return fields
    
    def parse_apache_access(self, line: str) -> Dict[str, Any]:
        """Parse Apache/Nginx access log"""
        fields = {}
        
        # Common Log Format: IP - - [timestamp] "method URI protocol" status size
        apache_pattern = r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+([^"]+)"\s+(\d+)\s+(\S+)'
        
        match = re.match(apache_pattern, line)
        if match:
            ip, timestamp, method, uri, protocol, status, size = match.groups()
            fields['ip'] = ip
            fields['method'] = method
            fields['uri'] = uri
            fields['protocol'] = protocol
            fields['status_code'] = status
            fields['size'] = size
        
        return fields
    
    def parse_line(self, line: str, format_type: str = None) -> Dict[str, Any]:
        """
        Parse a single log line
        
        Args:
            line: Log line to parse
            format_type: Detected format type
            
        Returns:
            Dictionary of parsed fields
        """
        if not line.strip():
            return None
        
        result = {
            'raw_line': line.strip(),
            'line_number': None  # Will be set by processor
        }
        
        # Extract timestamp first
        timestamp_info = self.extract_timestamp(line)
        if timestamp_info:
            dt, ts_format = timestamp_info
            result['timestamp'] = dt.isoformat()
            result['timestamp_format'] = ts_format
        
        # Try format-specific parsing
        if format_type == 'json':
            json_data = self.parse_json_line(line)
            if json_data:
                result.update(json_data)
                return result
        
        elif format_type == 'windows_event' or format_type == 'powershell':
            result.update(self.parse_windows_event(line))
        
        elif format_type == 'syslog':
            result.update(self.parse_syslog(line))
        
        elif format_type == 'apache_access':
            result.update(self.parse_apache_access(line))
        
        # Generic key-value extraction
        kv_pairs = self.extract_key_value_pairs(line)
        result.update(kv_pairs)
        
        # If no structured fields found, store as message
        if len(result) <= 2:  # Only raw_line and maybe timestamp
            result['message'] = line.strip()
        
        return result


class LogProcessor:
    """Process multiple log files and perform analysis"""
    
    def __init__(self):
        self.parser = LogParser()
        self.entries = []
        self.stats = defaultdict(Counter)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def process_file(self, filepath: Path, format_type: str = None) -> List[Dict]:
        """
        Process a single log file
        
        Args:
            filepath: Path to log file
            format_type: Force specific format (None = auto-detect)
            
        Returns:
            List of parsed log entries
        """
        self.logger.info(f"Processing: {filepath}")
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            self.logger.error(f"Error reading {filepath}: {e}")
            return []
        
        # Auto-detect format if not specified
        if format_type is None:
            format_type = self.parser.detect_format(lines)
        
        self.logger.info(f"Using format: {format_type}")
        
        # Parse lines
        entries = []
        for line_num, line in enumerate(lines, 1):
            parsed = self.parser.parse_line(line, format_type)
            if parsed:
                parsed['line_number'] = line_num
                parsed['source_file'] = str(filepath)
                entries.append(parsed)
        
        self.logger.info(f"Parsed {len(entries)} entries from {filepath.name}")
        return entries
    
    def process_directory(self, directory: Path, pattern: str = "*.log",
                         recursive: bool = True) -> List[Dict]:
        """
        Process all log files in directory
        
        Args:
            directory: Directory path
            pattern: File pattern to match
            recursive: Scan subdirectories
            
        Returns:
            List of all parsed entries
        """
        if recursive:
            files = list(directory.rglob(pattern))
        else:
            files = list(directory.glob(pattern))
        
        # Also check for .txt files
        if pattern == "*.log":
            if recursive:
                files.extend(directory.rglob("*.txt"))
            else:
                files.extend(directory.glob("*.txt"))
        
        self.logger.info(f"Found {len(files)} file(s) to process")
        
        all_entries = []
        for filepath in files:
            if filepath.is_file():
                entries = self.process_file(filepath)
                all_entries.extend(entries)
        
        self.entries = all_entries
        return all_entries
    
    def generate_statistics(self) -> Dict:
        """Generate statistics from processed entries"""
        if not self.entries:
            return {}
        
        stats = {
            'total_entries': len(self.entries),
            'files_processed': len(set(e.get('source_file') for e in self.entries)),
            'timestamp_formats': Counter(e.get('timestamp_format') for e in self.entries if e.get('timestamp_format')),
            'fields_found': set(),
        }
        
        # Collect all field names
        for entry in self.entries:
            stats['fields_found'].update(entry.keys())
        
        stats['fields_found'] = sorted(stats['fields_found'])
        
        # Time range
        timestamps = [e['timestamp'] for e in self.entries if 'timestamp' in e]
        if timestamps:
            timestamps.sort()
            stats['earliest'] = timestamps[0]
            stats['latest'] = timestamps[-1]
        
        # Level distribution
        levels = [e.get('level', 'unknown') for e in self.entries]
        stats['level_distribution'] = dict(Counter(levels))
        
        # Source distribution
        sources = [e.get('source', 'unknown') for e in self.entries]
        stats['source_distribution'] = dict(Counter(sources).most_common(10))
        
        return stats
    
    def search(self, keyword: str = None, field: str = None,
              start_time: str = None, end_time: str = None) -> List[Dict]:
        """
        Search log entries
        
        Args:
            keyword: Keyword to search for (searches all fields)
            field: Specific field to search
            start_time: Start time filter (ISO format)
            end_time: End time filter (ISO format)
            
        Returns:
            Filtered list of entries
        """
        results = self.entries
        
        # Keyword search
        if keyword:
            keyword_lower = keyword.lower()
            if field:
                results = [e for e in results if field in e and 
                          keyword_lower in str(e[field]).lower()]
            else:
                results = [e for e in results if 
                          any(keyword_lower in str(v).lower() for v in e.values())]
        
        # Time filtering
        if start_time:
            results = [e for e in results if 'timestamp' in e and 
                      e['timestamp'] >= start_time]
        
        if end_time:
            results = [e for e in results if 'timestamp' in e and 
                      e['timestamp'] <= end_time]
        
        return results
    
    def save_results(self, entries: List[Dict], output_file: Path,
                    format: str = 'csv'):
        """
        Save parsed entries to file
        
        Args:
            entries: List of entries to save
            output_file: Output file path
            format: Output format ('csv' or 'json')
        """
        if not entries:
            self.logger.warning("No entries to save")
            return
        
        if format == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(entries, f, indent=2, default=str)
        
        elif format == 'csv':
            # Get all unique fields
            all_fields = set()
            for entry in entries:
                all_fields.update(entry.keys())
            
            fieldnames = sorted(all_fields)
            
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(entries)
        
        self.logger.info(f"Saved {len(entries)} entries to {output_file}")


def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description='Intelligent Log Processor - Automatic log parsing and analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process single log file
  python log_processor.py -f system.log -o parsed.csv
  
  # Process directory of logs
  python log_processor.py -d /var/log -r -o all_logs.json -F json
  
  # Search for keyword
  python log_processor.py -d /logs -r --search "error" -o errors.csv
  
  # Time range filtering
  python log_processor.py -f app.log --start "2024-12-01" --end "2024-12-15" -o range.csv
  
  # Generate statistics
  python log_processor.py -d /logs -r --stats -o stats.json
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-f', '--file', help='Single log file to process')
    input_group.add_argument('-d', '--directory', help='Directory of log files')
    
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Process directories recursively')
    parser.add_argument('-p', '--pattern', default='*.log',
                       help='File pattern to match (default: *.log)')
    parser.add_argument('--format', choices=['json', 'syslog', 'windows_event', 'apache_access', 'generic'],
                       help='Force specific log format (default: auto-detect)')
    
    # Output options
    parser.add_argument('-o', '--output', required=True,
                       help='Output file path')
    parser.add_argument('-F', '--output-format', choices=['csv', 'json'], default='csv',
                       help='Output format (default: csv)')
    
    # Search/filter options
    parser.add_argument('--search', help='Search for keyword')
    parser.add_argument('--field', help='Search in specific field')
    parser.add_argument('--start', help='Start time filter (ISO format)')
    parser.add_argument('--end', help='End time filter (ISO format)')
    
    # Statistics
    parser.add_argument('--stats', action='store_true',
                       help='Generate and save statistics')
    
    args = parser.parse_args()
    
    # Create processor
    processor = LogProcessor()
    
    # Process files
    if args.file:
        entries = processor.process_file(Path(args.file), format_type=args.format)
    else:
        entries = processor.process_directory(
            Path(args.directory),
            pattern=args.pattern,
            recursive=args.recursive
        )
    
    # Apply filters
    if args.search or args.start or args.end:
        entries = processor.search(
            keyword=args.search,
            field=args.field,
            start_time=args.start,
            end_time=args.end
        )
        print(f"Found {len(entries)} matching entries")
    
    # Generate statistics
    if args.stats:
        stats = processor.generate_statistics()
        print("\n" + "="*60)
        print("LOG PROCESSING STATISTICS")
        print("="*60)
        print(f"Total entries: {stats['total_entries']}")
        print(f"Files processed: {stats['files_processed']}")
        print(f"\nFields found: {', '.join(stats['fields_found'][:10])}...")
        print(f"\nTimestamp formats: {dict(stats['timestamp_formats'])}")
        if 'earliest' in stats:
            print(f"\nTime range: {stats['earliest']} to {stats['latest']}")
        print("="*60 + "\n")
        
        # Save stats
        stats_file = Path(args.output).with_suffix('.stats.json')
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2, default=str)
        print(f"Statistics saved to: {stats_file}")
    
    # Save results
    processor.save_results(entries, Path(args.output), format=args.output_format)
    
    return 0


if __name__ == '__main__':
    exit(main())
