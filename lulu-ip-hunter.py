#!/usr/bin/env python3
"""
IP Correlation Analyzer - Find and tier IP addresses across multiple log files
Designed for forensic log analysis and threat correlation
"""

import re
import csv
import json
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple
import argparse


class IPCorrelator:
    """Correlate IP addresses across multiple log files"""
    
    # Comprehensive IP address regex
    IP_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    
    # Timestamp patterns for temporal correlation
    TIMESTAMP_PATTERNS = [
        # Syslog: Dec 15 00:05:57
        (r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', '%b %d %H:%M:%S', 'syslog'),
        # DirectAdmin: 2025:12:14-15:28:32
        (r'(\d{4}:\d{2}:\d{2}-\d{2}:\d{2}:\d{2})', '%Y:%m:%d-%H:%M:%S', 'directadmin'),
        # CSV: December 15, 2025, 8:13 am
        (r'(\w+ \d+, \d{4}, \d{1,2}:\d{2} [ap]m)', '%B %d, %Y, %I:%M %p', 'csv'),
        # Generic ISO
        (r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', '%Y-%m-%d %H:%M:%S', 'iso'),
    ]
    
    def __init__(self):
        self.ip_occurrences = defaultdict(lambda: {
            'files': set(),
            'count': 0,
            'timestamps': [],
            'contexts': []
        })
        
    def extract_ips_from_line(self, line: str) -> List[str]:
        """
        Extract all IP addresses from a line
        
        Args:
            line: Log line
            
        Returns:
            List of IP addresses found
        """
        return re.findall(self.IP_PATTERN, line)
    
    def extract_timestamp(self, line: str) -> Tuple[datetime, str]:
        """
        Extract timestamp from line
        
        Args:
            line: Log line
            
        Returns:
            Tuple of (datetime object, format type) or (None, None)
        """
        for pattern, date_format, format_type in self.TIMESTAMP_PATTERNS:
            match = re.search(pattern, line)
            if match:
                timestamp_str = match.group(1)
                try:
                    dt = datetime.strptime(timestamp_str, date_format)
                    # Add current year for syslog
                    if format_type == 'syslog' and dt.year == 1900:
                        dt = dt.replace(year=datetime.now().year)
                    return (dt, format_type)
                except:
                    continue
        return (None, None)
    
    def process_file(self, filepath: Path, label: str = None, start_date: datetime = None, end_date: datetime = None):
        """
        Process a single log file and extract IPs
        
        Args:
            filepath: Path to log file
            label: Optional label for the file (default: filename)
            start_date: Optional start date filter
            end_date: Optional end date filter
        """
        if label is None:
            label = filepath.name
        
        print(f"Processing: {label}")
        
        try:
            # Try different encodings
            for encoding in ['utf-8', 'latin-1', 'iso-8859-1']:
                try:
                    with open(filepath, 'r', encoding=encoding, errors='ignore') as f:
                        lines = f.readlines()
                    break
                except UnicodeDecodeError:
                    continue
        except Exception as e:
            print(f"  Error reading {filepath}: {e}")
            return
        
        ip_count = 0
        line_count = 0
        filtered_count = 0
        
        for line_num, line in enumerate(lines, 1):
            line_count += 1
            
            # Extract timestamp for filtering
            timestamp, ts_format = self.extract_timestamp(line)
            
            # Date range filtering
            if start_date and timestamp and timestamp < start_date:
                filtered_count += 1
                continue
            if end_date and timestamp and timestamp > end_date:
                filtered_count += 1
                continue
            
            ips = self.extract_ips_from_line(line)
            
            if ips:
                for ip in ips:
                    self.ip_occurrences[ip]['files'].add(label)
                    self.ip_occurrences[ip]['count'] += 1
                    ip_count += 1
                    
                    if timestamp:
                        self.ip_occurrences[ip]['timestamps'].append(timestamp)
                    
                    # Store context (truncated line)
                    context = line.strip()[:200]
                    self.ip_occurrences[ip]['contexts'].append({
                        'file': label,
                        'line': line_num,
                        'context': context,
                        'timestamp': timestamp.isoformat() if timestamp else None
                    })
        
        print(f"  Lines processed: {line_count:,}")
        if start_date or end_date:
            print(f"  Lines filtered out: {filtered_count:,}")
        print(f"  IP addresses found: {ip_count:,}")
        print(f"  Unique IPs: {len([ip for ip, data in self.ip_occurrences.items() if label in data['files']]):,}")
    
    def tier_ips(self, num_files: int) -> Dict[int, List[Tuple[str, Dict]]]:
        """
        Tier IPs based on how many files they appear in
        
        Args:
            num_files: Total number of files processed
            
        Returns:
            Dictionary mapping tier number to list of (IP, data) tuples
        """
        tiers = defaultdict(list)
        
        for ip, data in self.ip_occurrences.items():
            num_appearances = len(data['files'])
            
            # Tier 1: Appears in all files (highest priority)
            # Tier 2: Appears in all but one file
            # Tier 3: Appears in 2 files
            # Tier 4: Appears in 1 file only
            
            if num_appearances == num_files:
                tier = 1
            elif num_appearances == num_files - 1:
                tier = 2
            elif num_appearances == 2:
                tier = 3
            else:
                tier = 4
            
            tiers[tier].append((ip, data))
        
        # Sort each tier by count (most occurrences first)
        for tier in tiers:
            tiers[tier].sort(key=lambda x: x[1]['count'], reverse=True)
        
        return dict(tiers)
    
    def find_temporal_correlations(self, time_window_minutes: int = 20) -> List[Dict]:
        """
        Find IPs that appear in multiple logs within a time window
        
        Args:
            time_window_minutes: Time window in minutes
            
        Returns:
            List of correlation events
        """
        correlations = []
        
        for ip, data in self.ip_occurrences.items():
            if len(data['files']) < 2:
                continue
            
            # Get all timestamps for this IP
            timestamps = sorted([ts for ts in data['timestamps'] if ts])
            
            if len(timestamps) < 2:
                continue
            
            # Check for events within time window
            for i, ts1 in enumerate(timestamps[:-1]):
                for ts2 in timestamps[i+1:]:
                    delta = abs((ts2 - ts1).total_seconds() / 60)
                    
                    if delta <= time_window_minutes:
                        # Find which files these timestamps came from
                        contexts = [c for c in data['contexts'] 
                                  if c['timestamp'] in [ts1.isoformat(), ts2.isoformat()]]
                        
                        files_involved = set(c['file'] for c in contexts)
                        
                        if len(files_involved) > 1:
                            correlations.append({
                                'ip': ip,
                                'time_window_minutes': delta,
                                'files': list(files_involved),
                                'timestamps': [ts1.isoformat(), ts2.isoformat()],
                                'contexts': contexts[:3]  # First 3 contexts
                            })
        
        # Sort by time window (closest events first)
        correlations.sort(key=lambda x: x['time_window_minutes'])
        
        return correlations
    
    def generate_report(self, tiers: Dict, num_files: int, output_file: Path = None, start_date: datetime = None, end_date: datetime = None):
        """
        Generate comprehensive report
        
        Args:
            tiers: Tiered IP data
            num_files: Total number of files
            output_file: Optional output file path
            start_date: Optional start date filter
            end_date: Optional end date filter
        """
        report_lines = []
        
        report_lines.append("="*80)
        report_lines.append("IP CORRELATION ANALYSIS REPORT")
        report_lines.append("="*80)
        report_lines.append("")
        report_lines.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Total Files Analyzed: {num_files}")
        
        if start_date:
            report_lines.append(f"Date Range Filter: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d') if end_date else 'present'}")
        
        report_lines.append(f"Total Unique IPs Found: {len(self.ip_occurrences)}")
        report_lines.append("")
        
        # Tier summary
        report_lines.append("TIER SUMMARY")
        report_lines.append("-" * 80)
        for tier in sorted(tiers.keys()):
            count = len(tiers[tier])
            if tier == 1:
                desc = f"IPs in ALL {num_files} logs (CRITICAL)"
            elif tier == 2:
                desc = f"IPs in {num_files-1} logs (HIGH PRIORITY)"
            elif tier == 3:
                desc = "IPs in 2 logs (MEDIUM PRIORITY)"
            else:
                desc = "IPs in 1 log only (LOW PRIORITY)"
            
            report_lines.append(f"Tier {tier}: {count:,} IPs - {desc}")
        report_lines.append("")
        
        # Detailed tier information
        for tier in sorted(tiers.keys()):
            if not tiers[tier]:
                continue
            
            report_lines.append("="*80)
            report_lines.append(f"TIER {tier} DETAILS")
            report_lines.append("="*80)
            report_lines.append("")
            
            for ip, data in tiers[tier][:50]:  # Top 50 per tier
                report_lines.append(f"IP Address: {ip}")
                report_lines.append(f"  Total Occurrences: {data['count']}")
                report_lines.append(f"  Found in Files: {', '.join(sorted(data['files']))}")
                
                if data['timestamps']:
                    earliest = min(data['timestamps'])
                    latest = max(data['timestamps'])
                    report_lines.append(f"  Time Range: {earliest.strftime('%Y-%m-%d %H:%M:%S')} to {latest.strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Show sample contexts (max 2)
                report_lines.append(f"  Sample Occurrences:")
                for context in data['contexts'][:2]:
                    report_lines.append(f"    [{context['file']}:{context['line']}] {context['context'][:100]}")
                
                report_lines.append("")
            
            if len(tiers[tier]) > 50:
                report_lines.append(f"  ... and {len(tiers[tier]) - 50} more IPs in Tier {tier}")
                report_lines.append("")
        
        report = "\n".join(report_lines)
        
        # Print to console
        print(report)
        
        # Save to file if specified
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\nReport saved to: {output_file}")
    
    def save_json_report(self, tiers: Dict, correlations: List, output_file: Path):
        """
        Save detailed JSON report
        
        Args:
            tiers: Tiered IP data
            correlations: Temporal correlations
            output_file: Output file path
        """
        # Convert sets to lists for JSON serialization
        json_data = {
            'analysis_date': datetime.now().isoformat(),
            'total_unique_ips': len(self.ip_occurrences),
            'tiers': {},
            'temporal_correlations': correlations
        }
        
        for tier, ips in tiers.items():
            json_data['tiers'][f'tier_{tier}'] = [
                {
                    'ip': ip,
                    'files': list(data['files']),
                    'count': data['count'],
                    'timestamps': [ts.isoformat() for ts in data['timestamps'] if ts],
                    'sample_contexts': data['contexts'][:5]
                }
                for ip, data in ips
            ]
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, default=str)
        
        print(f"Detailed JSON report saved to: {output_file}")
    
    def save_csv_report(self, tiers: Dict, output_file: Path):
        """
        Save CSV report for easy import into Excel/other tools
        
        Args:
            tiers: Tiered IP data
            output_file: Output file path
        """
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Tier',
                'IP Address',
                'Total Count',
                'Files Found In',
                'Number of Files',
                'Earliest Timestamp',
                'Latest Timestamp',
                'Sample Context'
            ])
            
            for tier in sorted(tiers.keys()):
                for ip, data in tiers[tier]:
                    files = ', '.join(sorted(data['files']))
                    
                    earliest = min(data['timestamps']).isoformat() if data['timestamps'] else 'N/A'
                    latest = max(data['timestamps']).isoformat() if data['timestamps'] else 'N/A'
                    
                    sample_context = data['contexts'][0]['context'] if data['contexts'] else ''
                    
                    writer.writerow([
                        tier,
                        ip,
                        data['count'],
                        files,
                        len(data['files']),
                        earliest,
                        latest,
                        sample_context
                    ])
        
        print(f"CSV report saved to: {output_file}")


def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description='IP Correlation Analyzer - Find and tier IPs across multiple logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze multiple log files
  python ip_correlator.py -f log1.txt log2.txt log3.csv -o report.txt
  
  # With temporal correlation (20 minute window)
  python ip_correlator.py -f *.log -t 20 -o report.txt
  
  # Generate all output formats
  python ip_correlator.py -f *.log -o report.txt --csv ips.csv --json details.json
  
Tier Definitions:
  Tier 1: IP appears in ALL logs (CRITICAL - highest priority)
  Tier 2: IP appears in N-1 logs (HIGH PRIORITY)
  Tier 3: IP appears in 2 logs (MEDIUM PRIORITY)
  Tier 4: IP appears in 1 log only (LOW PRIORITY)
        """
    )
    
    parser.add_argument('-f', '--files', nargs='+', required=True,
                       help='Log files to analyze')
    
    parser.add_argument('-o', '--output', required=True,
                       help='Output report file (text format)')
    
    parser.add_argument('--csv', help='CSV output file')
    parser.add_argument('--json', help='JSON output file')
    
    parser.add_argument('-t', '--time-window', type=int, default=20,
                       help='Time window in minutes for temporal correlation (default: 20)')
    
    parser.add_argument('--no-temporal', action='store_true',
                       help='Skip temporal correlation analysis')
    
    parser.add_argument('--start-date', help='Start date filter (YYYY-MM-DD format)')
    parser.add_argument('--end-date', help='End date filter (YYYY-MM-DD format)')
    
    args = parser.parse_args()
    
    # Create correlator
    correlator = IPCorrelator()
    
    # Parse date filters if provided
    start_date = None
    end_date = None
    
    if args.start_date:
        try:
            start_date = datetime.strptime(args.start_date, '%Y-%m-%d')
            print(f"Filtering from: {start_date.strftime('%Y-%m-%d')}")
        except ValueError:
            print(f"Warning: Invalid start date format: {args.start_date}")
    
    if args.end_date:
        try:
            # Set to end of day
            end_date = datetime.strptime(args.end_date, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
            print(f"Filtering to: {end_date.strftime('%Y-%m-%d')}")
        except ValueError:
            print(f"Warning: Invalid end date format: {args.end_date}")
    
    # Process all files
    print(f"\nProcessing {len(args.files)} log file(s)...\n")
    for filepath in args.files:
        path = Path(filepath)
        if path.exists():
            correlator.process_file(path, start_date=start_date, end_date=end_date)
        else:
            print(f"Warning: File not found: {filepath}")
    
    print(f"\n{'='*80}")
    print("ANALYSIS COMPLETE")
    print(f"{'='*80}\n")
    
    # Tier IPs
    num_files = len(args.files)
    tiers = correlator.tier_ips(num_files)
    
    # Generate reports
    correlator.generate_report(tiers, num_files, Path(args.output), start_date=start_date, end_date=end_date)
    
    if args.csv:
        correlator.save_csv_report(tiers, Path(args.csv))
    
    # Temporal correlation
    correlations = []
    if not args.no_temporal:
        print(f"\nAnalyzing temporal correlations (within {args.time_window} minutes)...")
        correlations = correlator.find_temporal_correlations(args.time_window)
        
        if correlations:
            print(f"Found {len(correlations)} temporal correlation events")
            print("\nTop 5 Temporal Correlations:")
            for i, corr in enumerate(correlations[:5], 1):
                print(f"\n{i}. IP: {corr['ip']}")
                print(f"   Files: {', '.join(corr['files'])}")
                print(f"   Time Window: {corr['time_window_minutes']:.1f} minutes")
                print(f"   Timestamps: {corr['timestamps'][0]} - {corr['timestamps'][1]}")
        else:
            print("No temporal correlations found within the time window")
    
    if args.json:
        correlator.save_json_report(tiers, correlations, Path(args.json))
    
    print(f"\n{'='*80}")
    print("Analysis complete! Review the report files for detailed findings.")
    print(f"{'='*80}\n")
    
    return 0


if __name__ == '__main__':
    exit(main())
