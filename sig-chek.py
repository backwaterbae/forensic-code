#!/usr/bin/env python3
"""
Signature Testing & Validation Utility
Test signatures before running full dump analysis
"""

import re
import sys
from pathlib import Path
from collections import defaultdict


class SignatureValidator:
    """Validates and tests signature files"""
    
    def __init__(self):
        self.stats = {
            'total': 0,
            'exact': 0,
            'partial': 0,
            'regex': 0,
            'invalid': 0,
            'comments': 0
        }
        self.errors = []
    
    def validate_file(self, filepath: Path) -> bool:
        """Validate signature file format"""
        print(f"\n[*] Validating: {filepath.name}")
        print("-" * 60)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            return False
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            if not line:
                continue
            
            if line.startswith('#'):
                self.stats['comments'] += 1
                continue
            
            self.stats['total'] += 1
            
            # Validate regex patterns
            if line.startswith('REGEX:'):
                pattern = line[6:].strip()
                try:
                    re.compile(pattern, re.IGNORECASE)
                    self.stats['regex'] += 1
                    print(f"  ✓ Line {line_num:4d}: REGEX    '{pattern[:50]}'")
                except re.error as e:
                    self.stats['invalid'] += 1
                    error = f"Line {line_num}: Invalid regex '{pattern}' - {e}"
                    self.errors.append(error)
                    print(f"  ✗ Line {line_num:4d}: ERROR    {e}")
            
            elif line.startswith('PARTIAL:'):
                sig = line[8:].strip()
                if sig:
                    self.stats['partial'] += 1
                    print(f"  ✓ Line {line_num:4d}: PARTIAL  '{sig[:50]}'")
                else:
                    self.stats['invalid'] += 1
                    error = f"Line {line_num}: Empty PARTIAL signature"
                    self.errors.append(error)
                    print(f"  ✗ Line {line_num:4d}: ERROR    Empty PARTIAL")
            
            elif line.startswith('EXACT:'):
                sig = line[6:].strip()
                if sig:
                    self.stats['exact'] += 1
                    print(f"  ✓ Line {line_num:4d}: EXACT    '{sig[:50]}'")
                else:
                    self.stats['invalid'] += 1
                    error = f"Line {line_num}: Empty EXACT signature"
                    self.errors.append(error)
                    print(f"  ✗ Line {line_num:4d}: ERROR    Empty EXACT")
            
            else:
                # Default to exact match
                self.stats['exact'] += 1
                print(f"  ✓ Line {line_num:4d}: EXACT    '{line[:50]}'")
        
        return self.stats['invalid'] == 0
    
    def print_summary(self):
        """Print validation summary"""
        print("\n" + "=" * 60)
        print("VALIDATION SUMMARY")
        print("=" * 60)
        print(f"Total signatures:    {self.stats['total']}")
        print(f"  - Exact matches:   {self.stats['exact']}")
        print(f"  - Partial matches: {self.stats['partial']}")
        print(f"  - Regex patterns:  {self.stats['regex']}")
        print(f"Comment lines:       {self.stats['comments']}")
        print(f"Invalid signatures:  {self.stats['invalid']}")
        
        if self.errors:
            print("\nERRORS:")
            for error in self.errors:
                print(f"  ✗ {error}")
            print(f"\n[!] Validation FAILED with {len(self.errors)} error(s)")
            return False
        else:
            print("\n[✓] Validation PASSED - All signatures are valid")
            return True


class SignatureTester:
    """Test signatures against sample text"""
    
    def __init__(self, sig_file: Path):
        self.sig_file = sig_file
        self.exact_strings = set()
        self.regex_patterns = []
        self.partial_strings = set()
        self._load_signatures()
    
    def _load_signatures(self):
        """Load signatures from file"""
        with open(self.sig_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if line.startswith('REGEX:'):
                    pattern = line[6:].strip()
                    try:
                        compiled = re.compile(pattern, re.IGNORECASE)
                        self.regex_patterns.append((pattern, compiled))
                    except re.error:
                        pass
                
                elif line.startswith('PARTIAL:'):
                    sig = line[8:].strip()
                    self.partial_strings.add(sig.lower())
                
                elif line.startswith('EXACT:'):
                    sig = line[6:].strip()
                    self.exact_strings.add(sig)
                
                else:
                    self.exact_strings.add(line)
    
    def test_text(self, text: str) -> list:
        """Test text against all signatures"""
        matches = []
        
        # Exact matches
        for sig in self.exact_strings:
            if sig in text:
                matches.append(('EXACT', sig))
        
        # Partial matches
        text_lower = text.lower()
        for sig in self.partial_strings:
            if sig in text_lower:
                matches.append(('PARTIAL', sig))
        
        # Regex matches
        for pattern_str, pattern in self.regex_patterns:
            if pattern.search(text):
                matches.append(('REGEX', pattern_str))
        
        return matches
    
    def test_file(self, test_file: Path):
        """Test signatures against a file"""
        print(f"\n[*] Testing signatures against: {test_file.name}")
        print("=" * 60)
        
        match_count = 0
        with open(test_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                matches = self.test_text(line)
                if matches:
                    match_count += len(matches)
                    print(f"\nLine {line_num}: {line.strip()[:80]}")
                    for match_type, sig in matches:
                        print(f"  → {match_type}: {sig[:60]}")
        
        print(f"\n[✓] Found {match_count} matches")
    
    def interactive_test(self):
        """Interactive testing mode"""
        print("\n[*] Interactive Signature Testing")
        print("=" * 60)
        print("Enter text to test (or 'quit' to exit):\n")
        
        while True:
            try:
                text = input("> ")
                if text.lower() in ['quit', 'exit', 'q']:
                    break
                
                matches = self.test_text(text)
                if matches:
                    print(f"  Found {len(matches)} match(es):")
                    for match_type, sig in matches:
                        print(f"    → {match_type}: {sig}")
                else:
                    print("  No matches found")
                print()
                
            except (KeyboardInterrupt, EOFError):
                break
        
        print("\n[*] Exiting interactive mode")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Signature Testing & Validation Utility',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate signature file
  %(prog)s --validate signatures.txt
  
  # Test signatures against a file
  %(prog)s --test-file sample.txt signatures.txt
  
  # Interactive testing
  %(prog)s --interactive signatures.txt
  
  # Validate multiple signature files
  %(prog)s --validate sigs1.txt sigs2.txt sigs3.txt
        """
    )
    
    parser.add_argument('signatures', nargs='?', type=Path,
                       help='Signature file to test')
    parser.add_argument('--validate', action='store_true',
                       help='Validate signature file format')
    parser.add_argument('--test-file', type=Path,
                       help='Test signatures against this file')
    parser.add_argument('--interactive', '-i', action='store_true',
                       help='Interactive testing mode')
    parser.add_argument('--batch-validate', nargs='+', type=Path,
                       help='Validate multiple signature files')
    
    args = parser.parse_args()
    
    # Batch validation
    if args.batch_validate:
        all_valid = True
        for sig_file in args.batch_validate:
            validator = SignatureValidator()
            valid = validator.validate_file(sig_file)
            validator.print_summary()
            if not valid:
                all_valid = False
        
        return 0 if all_valid else 1
    
    # Single file operations
    if not args.signatures:
        parser.error('signature file required')
    
    if not args.signatures.exists():
        print(f"[!] File not found: {args.signatures}")
        return 1
    
    # Validate
    if args.validate or (not args.test_file and not args.interactive):
        validator = SignatureValidator()
        valid = validator.validate_file(args.signatures)
        validator.print_summary()
        return 0 if valid else 1
    
    # Test against file
    if args.test_file:
        if not args.test_file.exists():
            print(f"[!] Test file not found: {args.test_file}")
            return 1
        
        tester = SignatureTester(args.signatures)
        tester.test_file(args.test_file)
        return 0
    
    # Interactive mode
    if args.interactive:
        tester = SignatureTester(args.signatures)
        tester.interactive_test()
        return 0
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
