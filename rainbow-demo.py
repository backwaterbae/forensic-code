#!/usr/bin/env python3
"""
Demo Script for Rainbow Table Tools
Shows basic usage and verifies functionality
"""

import sys
import os
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from rainbow_generator import RainbowTableGenerator
from rainbow_search import RainbowTableSearcher


def demo_basic_usage():
    """Demonstrate basic rainbow table generation and search"""
    
    print("="*70)
    print("RAINBOW TABLE TOOLS - DEMO")
    print("="*70)
    print()
    
    # Configuration
    demo_dir = "demo_tables"
    charset = "abc123"
    min_len = 3
    max_len = 4
    algorithm = "sha256"
    
    print(f"Configuration:")
    print(f"  Charset: {charset}")
    print(f"  Lengths: {min_len}-{max_len}")
    print(f"  Algorithm: {algorithm}")
    print(f"  Output: {demo_dir}/")
    print()
    
    # Step 1: Generate rainbow tables
    print("-" * 70)
    print("STEP 1: Generating Rainbow Tables")
    print("-" * 70)
    
    generator = RainbowTableGenerator(
        charset=charset,
        salt="",
        algorithm=algorithm,
        output_dir=demo_dir
    )
    
    summary = generator.generate(
        min_length=min_len,
        max_length=max_len,
        max_workers=2
    )
    
    print(f"\n✓ Generated {summary['total_passwords']:,} passwords in {summary['elapsed_time']:.2f}s")
    print(f"✓ Speed: {summary['passwords_per_second']:,.0f} passwords/second")
    print()
    
    # Step 2: Demo searches
    print("-" * 70)
    print("STEP 2: Searching Rainbow Tables")
    print("-" * 70)
    print()
    
    searcher = RainbowTableSearcher(table_directory=demo_dir)
    
    # Test cases - these are known password/hash pairs for our charset
    test_cases = [
        # Format: (password, description)
        ("abc", "Simple 3-char password"),
        ("123", "Numeric 3-char password"),
        ("a1b2", "Mixed 4-char password"),
        ("xyz", "Not in charset - should fail"),
    ]
    
    for password, description in test_cases:
        # Generate the hash for this password
        import hashlib
        h = hashlib.sha256()
        h.update(password.encode('utf-8'))
        test_hash = h.hexdigest()
        
        print(f"Test: {description}")
        print(f"  Password: {password}")
        print(f"  Hash: {test_hash}")
        
        result = searcher.search(test_hash, algorithm=algorithm)
        
        if result['found']:
            print(f"  ✓ FOUND: '{result['password']}' in {result['elapsed_time']:.4f}s")
            if result['password'] == password:
                print(f"  ✓ MATCH: Correct password recovered!")
            else:
                print(f"  ✗ ERROR: Found '{result['password']}' but expected '{password}'")
        else:
            if password == "xyz":
                print(f"  ✓ EXPECTED: Not found (not in charset)")
            else:
                print(f"  ✗ ERROR: Should have been found!")
        print()
    
    # Step 3: Batch search demo
    print("-" * 70)
    print("STEP 3: Batch Search Demo")
    print("-" * 70)
    print()
    
    # Create a batch file with multiple hashes
    batch_file = Path(demo_dir) / "demo_hashes.txt"
    
    # Generate some test hashes
    test_passwords = ["abc", "123", "a1b", "c3c"]
    with open(batch_file, 'w') as f:
        for pw in test_passwords:
            h = hashlib.sha256()
            h.update(pw.encode('utf-8'))
            f.write(f"{h.hexdigest()}\n")
    
    print(f"Created batch file: {batch_file}")
    print(f"  Contains {len(test_passwords)} hashes")
    print()
    
    results = searcher.batch_search(str(batch_file), algorithm=algorithm)
    
    print("\nBatch Results Summary:")
    for i, result in enumerate(results, 1):
        status = "✓ Found" if result['found'] else "✗ Not found"
        password = result['password'] if result['found'] else "N/A"
        print(f"  {i}. {status}: {password}")
    
    print()
    print("="*70)
    print("DEMO COMPLETE")
    print("="*70)
    print()
    print("Generated files:")
    for file in sorted(Path(demo_dir).glob("*")):
        size = file.stat().st_size
        print(f"  {file.name:40s} {size:>10,} bytes")
    print()
    print("To clean up: rm -rf demo_tables/")
    print()


def demo_comparison():
    """Compare different hash algorithms"""
    
    print("\n" + "="*70)
    print("ALGORITHM COMPARISON DEMO")
    print("="*70)
    print()
    
    import hashlib
    import time
    
    password = "test123"
    algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    
    print(f"Testing password: '{password}'")
    print()
    print(f"{'Algorithm':<10} {'Hash Length':<15} {'Hash Value'}")
    print("-" * 70)
    
    for name, func in algorithms.items():
        h = func()
        h.update(password.encode('utf-8'))
        digest = h.hexdigest()
        print(f"{name:<10} {len(digest):<15} {digest}")
    
    print()


if __name__ == '__main__':
    print("\n")
    
    # Check if demo directory exists
    if Path("demo_tables").exists():
        response = input("Demo tables directory exists. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print("Demo cancelled.")
            sys.exit(0)
        # Clean up
        import shutil
        shutil.rmtree("demo_tables")
    
    # Run demos
    demo_basic_usage()
    demo_comparison()
    
    print("\n✓ All demos completed successfully!\n")
