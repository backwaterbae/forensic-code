#!/usr/bin/env python3
"""
Multi-Core Rainbow Table Generator
Modernized version with Python 3, proper error handling, and enhanced features
"""

import hashlib
import time
import itertools
import argparse
import logging
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Set

# Optional tqdm import for progress bars
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    # Fallback: tqdm is just an identity function
    def tqdm(iterable, *args, **kwargs):
        return iterable


class RainbowTableGenerator:
    """Generate rainbow tables using multiple hash algorithms"""
    
    # Supported hash algorithms
    SUPPORTED_ALGORITHMS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }
    
    def __init__(self, charset: str, salt: str = "", algorithm: str = 'sha256', 
                 output_dir: str = 'rainbow_tables'):
        """
        Initialize rainbow table generator
        
        Args:
            charset: Characters to use in password generation
            salt: Salt value to prepend to passwords
            algorithm: Hash algorithm to use (md5, sha1, sha256, sha512)
            output_dir: Directory to store output files
        """
        self.charset = list(charset)
        self.salt = salt
        self.algorithm = algorithm.lower()
        self.output_dir = Path(output_dir)
        
        # Validate algorithm
        if self.algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}. "
                           f"Use one of: {', '.join(self.SUPPORTED_ALGORITHMS.keys())}")
        
        # Create output directory
        self.output_dir.mkdir(exist_ok=True)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def _hash_password(self, password: str) -> str:
        """
        Hash a password with the configured algorithm and salt
        
        Args:
            password: Plain text password
            
        Returns:
            Hexadecimal hash digest
        """
        hash_func = self.SUPPORTED_ALGORITHMS[self.algorithm]
        h = hash_func()
        # Proper encoding and concatenation
        h.update((self.salt + password).encode('utf-8'))
        return h.hexdigest()
    
    def _generate_for_length(self, length: int) -> tuple:
        """
        Generate rainbow table for passwords of specific length
        
        Args:
            length: Password length
            
        Returns:
            Tuple of (length, count, filename)
        """
        filename = self.output_dir / f'rainbow_{self.algorithm}_len{length}.txt'
        pw_count = 0
        
        try:
            # Calculate total combinations for progress bar
            total_combinations = len(self.charset) ** length
            
            with open(filename, 'w', encoding='utf-8') as fp:
                # Create iterator for all combinations
                combinations = itertools.product(self.charset, repeat=length)
                
                # Process with progress bar
                for combo in tqdm(combinations, total=total_combinations, 
                                desc=f"Length {length}", leave=False):
                    password = ''.join(combo)
                    hash_digest = self._hash_password(password)
                    
                    # Write hash:password pair
                    fp.write(f"{hash_digest}:{password}\n")
                    pw_count += 1
            
            self.logger.info(f"Length {length}: {pw_count:,} passwords processed")
            return (length, pw_count, str(filename))
            
        except Exception as e:
            self.logger.error(f"Error processing length {length}: {e}")
            return (length, 0, None)
    
    def generate(self, min_length: int, max_length: int, max_workers: int = None) -> dict:
        """
        Generate rainbow tables for password range using multiprocessing
        
        Args:
            min_length: Minimum password length
            max_length: Maximum password length
            max_workers: Number of worker processes (default: CPU count)
            
        Returns:
            Dictionary with generation statistics
        """
        if max_workers is None:
            import os
            max_workers = os.cpu_count()
        
        self.logger.info(f"Starting rainbow table generation")
        self.logger.info(f"Charset: {self.charset}")
        self.logger.info(f"Algorithm: {self.algorithm}")
        self.logger.info(f"Salt: {'(none)' if not self.salt else '***'}")
        self.logger.info(f"Password lengths: {min_length} - {max_length}")
        self.logger.info(f"Worker processes: {max_workers}")
        
        start_time = time.time()
        lengths = range(min_length, max_length + 1)
        results = []
        total_passwords = 0
        
        # Use ProcessPoolExecutor for modern multiprocessing
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_length = {
                executor.submit(self._generate_for_length, length): length 
                for length in lengths
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_length):
                length, count, filename = future.result()
                results.append({'length': length, 'count': count, 'file': filename})
                total_passwords += count
        
        elapsed_time = time.time() - start_time
        
        # Generate summary
        summary = {
            'algorithm': self.algorithm,
            'charset': ''.join(self.charset),
            'charset_size': len(self.charset),
            'min_length': min_length,
            'max_length': max_length,
            'total_passwords': total_passwords,
            'elapsed_time': elapsed_time,
            'passwords_per_second': total_passwords / elapsed_time if elapsed_time > 0 else 0,
            'files': results,
            'output_directory': str(self.output_dir)
        }
        
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"Rainbow Table Generation Complete!")
        self.logger.info(f"Total passwords: {total_passwords:,}")
        self.logger.info(f"Elapsed time: {elapsed_time:.2f} seconds")
        self.logger.info(f"Speed: {summary['passwords_per_second']:,.0f} passwords/second")
        self.logger.info(f"Output directory: {self.output_dir}")
        self.logger.info(f"{'='*60}\n")
        
        return summary


def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Multi-Core Rainbow Table Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate with default settings (lowercase a-h, SHA-256)
  python rainbow_generator.py -min 4 -max 8
  
  # Use MD5 with custom charset
  python rainbow_generator.py -c "0123456789" -min 4 -max 6 -a md5
  
  # Add salt and use all CPU cores
  python rainbow_generator.py -c "abc123" -min 3 -max 5 -s "MySalt123" -w 8
        """
    )
    
    parser.add_argument('-c', '--charset', 
                       default='abcdefgh',
                       help='Characters to use in password generation (default: abcdefgh)')
    
    parser.add_argument('-min', '--min-length',
                       type=int,
                       default=4,
                       help='Minimum password length (default: 4)')
    
    parser.add_argument('-max', '--max-length',
                       type=int,
                       default=8,
                       help='Maximum password length (default: 8)')
    
    parser.add_argument('-s', '--salt',
                       default='',
                       help='Salt value to prepend to passwords (default: none)')
    
    parser.add_argument('-a', '--algorithm',
                       choices=['md5', 'sha1', 'sha256', 'sha512'],
                       default='sha256',
                       help='Hash algorithm to use (default: sha256)')
    
    parser.add_argument('-o', '--output-dir',
                       default='rainbow_tables',
                       help='Output directory (default: rainbow_tables)')
    
    parser.add_argument('-w', '--workers',
                       type=int,
                       help='Number of worker processes (default: CPU count)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.min_length < 1:
        parser.error("Minimum length must be at least 1")
    if args.max_length < args.min_length:
        parser.error("Maximum length must be >= minimum length")
    if not args.charset:
        parser.error("Charset cannot be empty")
    
    # Create generator and run
    generator = RainbowTableGenerator(
        charset=args.charset,
        salt=args.salt,
        algorithm=args.algorithm,
        output_dir=args.output_dir
    )
    
    summary = generator.generate(
        min_length=args.min_length,
        max_length=args.max_length,
        max_workers=args.workers
    )
    
    # Save summary report
    report_file = Path(args.output_dir) / 'generation_summary.txt'
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("Rainbow Table Generation Summary\n")
        f.write("=" * 60 + "\n\n")
        for key, value in summary.items():
            if key != 'files':
                f.write(f"{key}: {value}\n")
        f.write("\nGenerated Files:\n")
        for file_info in summary['files']:
            f.write(f"  Length {file_info['length']}: {file_info['count']:,} passwords "
                   f"-> {file_info['file']}\n")
    
    print(f"\nSummary report saved to: {report_file}")


if __name__ == '__main__':
    main()
