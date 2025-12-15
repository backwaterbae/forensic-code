
#!/usr/bin/env python3
"""
Rainbow Table Search Tool
Search for password hashes in generated rainbow tables
"""

import argparse
import logging
from pathlib import Path
from typing import List, Optional, Dict
import time


class RainbowTableSearcher:
    """Search rainbow tables for hash matches"""
    
    def __init__(self, table_directory: str = 'rainbow_tables'):
        """
        Initialize rainbow table searcher
        
        Args:
            table_directory: Directory containing rainbow table files
        """
        self.table_dir = Path(table_directory)
        
        if not self.table_dir.exists():
            raise FileNotFoundError(f"Rainbow table directory not found: {table_directory}")
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Discover available tables
        self.tables = self._discover_tables()
    
    def _discover_tables(self) -> List[Path]:
        """
        Discover all rainbow table files in the directory
        
        Returns:
            List of Path objects for rainbow table files
        """
        tables = list(self.table_dir.glob('rainbow_*.txt'))
        
        if not tables:
            self.logger.warning(f"No rainbow tables found in {self.table_dir}")
        else:
            self.logger.info(f"Found {len(tables)} rainbow table(s):")
            for table in sorted(tables):
                self.logger.info(f"  - {table.name}")
        
        return sorted(tables)
    
    def _search_file(self, hash_value: str, table_file: Path) -> Optional[str]:
        """
        Search a single rainbow table file for a hash
        
        Args:
            hash_value: Hash to search for
            table_file: Path to rainbow table file
            
        Returns:
            Password if found, None otherwise
        """
        hash_lower = hash_value.lower()
        
        try:
            with open(table_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        file_hash, password = line.split(':', 1)
                        if file_hash.lower() == hash_lower:
                            return password
        except Exception as e:
            self.logger.error(f"Error searching {table_file.name}: {e}")
        
        return None
    
    def search(self, hash_value: str, algorithm: Optional[str] = None, 
               length: Optional[int] = None) -> Dict:
        """
        Search for a hash in rainbow tables
        
        Args:
            hash_value: Hash to search for
            algorithm: Specific algorithm to search (optional, filters tables)
            length: Specific password length to search (optional, filters tables)
            
        Returns:
            Dictionary with search results
        """
        start_time = time.time()
        
        # Filter tables based on criteria
        search_tables = self.tables
        
        if algorithm:
            search_tables = [t for t in search_tables if algorithm in t.name]
            
        if length is not None:
            search_tables = [t for t in search_tables if f'len{length}' in t.name]
        
        if not search_tables:
            return {
                'found': False,
                'hash': hash_value,
                'password': None,
                'table': None,
                'elapsed_time': time.time() - start_time,
                'tables_searched': 0
            }
        
        self.logger.info(f"Searching for hash: {hash_value}")
        self.logger.info(f"Tables to search: {len(search_tables)}")
        
        # Search each table
        for table in search_tables:
            self.logger.info(f"Searching {table.name}...")
            password = self._search_file(hash_value, table)
            
            if password:
                elapsed_time = time.time() - start_time
                self.logger.info(f"✓ FOUND! Password: {password}")
                self.logger.info(f"Search completed in {elapsed_time:.4f} seconds")
                
                return {
                    'found': True,
                    'hash': hash_value,
                    'password': password,
                    'table': str(table),
                    'elapsed_time': elapsed_time,
                    'tables_searched': search_tables.index(table) + 1
                }
        
        elapsed_time = time.time() - start_time
        self.logger.warning(f"✗ Hash not found in any table")
        self.logger.info(f"Search completed in {elapsed_time:.4f} seconds")
        
        return {
            'found': False,
            'hash': hash_value,
            'password': None,
            'table': None,
            'elapsed_time': elapsed_time,
            'tables_searched': len(search_tables)
        }
    
    def batch_search(self, hash_file: str, algorithm: Optional[str] = None) -> List[Dict]:
        """
        Search for multiple hashes from a file
        
        Args:
            hash_file: Path to file containing hashes (one per line)
            algorithm: Specific algorithm to search (optional)
            
        Returns:
            List of search result dictionaries
        """
        hash_path = Path(hash_file)
        
        if not hash_path.exists():
            raise FileNotFoundError(f"Hash file not found: {hash_file}")
        
        # Read hashes
        with open(hash_path, 'r', encoding='utf-8') as f:
            hashes = [line.strip() for line in f if line.strip()]
        
        self.logger.info(f"Batch searching {len(hashes)} hash(es)")
        
        results = []
        found_count = 0
        
        for i, hash_value in enumerate(hashes, 1):
            self.logger.info(f"\n[{i}/{len(hashes)}] Processing: {hash_value}")
            result = self.search(hash_value, algorithm=algorithm)
            results.append(result)
            
            if result['found']:
                found_count += 1
        
        # Summary
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"Batch Search Complete")
        self.logger.info(f"Total hashes: {len(hashes)}")
        self.logger.info(f"Found: {found_count}")
        self.logger.info(f"Not found: {len(hashes) - found_count}")
        self.logger.info(f"{'='*60}\n")
        
        return results
    
    def create_index(self, algorithm: str, output_file: str = None):
        """
        Create an indexed/sorted version of rainbow tables for faster searching
        (Future enhancement - currently just a placeholder)
        
        Args:
            algorithm: Algorithm to index
            output_file: Output file for index
        """
        self.logger.info("Index creation not yet implemented")
        self.logger.info("Current implementation uses linear search")


def main():
    """Main function with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Rainbow Table Hash Search Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Search for a single hash
  python rainbow_search.py -hash 5d41402abc4b2a76b9719d911017c592
  
  # Search with algorithm filter
  python rainbow_search.py -hash abc123... -a sha256
  
  # Search with length filter
  python rainbow_search.py -hash abc123... -l 5
  
  # Batch search from file
  python rainbow_search.py -f hashes.txt -a md5
        """
    )
    
    parser.add_argument('-d', '--directory',
                       default='rainbow_tables',
                       help='Rainbow table directory (default: rainbow_tables)')
    
    # Single hash or batch mode
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-hash', '--hash',
                      help='Single hash to search for')
    group.add_argument('-f', '--file',
                      help='File containing hashes (one per line)')
    
    parser.add_argument('-a', '--algorithm',
                       choices=['md5', 'sha1', 'sha256', 'sha512'],
                       help='Filter by hash algorithm')
    
    parser.add_argument('-l', '--length',
                       type=int,
                       help='Filter by password length')
    
    parser.add_argument('-o', '--output',
                       help='Save results to file')
    
    args = parser.parse_args()
    
    # Create searcher
    try:
        searcher = RainbowTableSearcher(table_directory=args.directory)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return 1
    
    # Perform search
    if args.hash:
        # Single hash search
        result = searcher.search(
            hash_value=args.hash,
            algorithm=args.algorithm,
            length=args.length
        )
        
        # Save result if output specified
        if args.output:
            output_path = Path(args.output)
            with open(output_path, 'w', encoding='utf-8') as f:
                if result['found']:
                    f.write(f"{result['hash']}:{result['password']}\n")
                else:
                    f.write(f"{result['hash']}:NOT_FOUND\n")
            print(f"\nResult saved to: {output_path}")
    
    else:
        # Batch search
        results = searcher.batch_search(
            hash_file=args.file,
            algorithm=args.algorithm
        )
        
        # Save results if output specified
        if args.output:
            output_path = Path(args.output)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("hash:password:found:elapsed_time\n")
                for result in results:
                    password = result['password'] if result['found'] else 'NOT_FOUND'
                    f.write(f"{result['hash']}:{password}:{result['found']}:"
                           f"{result['elapsed_time']:.4f}\n")
            print(f"\nResults saved to: {output_path}")
    
    return 0


if __name__ == '__main__':
    exit(main())
