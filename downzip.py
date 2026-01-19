#!/usr/bin/env python3
"""
URL-to-ZIP Downloader
Downloads files from URLs directly into password-protected ZIP archives
WITHOUT writing original files to disk (safer for malware/suspicious files)

Usage:
  python3 download_to_zip.py <url> [options]
  python3 download_to_zip.py https://example.com/suspicious.jpg --output samples.zip
  python3 download_to_zip.py https://example.com/malware.exe --password infected
  python3 download_to_zip.py --urls urls.txt --output evidence.zip

Security Features:
  • Original file NEVER touches disk
  • Downloads to memory only
  • Writes directly to password-protected ZIP
  • Safe handling of potentially malicious content

Author: Backwater Forensics
Created: January 2026
"""

import sys
import os
import argparse
import urllib.request
import urllib.parse
import urllib.error
from io import BytesIO
import zipfile
from datetime import datetime
import hashlib
import json


class SecureURLDownloader:
    """Download files from URLs directly to ZIP without disk writes"""
    
    def __init__(self, output_zip, password='infected', overwrite=False):
        """
        Initialize downloader
        
        Args:
            output_zip: Path to output ZIP file
            password: Password for ZIP encryption (default: 'infected')
            overwrite: Whether to overwrite existing ZIP
        """
        self.output_zip = output_zip
        self.password = password.encode() if password else None
        self.overwrite = overwrite
        
        # Check if ZIP exists
        if os.path.exists(output_zip) and not overwrite:
            raise FileExistsError(
                f"ZIP file already exists: {output_zip}\n"
                f"Use --overwrite to replace it, or choose a different name"
            )
        
        # Metadata for tracking
        self.downloads = []
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def download_url(self, url, filename=None, timeout=30):
        """
        Download file from URL to memory
        
        Args:
            url: URL to download from
            filename: Optional custom filename (auto-generated if None)
            timeout: Download timeout in seconds
            
        Returns:
            tuple: (file_data_bytes, filename, metadata)
        """
        print(f"\n[*] Downloading from: {url}")
        
        try:
            # Set user agent to avoid blocking
            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
            }
            
            req = urllib.request.Request(url, headers=headers)
            
            # Download to memory
            with urllib.request.urlopen(req, timeout=timeout) as response:
                file_data = response.read()
                
                # Get filename from URL if not provided
                if not filename:
                    # Try Content-Disposition header first
                    content_disposition = response.headers.get('Content-Disposition')
                    if content_disposition and 'filename=' in content_disposition:
                        filename = content_disposition.split('filename=')[1].strip('"\'')
                    else:
                        # Extract from URL
                        parsed_url = urllib.parse.urlparse(url)
                        filename = os.path.basename(parsed_url.path)
                        
                        # If no filename in URL, generate one
                        if not filename or filename == '/':
                            ext = self._guess_extension(response.headers.get('Content-Type', ''))
                            filename = f"download_{self.session_id}{ext}"
                
                # Get metadata
                metadata = {
                    'url': url,
                    'filename': filename,
                    'size': len(file_data),
                    'size_mb': round(len(file_data) / 1024 / 1024, 2),
                    'content_type': response.headers.get('Content-Type', 'unknown'),
                    'download_time': datetime.now().isoformat(),
                    'md5': hashlib.md5(file_data).hexdigest(),
                    'sha256': hashlib.sha256(file_data).hexdigest(),
                }
                
                print(f"    Filename: {filename}")
                print(f"    Size: {metadata['size']:,} bytes ({metadata['size_mb']} MB)")
                print(f"    Content-Type: {metadata['content_type']}")
                print(f"    MD5: {metadata['md5']}")
                print(f"    SHA256: {metadata['sha256']}")
                
                return file_data, filename, metadata
                
        except urllib.error.HTTPError as e:
            raise Exception(f"HTTP Error {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            raise Exception(f"URL Error: {e.reason}")
        except Exception as e:
            raise Exception(f"Download failed: {e}")
    
    def _guess_extension(self, content_type):
        """Guess file extension from Content-Type header"""
        ext_map = {
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
            'image/webp': '.webp',
            'image/bmp': '.bmp',
            'application/pdf': '.pdf',
            'application/zip': '.zip',
            'application/x-executable': '.exe',
            'text/html': '.html',
            'text/plain': '.txt',
        }
        
        return ext_map.get(content_type, '.bin')
    
    def add_to_zip(self, file_data, filename):
        """
        Add file to ZIP archive (memory to disk only)
        
        Args:
            file_data: Bytes of file content
            filename: Name to use in ZIP
        """
        print(f"    Adding to ZIP: {filename}")
        
        # Open or create ZIP
        mode = 'a' if os.path.exists(self.output_zip) else 'w'
        
        with zipfile.ZipFile(self.output_zip, mode, zipfile.ZIP_DEFLATED) as zf:
            # Add file with password protection
            if self.password:
                zf.setpassword(self.password)
                # Write with encryption
                zf.writestr(
                    filename,
                    file_data,
                    compress_type=zipfile.ZIP_DEFLATED
                )
            else:
                # Write without encryption
                zf.writestr(filename, file_data)
        
        print(f"    ✓ Added to {self.output_zip}")
    
    def download_and_zip(self, url, filename=None):
        """
        Complete workflow: download from URL and add to ZIP
        
        Args:
            url: URL to download
            filename: Optional custom filename
            
        Returns:
            dict: Download metadata
        """
        try:
            # Download to memory
            file_data, resolved_filename, metadata = self.download_url(url, filename)
            
            # Add to ZIP (never write original to disk)
            self.add_to_zip(file_data, resolved_filename)
            
            metadata['status'] = 'success'
            metadata['zip_file'] = self.output_zip
            
            self.downloads.append(metadata)
            
            return metadata
            
        except Exception as e:
            error_metadata = {
                'url': url,
                'filename': filename or 'unknown',
                'status': 'failed',
                'error': str(e),
                'download_time': datetime.now().isoformat()
            }
            
            self.downloads.append(error_metadata)
            
            print(f"    ✗ Error: {e}")
            
            return error_metadata
    
    def save_metadata(self, metadata_file=None):
        """Save download metadata to JSON file"""
        if metadata_file is None:
            base_name = os.path.splitext(self.output_zip)[0]
            metadata_file = f"{base_name}_metadata.json"
        
        metadata = {
            'session_id': self.session_id,
            'output_zip': self.output_zip,
            'password_protected': self.password is not None,
            'total_downloads': len(self.downloads),
            'successful': len([d for d in self.downloads if d['status'] == 'success']),
            'failed': len([d for d in self.downloads if d['status'] == 'failed']),
            'downloads': self.downloads
        }
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"\n[+] Metadata saved to: {metadata_file}")
        return metadata_file


def main():
    parser = argparse.ArgumentParser(
        description='Download files from URLs directly to password-protected ZIP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Security Features:
  • Original files NEVER written to disk
  • Downloads kept in memory only
  • Writes directly to encrypted ZIP
  • Safe for malware/suspicious files

Examples:
  # Download single file (default password: infected)
  python3 download_to_zip.py https://example.com/suspicious.jpg
  
  # Explicitly use default password
  python3 download_to_zip.py https://example.com/malware.exe --default-password
  
  # Custom output filename
  python3 download_to_zip.py https://example.com/image.jpg --output samples.zip
  
  # Custom password
  python3 download_to_zip.py https://example.com/malware.exe --password malware123
  
  # No password (not recommended for malware)
  python3 download_to_zip.py https://example.com/safe.jpg --no-password
  
  # Multiple URLs from file
  python3 download_to_zip.py --urls urls.txt --output evidence.zip
  
  # Custom filename in ZIP
  python3 download_to_zip.py https://example.com/file.jpg --filename custom_name.jpg

Default Settings:
  • Output: downloads_<timestamp>.zip
  • Password: infected (industry standard) [use --default-password or omit password option]
  • Overwrite: No (safety feature)
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('url', nargs='?', help='URL to download')
    input_group.add_argument('--urls', '-u', help='File containing URLs (one per line)')
    
    # Output options
    parser.add_argument('--output', '-o',
                       help='Output ZIP filename (default: downloads_<timestamp>.zip)')
    parser.add_argument('--filename', '-f',
                       help='Custom filename for file in ZIP (single URL only)')
    
    # Security options (mutually exclusive)
    password_group = parser.add_mutually_exclusive_group()
    password_group.add_argument('--password', '-p',
                       help='Custom ZIP password')
    password_group.add_argument('--default-password', '-d',
                       action='store_true',
                       help='Use default password: infected (industry standard)')
    password_group.add_argument('--no-password',
                       action='store_true',
                       help='Do not password-protect ZIP (NOT recommended for malware)')
    
    # Other options
    parser.add_argument('--overwrite',
                       action='store_true',
                       help='Overwrite existing ZIP file')
    parser.add_argument('--timeout', '-t',
                       type=int,
                       default=30,
                       help='Download timeout in seconds (default: 30)')
    parser.add_argument('--metadata',
                       help='Custom metadata file path (default: <zip_name>_metadata.json)')
    
    args = parser.parse_args()
    
    # Set output filename
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"downloads_{timestamp}.zip"
    
    # Determine password
    if args.no_password:
        password = None
    elif args.default_password:
        password = 'infected'
    elif args.password:
        password = args.password
    else:
        # Default to infected if no password options specified
        password = 'infected'
    
    if args.no_password:
        print("\n⚠️  WARNING: ZIP will NOT be password-protected!")
        print("    This is NOT recommended for malware or suspicious files.")
        response = input("    Continue without password? (y/n): ")
        if response.lower() != 'y':
            print("Cancelled")
            return 0
    
    print("="*80)
    print("SECURE URL-TO-ZIP DOWNLOADER")
    print("="*80)
    print(f"Output ZIP: {args.output}")
    print(f"Password: {password if password else 'NONE (not protected)'}")
    print(f"Security: Original files NEVER written to disk")
    print("="*80)
    
    try:
        # Initialize downloader
        downloader = SecureURLDownloader(
            output_zip=args.output,
            password=password,
            overwrite=args.overwrite
        )
        
        # Get URLs to download
        urls = []
        if args.url:
            urls = [args.url]
        elif args.urls:
            if not os.path.exists(args.urls):
                print(f"Error: URL file not found: {args.urls}")
                return 1
            
            with open(args.urls, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if not urls:
            print("Error: No URLs to download")
            return 1
        
        print(f"\n[*] URLs to download: {len(urls)}")
        
        # Download and zip each URL
        for idx, url in enumerate(urls, 1):
            print(f"\n{'='*80}")
            print(f"[{idx}/{len(urls)}] Processing URL")
            print(f"{'='*80}")
            
            # Use custom filename only for single URL
            filename = args.filename if len(urls) == 1 else None
            
            downloader.download_and_zip(url, filename)
        
        # Save metadata
        metadata_file = downloader.save_metadata(args.metadata)
        
        # Print summary
        print("\n" + "="*80)
        print("DOWNLOAD SUMMARY")
        print("="*80)
        print(f"Total URLs: {len(urls)}")
        print(f"Successful: {len([d for d in downloader.downloads if d['status'] == 'success'])}")
        print(f"Failed: {len([d for d in downloader.downloads if d['status'] == 'failed'])}")
        print(f"\nOutput ZIP: {args.output}")
        print(f"Metadata: {metadata_file}")
        
        if password:
            print(f"Password: {password}")
            print("\n⚠️  IMPORTANT: Keep password secure for evidence access")
        
        print("\nTo analyze files in ZIP:")
        if password:
            print(f"  python3 analyze_from_zip.py {args.output} --password {password} --list")
        else:
            print(f"  python3 analyze_from_zip.py {args.output} --list")
        
        print("="*80)
        
        return 0 if all(d['status'] == 'success' for d in downloader.downloads) else 1
        
    except Exception as e:
        print(f"\n[!] Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
