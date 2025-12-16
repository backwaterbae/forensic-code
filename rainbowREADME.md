# forensic-code

# Rainbow Table Tools - Modern Python 3 Suite

Complete rainbow table generation and search toolkit for digital forensics and password analysis.

## 🎯 What's New in This Version

### Major Improvements from Original Code
- ✅ **Python 3 Compatible** - Full rewrite for Python 3.6+
- ✅ **Multiple Hash Algorithms** - MD5, SHA-1, SHA-256, SHA-512
- ✅ **Modern Multiprocessing** - Uses `concurrent.futures` instead of deprecated Pool
- ✅ **Progress Tracking** - Real-time progress bars with `tqdm`
- ✅ **Proper Error Handling** - Specific exceptions, logging, and recovery
- ✅ **Command-line Interface** - Full argparse implementation
- ✅ **Companion Search Tool** - Fast hash lookup utility
- ✅ **Better Performance** - Optimized I/O and encoding
- ✅ **Professional Logging** - Timestamped logs and summary reports

## 📋 Requirements

```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install tqdm
```

## 🚀 Quick Start

### 1. Generate Rainbow Tables

**Basic usage (default: a-h charset, SHA-256, length 4-8):**
```bash
python rainbow_generator.py -min 4 -max 8
```

**Custom charset (numbers only):**
```bash
python rainbow_generator.py -c "0123456789" -min 4 -max 6
```

**Use MD5 (for compatibility with legacy systems):**
```bash
python rainbow_generator.py -a md5 -min 4 -max 6
```

**Add salt:**
```bash
python rainbow_generator.py -s "MySalt123" -min 3 -max 5
```

**Full example:**
```bash
python rainbow_generator.py \
    -c "abcdefghijklmnopqrstuvwxyz" \
    -min 4 \
    -max 6 \
    -a sha256 \
    -s "ForensicSalt2024" \
    -o my_tables \
    -w 8
```

### 2. Search Rainbow Tables

**Search for a single hash:**
```bash
python rainbow_search.py -hash 5d41402abc4b2a76b9719d911017c592
```

**Search with algorithm filter:**
```bash
python rainbow_search.py -hash abc123def456... -a sha256
```

**Search with length filter (faster):**
```bash
python rainbow_search.py -hash abc123def456... -l 5
```

**Batch search from file:**
```bash
# Create hashes.txt with one hash per line
python rainbow_search.py -f hashes.txt -o results.txt
```

## 📖 Detailed Usage

### Rainbow Generator Options

```
usage: rainbow_generator.py [-h] [-c CHARSET] [-min MIN_LENGTH] [-max MAX_LENGTH]
                            [-s SALT] [-a {md5,sha1,sha256,sha512}]
                            [-o OUTPUT_DIR] [-w WORKERS]

Arguments:
  -c, --charset       Characters to use (default: abcdefgh)
  -min, --min-length  Minimum password length (default: 4)
  -max, --max-length  Maximum password length (default: 8)
  -s, --salt          Salt to prepend (default: none)
  -a, --algorithm     Hash algorithm (default: sha256)
  -o, --output-dir    Output directory (default: rainbow_tables)
  -w, --workers       Number of processes (default: CPU count)
```

### Rainbow Search Options

```
usage: rainbow_search.py [-h] [-d DIRECTORY] (-hash HASH | -f FILE)
                        [-a {md5,sha1,sha256,sha512}] [-l LENGTH] [-o OUTPUT]

Arguments:
  -d, --directory  Rainbow table directory (default: rainbow_tables)
  -hash, --hash    Single hash to search
  -f, --file       File with hashes (one per line)
  -a, --algorithm  Filter by algorithm
  -l, --length     Filter by password length
  -o, --output     Save results to file
```

## 🔍 Understanding Rainbow Tables

### What They Are
Rainbow tables are precomputed hash-to-password lookup tables used in password cracking. They trade computational time for storage space.

### When to Use Different Hash Algorithms

- **MD5**: Fast, legacy systems, known to be broken for security
- **SHA-1**: Slightly more secure than MD5, still deprecated
- **SHA-256**: Modern standard, good balance
- **SHA-512**: Most secure, larger output

### Performance Considerations

**Charset Size Impact:**
- Lowercase letters (26 chars): 26^length combinations
- Lowercase + digits (36 chars): 36^length combinations  
- Full alphanumeric (62 chars): 62^length combinations

**Example: 5-character passwords**
- 26 chars: 11,881,376 combinations
- 36 chars: 60,466,176 combinations
- 62 chars: 916,132,832 combinations

**Storage Estimates (SHA-256):**
- Length 4: ~2.5 MB per file
- Length 5: ~65 MB per file
- Length 6: ~1.7 GB per file
- Length 7: ~44 GB per file
- Length 8: ~1.1 TB per file

## 💡 Practical Examples

### Example 1: Common PIN Analysis
```bash
# Generate table for 4-digit PINs
python rainbow_generator.py -c "0123456789" -min 4 -max 4 -a md5

# Search for PIN hash
python rainbow_search.py -hash 5f4dcc3b5aa765d61d8327deb882cf99 -a md5 -l 4
```

### Example 2: Weak Password Database
```bash
# Common weak passwords (lowercase only, short)
python rainbow_generator.py -c "abcdefghijklmnopqrstuvwxyz" -min 4 -max 7 -a sha256

# Search multiple hashes
echo "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92" > hashes.txt
echo "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" >> hashes.txt
python rainbow_search.py -f hashes.txt -a sha256 -o cracked.txt
```

### Example 3: Forensic Investigation
```bash
# Generate tables matching evidence parameters
python rainbow_generator.py \
    -c "0123456789abcdef" \
    -min 6 \
    -max 8 \
    -a sha1 \
    -s "CompanyName2024" \
    -o case_123_tables

# Search extracted hashes
python rainbow_search.py -d case_123_tables -f evidence_hashes.txt -o findings.csv
```

## 🛠️ Advanced Features

### Using as a Library

```python
from rainbow_generator import RainbowTableGenerator
from rainbow_search import RainbowTableSearcher

# Generate tables programmatically
generator = RainbowTableGenerator(
    charset='abc123',
    salt='MySalt',
    algorithm='sha256',
    output_dir='my_tables'
)

summary = generator.generate(min_length=4, max_length=6, max_workers=4)
print(f"Generated {summary['total_passwords']} passwords")

# Search programmatically
searcher = RainbowTableSearcher(table_directory='my_tables')
result = searcher.search('abc123def456...')

if result['found']:
    print(f"Password found: {result['password']}")
```

### Batch Processing Script

```python
#!/usr/bin/env python3
"""Batch process multiple hash files"""

from rainbow_search import RainbowTableSearcher
import sys

searcher = RainbowTableSearcher('rainbow_tables')

for hash_file in sys.argv[1:]:
    print(f"\nProcessing: {hash_file}")
    results = searcher.batch_search(hash_file)
    
    found = sum(1 for r in results if r['found'])
    print(f"Found {found}/{len(results)} passwords")
```

## ⚠️ Legal and Ethical Considerations

**IMPORTANT**: Rainbow tables are powerful forensic tools. Use responsibly:

- ✅ **Legal uses**: Digital forensics investigations, authorized penetration testing, academic research
- ✅ **Ethical uses**: Password strength analysis, security auditing with permission
- ❌ **Illegal uses**: Unauthorized access, cracking others' passwords without consent

**Always ensure you have proper authorization before using these tools in any investigation or security assessment.**

## 🔐 Security Notes

1. **MD5 is broken** - Only use for legacy compatibility
2. **Salts matter** - Rainbow tables are specific to their salt values
3. **Modern defenses** - bcrypt, scrypt, and Argon2 are designed to resist rainbow tables
4. **Storage security** - Protect your rainbow tables; they're valuable attack resources

## 📊 Performance Tips

1. **Start small** - Test with short lengths first
2. **Use SSD storage** - I/O speed matters for large tables
3. **Optimize workers** - Usually CPU count or CPU count - 1
4. **Filter searches** - Use algorithm and length filters when possible
5. **Consider memory** - Very large charsets may require significant RAM

## 🐛 Troubleshooting

**Issue: "No rainbow tables found"**
```bash
# Make sure tables exist
ls -la rainbow_tables/

# Generate tables first
python rainbow_generator.py -min 4 -max 4
```

**Issue: "Too slow"**
```bash
# Reduce charset size or password length
# Use fewer workers if memory-constrained
python rainbow_generator.py -c "abc" -min 3 -max 4 -w 2
```

**Issue: "Out of disk space"**
```bash
# Calculate space needed before generating
# Use smaller charset or shorter passwords
# Consider splitting into multiple runs
```

## 📝 File Formats

**Rainbow Table Files:**
```
hash:password
5d41402abc4b2a76b9719d911017c592:hello
098f6bcd4621d373cade4e832627b4f6:test
```

**Batch Search Input:**
```
5d41402abc4b2a76b9719d911017c592
098f6bcd4621d373cade4e832627b4f6
ad0234829205b9033196ba818f7a872b
```

**Batch Search Output:**
```
hash:password:found:elapsed_time
5d41402abc4b2a76b9719d911017c592:hello:True:0.1234
098f6bcd4621d373cade4e832627b4f6:test:True:0.2345
ad0234829205b9033196ba818f7a872b:NOT_FOUND:False:0.3456
```

## 🎓 Educational Resources

For understanding the cryptographic and forensic concepts:
- [NIST Hash Functions](https://csrc.nist.gov/projects/hash-functions)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- Digital Forensics and Incident Response (DFIR) best practices

## 📄 License

This is a modernized educational tool for digital forensics training and authorized security research.

## 🤝 Contributing

Suggestions for improvements:
- [ ] Binary search implementation for sorted tables
- [ ] Database backend (SQLite) for faster lookups
- [ ] GPU acceleration support
- [ ] Compressed storage format
- [ ] Web interface for searches

---

**Original Code**: Python 2 multicore rainbow table generator  
**Modernized**: Python 3 with enhanced features and companion tools  
**Purpose**: Digital forensics education and authorized security research
