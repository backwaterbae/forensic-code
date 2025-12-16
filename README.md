# Forensic Code

A collection of digital forensic tools and scripts for analysis, investigation, and evidence processing.

## Overview

This repository contains various forensic utilities organized into specialized branches, each focusing on different aspects of digital forensics. Whether you're analyzing communications, parsing logs, or performing basic file operations, these tools are designed to streamline your forensic workflow.

## Repository Structure

This repository uses a branch-based organization system. Each branch contains tools specific to a particular forensic discipline:

### 🔍 Branches

#### **comms-analysis**
Tools for analyzing communications and digital artifacts:
- **Email Header Parsers** - Extract and analyze metadata from email headers to trace message origins and routing
- **Screenshot Readers** - Process and extract metadata from screenshot images

#### **lulu-logs**
Intelligent log analysis utilities:
- **Multi-Format Log Parser** - Adaptively parses various log formats with intelligent detection
- **Complimentary Scripts** - Specialized scripts for unique log analysis scenarios and edge cases

#### **the-basics**
Fundamental forensic utilities:
- **Batch File Hasher** - Generate cryptographic hashes for multiple files to verify integrity and create evidence documentation

## Getting Started

### Prerequisites
- Python 3.x
- Basic understanding of digital forensic principles

### Usage

1. Clone the repository:
```bash
git clone https://github.com/backwaterbae/forensic-code.git
cd forensic-code
```

2. Switch to the branch containing the tools you need:
```bash
git checkout comms-analysis    # For communication analysis tools
git checkout lulu-logs         # For log parsing tools
git checkout the-basics        # For basic forensic utilities
```

3. Refer to the specific documentation in each branch for detailed usage instructions.

## Contributing

Contributions are welcome! If you have forensic tools or improvements to existing scripts, please feel free to submit a pull request.

## Disclaimer

These tools are intended for legitimate forensic investigation, security research, and educational purposes only. Always ensure you have proper authorization before analyzing any systems or data.

## License

Please review the LICENSE file for terms of use.

## Contact

For questions or suggestions, please open an issue on GitHub.

---

*Developed for the digital forensics community*
