```
 █████╗ ███╗   ██╗ █████╗ ██╗     ██╗   ██╗███████╗███████╗██████╗ 
██╔══██╗████╗  ██║██╔══██╗██║     ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
███████║██╔██╗ ██║███████║██║      ╚████╔╝   ███╔╝ █████╗  ██████╔╝
██╔══██║██║╚██╗██║██╔══██║██║       ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
██║  ██║██║ ╚████║██║  ██║███████╗   ██║   ███████╗███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
```

A Python tool for the static analysis of suspicious files — inspecting a sample and extracting indicators without ever executing it.

## Legal Disclaimer

**This tool is intended for ethical and authorized security research only.**

Handle real malware samples exclusively in an isolated, controlled environment. The author assumes no responsibility for any misuse or for damage resulting from careless handling of live samples.

## Overview

This tool performs first-pass triage on a file the way an analyst would begin one: it reads the sample statically, identifies its real type from magic bytes, computes cryptographic hashes for threat-intel lookups, and mines the printable strings for embedded indicators of compromise. The file is never run.

## Key Features

- **Static Only**: Inspects the sample without executing it
- **Metadata Extraction**: Name, size, path, extension, modification and access times
- **Magic-Byte Typing**: Identifies the true file type instead of trusting the extension
- **Hashing**: Computes MD5, SHA1 and SHA256 for reputation lookups
- **IOC Extraction**: Pulls URLs, IP addresses, domains and referenced filenames from strings
- **String Dump**: Saves all remaining printable strings to `strings.txt`
- **Zero Dependencies**: Runs on the Python standard library alone

## Requirements

- Python 3.6+
- No external libraries required

## Installation

```bash
git clone https://github.com/nicola-guidi/static-file-analyzer.git
cd static-file-analyzer
```

## Usage

### Basic Syntax

```bash
python3 static_file_analyzer.py -s [SAMPLE PATH]
```

### Command-Line Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `--sample <file>` | `-s` | Path to the file to analyze (required) |

### Complete Usage Example

```bash
python3 static_file_analyzer.py -s /path/to/suspicious.exe
```

The report is printed to the console (metadata, file type, hashes, and extracted IOCs), and the full set of printable strings is written to `strings.txt` in the working directory.

## License

This project is provided for educational and ethical security research purposes only.

## Author

Created by **Nicola Guidi**
