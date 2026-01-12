# FlameMaster Pro — Multi-Platform Dynamic Analysis Tool

![FlameMaster Pro](https://img.shields.io/badge/FlameMaster-Pro-red)
![Python](https://img.shields.io/badge/Python-3.7%252B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📋 Overview

**FlameMaster Pro** is an advanced cybersecurity tool designed for comprehensive analysis of multiple file types, including APKs, IPAs, Windows executables, documents, network captures, and more.  
It integrates both **static** and **dynamic analysis** techniques to extract deep intelligence from malware samples and suspicious files.

---

## ✨ Features

### 🔍 Multi-Platform Analysis

- **Android APK Analysis**
  - Decompilation
  - AndroidManifest parsing
  - DEX and string extraction

- **iOS IPA Analysis**
  - Binary inspection
  - Info.plist parsing
  - Hex dumps

- **Windows / Linux Executables**
  - PE / ELF analysis
  - Imports / exports
  - Static strings

- **Document Analysis**
  - PDF, DOCX, XLSX metadata
  - Text extraction
  - Hidden content detection

- **Network Analysis**
  - PCAP parsing
  - Protocol distribution
  - HTTP extraction

- **PowerShell Analysis**
  - Suspicious command patterns
  - Obfuscation detection

- **E-Mail Analysis**
  - Header inspection
  - Attachment handling

- **Archive Analysis**
  - ZIP / RAR / 7Z / TAR extraction
  - Recursive nested analysis

---

## 🛡️ Security Analysis Capabilities

### Pattern Detection
- 200+ predefined security and malware patterns

### Advanced Injection Detection
- UEFI / Firmware injection
- Hardware-based injection
- Memory-based injection
- Module-based injection
- Process injection variants

### Malware Indicators
- Root & emulator detection
- Anti-debugging techniques
- Obfuscation patterns
- Persistence mechanisms
- Command & Control (C2)

---

## 📊 Output & Reporting

- Rich colorized console output
- Detailed HTML reports
- Timestamped logs
- TXT and HTML outputs
- Automated remediation suggestions

---

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Installation Steps

```bash
# Core dependencies
pip install androguard rich colorama jinja2 scapy pdfminer.six python-docx lief

# Optional features
pip install rarfile py7zr plistlib
````

---

## 🎯 Usage

### Basic Usage

```bash
python FlameMaster_pro.py <file_path>
```

### Examples

```bash
# Android APK
python FlameMaster_pro.py sample.apk

# Windows EXE
python FlameMaster_pro.py malware.exe

# Custom pattern scan
python FlameMaster_pro.py suspicious.apk \
  --custom "C2Server:http://[^\\s]+" \
  --custom "Mutex:[A-Za-z0-9_]+"

# Network traffic
python FlameMaster_pro.py traffic.pcap

# Document analysis
python FlameMaster_pro.py document.pdf

# Debug mode
python FlameMaster_pro.py sample.ipa --debug
```

### Command Line Arguments

```text
positional arguments:
  file                    Path to file for analysis

optional arguments:
  --custom PATTERN         Custom pattern (Name:Regex)
  --debug                  Enable verbose debug output
  --no-report              Skip HTML report generation
  -h, --help               Show help message
```

---

## 📁 Supported File Types

| File Type | Extensions                    | Capabilities               |
| --------- | ----------------------------- | -------------------------- |
| Android   | `.apk`                        | Manifest, DEX, permissions |
| iOS       | `.ipa`                        | Binary, Info.plist         |
| Windows   | `.exe`, `.dll`, `.msi`        | PE analysis                |
| Linux     | `.elf`, `.so`                 | ELF analysis               |
| macOS     | `.dylib`, `.app`              | Mach-O analysis            |
| Documents | `.pdf`, `.docx`, `.xlsx`      | Metadata & text            |
| Archives  | `.zip`, `.rar`, `.7z`, `.tar` | Recursive extraction       |
| Network   | `.pcap`, `.pcapng`            | Protocol analysis          |
| Scripts   | `.ps1`                        | Suspicious patterns        |
| E-Mail    | `.eml`, `.msg`                | Header & attachments       |
| Golang    | `.go`                         | Go-specific patterns       |

---

## 🔧 Analysis Modules

### Android APK

* AndroidManifest parsing
* DEX decompilation
* Permission mapping
* Component extraction
* String & pattern scanning

### Binary Analysis (PE / ELF / Mach-O)

* Headers & sections
* Imports / exports
* Static strings
* Obfuscation detection

### Document Analysis

* Text extraction
* Metadata inspection
* Hidden content detection
* Malware pattern matching

### Network Analysis

* Packet statistics
* Protocol breakdown
* HTTP extraction
* Suspicious traffic detection

### Advanced Security

* UEFI / BIOS injection detection
* I2C / SPI / UART / GPIO patterns
* Process hollowing
* Reflective DLL injection
* Code caves & NOP sled detection

---

## 🛠️ Pattern Detection Categories

### 🔐 Authentication & Secrets

* Hardcoded credentials
* API keys & tokens
* Encryption keys

### 🌐 Network & Communication

* URLs & endpoints
* IPs & ports
* C2 indicators
* DNS / HTTP / FTP

### 📱 Mobile-Specific

* Device identifiers
* Location tracking
* SMS & call access
* Camera & microphone
* Root / emulator detection

### 🛡️ Security Evasion

* Anti-debugging
* Sandbox evasion
* VM detection
* Persistence

### 💾 System Interaction

* File system access
* Windows registry
* Process injection
* Services & scheduled tasks

### 🔬 Advanced Malware

* Firmware tampering
* Hardware attacks
* Memory corruption
* Fileless malware

---

## 📊 Output Structure

```text
<filename>_analysis_YYYYMMDD_HHMMSS/
├── logs/
│   └── FlameMaster_pro_YYYYMMDD_HHMMSS.log
├── unzipped/
├── classes.dex.out/
├── extracted/
├── AndroidManifest.xml
├── manifest_analysis.txt
├── strings.txt
├── endpoints_urls.txt
├── sql_information.txt
├── hidden_domains.txt
├── user_credentials.txt
├── ip_ports.txt
├── api_information.txt
├── folder_paths.txt
├── advanced_static_analysis.txt
├── injection_reports/
└── FlameMaster_pro_comprehensive_report.html
```

---

## 🎨 Rich Interface

* Color-coded console output
* Progress bars
* Tabular summaries
* Banner display

---

## ⚙️ Configuration

### Custom Patterns

```bash
--custom "MyPattern:regex_here"
--custom "Email:\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
```

### Extending Built-in Patterns

Modify the `PATTERNS` dictionary in `FlameMaster_pro.py`.

---

## 🔍 Example Output

```text
[>] Starting analysis: malicious.apk
[+] Unpacked APK
[+] AndroidManifest parsed
[+] Decompiled DEX files
[>] Searching patterns...
[+] 15 suspicious indicators found
[+] HTML report generated
```

---

## 🛡️ Security Considerations

### Warning

This tool may extract:

* API keys
* Credentials
* IP addresses
* PII data

Handle all outputs securely.

### Best Practices

* Use isolated VMs
* Avoid live systems
* Protect output directories
* Follow responsible disclosure

---

## 📈 Performance Notes

* Memory: Moderate to high
* Speed: Depends on file size
* Storage: Temporary extraction folders
* Network: No external calls by default

---

## 🐛 Troubleshooting

### Missing Dependencies

```bash
pip install -r requirements.txt
```

### Permission Issues

```text
Run with proper file access permissions
```

### Large Files

```text
Files >10MB may require more memory
```

### Debug Mode

```bash
python FlameMaster_pro.py file.apk --debug
```

---

## 🤝 Contributing

Pull Requests are welcome.

### Contribution Areas

* New file formats
* Pattern expansion
* Performance tuning
* Reporting improvements
* Bug fixes

---

## 📄 License

MIT License — see `LICENSE` file.

---

## 👤 Author

**Haroon Awan**
Cybersecurity Researcher & Tool Developer

---

## 🙏 Acknowledgments

* Androguard
* LIEF Project
* Rich Library
* Open-source security community

---

## ⚠️ Disclaimer

This tool is intended **only** for educational and authorized security testing.
The author is **not responsible** for misuse or damage caused by this software.
Always obtain proper authorization before analysis.


```
