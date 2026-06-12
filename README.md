Here is the complete GitHub-ready `README.md` file:

```markdown
# 🛡️ Sandbox Detection Utility

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-red.svg)](https://www.linux.org)
[![C](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))

A comprehensive C-based sandbox detection utility for malware analysis and anti-analysis research. This tool implements multiple detection techniques to identify virtualized environments, sandboxes, and debuggers commonly used in malware analysis.

## 📋 Table of Contents

- [Features](#-features)
- [Detection Techniques](#-detection-techniques)
- [Supported Environments](#-supported-environments)
- [Installation](#-installation)
- [Usage](#-usage)
- [Examples](#-examples)
- [Detection Thresholds](#-detection-thresholds)
- [Confidence Scoring](#-confidence-scoring)
- [Architecture](#-architecture)
- [Use Cases](#-use-cases)
- [Limitations](#-limitations)
- [Evasion Countermeasures](#-evasion-countermeasures)
- [Legal Notice](#-legal-notice)
- [Contributing](#-contributing)
- [References](#-references)

## 🎯 Features

### Core Capabilities

| Category | Techniques | Confidence Range |
|----------|------------|------------------|
| **Virtualization Detection** | CPUID checks, Hypervisor signatures, Timing attacks | 70-95% |
| **Artifact Analysis** | File system, Registry, Device enumeration | 70-90% |
| **BIOS Validation** | Vendor verification, Product fingerprinting | 75-95% |
| **MAC Inspection** | OUI lookup against 15+ vendors | 70-95% |
| **Hardware Heuristics** | CPU, RAM, Disk, Process analysis | 10-90% |
| **Anti-Debugging** | Ptrace detection | 85% |

### Detection Methods

#### 1. Virtualization Detection
- ✅ CPUID hypervisor bit check (ECX[31])
- ✅ Hypervisor signature detection (VMware, VirtualBox, KVM, Xen, Hyper-V)
- ✅ Red Pill timing attack using SIDT instruction
- ✅ VMware I/O port timing anomaly detection

#### 2. Registry/File Artifact Analysis
- ✅ VMware SCSI device detection
- ✅ VirtualBox Guest Additions presence
- ✅ VMware Tools presence
- ✅ Hyper-V KVP daemon detection
- ✅ Container environment detection (Docker)
- ✅ PCI device enumeration

#### 3. BIOS Validation
- ✅ BIOS vendor verification
- ✅ System vendor fingerprinting
- ✅ Product name inspection
- ✅ Suspicious BIOS date detection

#### 4. MAC Address Inspection
- ✅ OUI (Organizationally Unique Identifier) lookup against known sandbox vendors
- ✅ VMware, VirtualBox, Hyper-V, KVM, QEMU, Docker OUI detection

#### 5. Hardware Heuristics
- ✅ CPU core count analysis
- ✅ RAM size evaluation (<1GB suspicious)
- ✅ Disk size analysis (<40GB suspicious)
- ✅ System uptime monitoring
- ✅ Process count analysis
- ✅ Hostname pattern matching

#### 6. Additional Anti-Analysis
- ✅ Ptrace debugger detection
- ✅ System uptime anomaly detection

## 🔍 Supported Environments

### Hypervisors Detected
```
┌─────────────┬──────────────────┬─────────────────┐
│ Hypervisor  │ Detection Method │ Confidence      │
├─────────────┼──────────────────┼─────────────────┤
│ VMware      │ CPUID, I/O, Files│ 85-95%          │
│ VirtualBox  │ CPUID, Files, MAC│ 80-95%          │
│ KVM         │ CPUID, MAC       │ 75-90%          │
│ Xen         │ CPUID, MAC       │ 70-85%          │
│ Hyper-V     │ CPUID, Files     │ 75-90%          │
│ QEMU        │ CPUID, MAC, Files│ 70-85%          │
└─────────────┴──────────────────┴─────────────────┘
```

### Containers Detected
- Docker (via .dockerenv, MAC addresses)
- General container environments

### Platforms
- **Primary**: Linux (Ubuntu, Debian, CentOS, RHEL)
- **Extensible**: Other Unix-like systems

## 📦 Installation

### Prerequisites

```bash
# Required packages (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install build-essential

# Required packages (RHEL/CentOS)
sudo yum groupinstall "Development Tools"
```

### Compilation

```bash
# Clone the repository
git clone https://github.com/yourusername/sandbox-detection.git
cd sandbox-detection

# Compile the utility
gcc -o sandbox_detect sandbox_detect.c -lm

# Optional: Install system-wide
sudo cp sandbox_detect /usr/local/bin/
```

### Verify Installation

```bash
./sandbox_detect --help
```

## 🚀 Usage

### Command Line Options

```bash
Usage: ./sandbox_detect [options]

Options:
  --verbose, -v    Enable verbose output with detailed logging
  --json, -j       Output results in JSON format for programmatic use
  --help, -h       Show this help message
```

### Basic Usage Examples

#### Standard Detection
```bash
# Run basic detection
./sandbox_detect
```

#### Verbose Mode
```bash
# Run with detailed information
./sandbox_detect --verbose
```

#### JSON Output for Automation
```bash
# Machine-readable output
./sandbox_detect --json

# Save to file
./sandbox_detect --json > results.json
```

#### Combined Options
```bash
# Verbose JSON output
./sandbox_detect --verbose --json
```

### Integration Examples

#### Bash Script Integration
```bash
#!/bin/bash
if ./sandbox_detect --json | grep -q '"overall_sandbox_confidence": 0.[7-9]'; then
    echo "Sandbox detected! Exiting..."
    exit 1
fi
echo "Safe environment detected"
```

#### Python Integration
```python
import subprocess
import json

result = subprocess.run(['./sandbox_detect', '--json'], 
                       capture_output=True, text=True)
data = json.loads(result.stdout)

if data['overall_sandbox_confidence'] > 0.7:
    print("⚠️ Sandbox environment detected")
else:
    print("✓ Clean environment")
```

## 📊 Examples

### Standard Output Example

```
========================================
   Sandbox Detection Results
========================================

[DETECTED] CPUID Hypervisor Bit
      Confidence: 95%
      Details: Hypervisor present bit set

[DETECTED] Hypervisor Signature
      Confidence: 95%
      Details: VMwareVMware

[DETECTED] Registry/File Artifacts
      Confidence: 85%
      Details: VMware SCSI, VMware Tools

[DETECTED] BIOS Validation
      Confidence: 80%
      Details: Virtualized BIOS: VMware

[DETECTED] MAC Inspection
      Confidence: 90%
      Details: 00:0C:29:AB:CD:EF 00:50:56:12:34:56

[DETECTED] Hardware Heuristics
      Confidence: 65%
      Details: Low CPU cores: 1 Low RAM: 512MB

[CLEAN] Debugger Detection
      Confidence: 0%
      Details: No debugger detected

========================================
Overall Sandbox Detection Confidence: 92%
========================================
⚠️  HIGH PROBABILITY: System appears to be a sandbox/VM
```

### JSON Output Example

```json
{
  "timestamp": 1702345678,
  "detections": [
    {
      "name": "CPUID Hypervisor Bit",
      "detected": true,
      "confidence": 0.95,
      "details": "Hypervisor present bit set"
    },
    {
      "name": "Hypervisor Signature",
      "detected": true,
      "confidence": 0.95,
      "details": "VMwareVMware"
    },
    {
      "name": "Registry/File Artifacts",
      "detected": true,
      "confidence": 0.85,
      "details": "VMware SCSI, VMware Tools"
    },
    {
      "name": "BIOS Validation",
      "detected": true,
      "confidence": 0.80,
      "details": "Virtualized BIOS: VMware"
    },
    {
      "name": "MAC Inspection",
      "detected": true,
      "confidence": 0.90,
      "details": "00:0C:29:AB:CD:EF 00:50:56:12:34:56"
    },
    {
      "name": "Hardware Heuristics",
      "detected": true,
      "confidence": 0.65,
      "details": "Low CPU cores: 1 Low RAM: 512MB"
    },
    {
      "name": "Debugger Detection",
      "detected": false,
      "confidence": 0.00,
      "details": "No debugger detected"
    }
  ],
  "overall_sandbox_confidence": 0.92
}
```

### Verbose Output Example

```
[INFO] Starting sandbox detection...
[DETECT] CPUID: Hypervisor present bit (ECX[31]) (confidence: 95%)
[DETECT] Hypervisor: VMwareVMware (confidence: 95%)
[DETECT] Artifacts: VMware SCSI, VMware Tools (confidence: 85%)
[DETECT] BIOS: Virtualized BIOS: VMware (confidence: 80%)
[DETECT] MAC Address: 00:0C:29:AB:CD:EF 00:50:56:12:34:56 (confidence: 90%)
[DETECT] Hardware: Low CPU cores: 1 Low RAM: 512MB (confidence: 65%)

========================================
   Sandbox Detection Results
========================================
...
```

## 📈 Detection Thresholds

| Metric | Threshold | Suspicious Range | Confidence Impact |
|--------|-----------|------------------|-------------------|
| **CPU Cores** | < 2 cores | 1 core | +10% |
| **RAM** | < 1 GB | 256-512 MB | +10% |
| **Disk Space** | < 40 GB | 10-20 GB | +10% |
| **System Uptime** | < 10 minutes | 0-5 minutes | +10% |
| **Process Count** | < 50 | 20-40 processes | +10% |
| **BIOS Vendor** | Virtualized | VMware, VBox, etc. | +5-15% |
| **MAC OUI** | Sandbox vendor | 15+ known OUIs | +10-25% |

## 🎯 Confidence Scoring

### Scoring Algorithm

```
Overall Confidence = (Σ detection_confidence) / number_of_detections
```

### Interpretation Guide

| Confidence Level | Interpretation | Recommended Action |
|-----------------|----------------|---------------------|
| **> 70%** | 🔴 HIGH PROBABILITY | Strong sandbox indicators - Consider environment switching |
| **40-70%** | 🟡 MEDIUM PROBABILITY | Multiple suspicious indicators - Further verification needed |
| **10-40%** | 🟢 LOW PROBABILITY | Some indicators but inconclusive - Likely legitimate |
| **< 10%** | ✅ NEGLIGIBLE | No significant indicators - Probably physical machine |

### Individual Detection Confidence

| Detection Method | Base Confidence | Factors Affecting |
|-----------------|----------------|-------------------|
| CPUID Hypervisor | 95% | Very reliable, hardware-level |
| Hypervisor Signature | 95% | Direct identification |
| VMware I/O Timing | 75% | May have false positives |
| MAC OUI Match | 70-95% | Depends on interface count |
| Hardware Heuristics | 10-90% | Cumulative scoring |
| Debugger Detection | 85% | Reliable on Linux |

## 🏗️ Architecture

```
sandbox_detect.c
│
├── Virtualization Detection Layer
│   ├── CPUID Hypervisor Bit
│   ├── Hypervisor Signatures  
│   ├── Red Pill Timing
│   └── VMware I/O Timing
│
├── Artifact Analysis Layer
│   ├── File System Artifacts
│   │   ├── /proc/scsi/scsi
│   │   ├── /opt/VBoxGuestAdditions
│   │   └── /usr/lib/vmware-tools
│   └── Device Detection
│       └── PCI device enumeration
│
├── BIOS Validation Layer
│   ├── /sys/class/dmi/id/bios_vendor
│   ├── /sys/class/dmi/id/sys_vendor
│   └── /sys/class/dmi/id/product_name
│
├── MAC Inspection Layer
│   ├── Interface enumeration
│   ├── OUI extraction
│   └── Known vendor matching
│
├── Hardware Heuristics Layer
│   ├── CPU core counting
│   ├── Memory analysis
│   ├── Disk space check
│   ├── Uptime analysis
│   └── Process enumeration
│
└── Anti-Debugging Layer
    └── Ptrace detection
```

## 💼 Use Cases

### 1. Malware Analysis
```c
// Detect sandbox before executing payload
if (detect_sandbox() > 0.7) {
    // Execute benign behavior
    benign_payload();
} else {
    // Execute malicious payload
    malicious_payload();
}
```

### 2. Red Teaming
- Identify analysis environments during assessments
- Adjust TTPs based on environment detection
- Evade automated analysis systems

### 3. Security Research
- Study anti-analysis techniques
- Analyze sandbox evasion methods
- Research detection bypasses

### 4. Software Protection
- Implement environment-aware licensing
- Detect debugging attempts
- Protect intellectual property

### 5. Forensics
- Determine system virtualization status
- Verify evidence authenticity
- Identify analysis environments

## ⚠️ Limitations

### Current Limitations

| Limitation | Impact | Mitigation |
|------------|--------|-------------|
| Linux-only | Windows not supported | Extensible architecture |
| Privilege requirements | Some checks need root | Graceful degradation |
| False positives | Hardware heuristics | Confidence scoring |
| Evasion possible | Advanced sandboxes | Multiple techniques |
| Static thresholds | May not fit all | Configurable values |

### Known False Positives

1. **Low CPU Cores**: Legitimate embedded systems
2. **Low RAM**: Older hardware, IoT devices
3. **Small Disk**: Cloud instances, containers
4. **Suspicious MAC**: Some legitimate hardware vendors

### Evasion Techniques That May Work

- CPUID instruction filtering
- Timing attack normalization
- Artifact spoofing
- Custom hardware emulation
- Transparent virtualization

## 🛡️ Evasion Countermeasures

Advanced sandboxes may implement:

```
┌─────────────────────────────────────────────────────┐
│           Sandbox Evasion Techniques                │
├─────────────────────────────────────────────────────┤
│ • CPUID instruction interception                    │
│ • Timing attack normalization                       │
│ • DMI/SMBIOS spoofing                               │
│ • MAC address randomization                         │
│ • Process hiding                                    │
│ • Filesystem filtering                              │
│ • Network traffic shaping                           │
│ • Memory manipulation                               │
└─────────────────────────────────────────────────────┘
```

## ⚖️ Legal Notice

### Intended Use

This tool is intended for:
- ✅ Legitimate security research
- ✅ Malware analysis in controlled environments
- ✅ Authorized penetration testing
- ✅ Educational purposes
- ✅ Defensive security research

### Prohibited Use

This tool MUST NOT be used for:
- ❌ Unauthorized system access
- ❌ Malware development
- ❌ Illegal activities
- ❌ Violating terms of service
- ❌ Circumventing security controls without authorization

### Compliance

**Users are responsible for compliance with applicable laws and regulations.**

By using this software, you agree to:
1. Use only in authorized environments
2. Comply with all local, state, and federal laws
3. Obtain proper authorization before testing
4. Not use for malicious purposes

## 🤝 Contributing

### Areas for Improvement

| Category | Specific Needs | Difficulty |
|----------|---------------|------------|
| **Platform Support** | Windows compatibility | High |
| **Detection** | Additional hypervisor signatures | Medium |
| **Techniques** | More sophisticated timing attacks | Medium |
| **Scoring** | Improved confidence algorithms | Low |
| **Artifacts** | Additional detection methods | Low |
| **Performance** | Optimization and speed | Medium |

### How to Contribute

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests if applicable
5. Submit a pull request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/sandbox-detection.git
cd sandbox-detection

# Create a branch
git checkout -b feature/your-feature

# Make changes and test
gcc -o sandbox_detect sandbox_detect.c -lm -Wall -Wextra

# Run tests
./sandbox_detect --verbose

# Commit and push
git add .
git commit -m "Add your feature"
git push origin feature/your-feature
```

### Coding Standards

- Follow C99 standard
- Use descriptive variable names
- Add comments for complex logic
- Maintain consistent indentation
- Update documentation

## 📚 References

### Technical References

1. [CPUID Hypervisor Bit - VMware KB](https://kb.vmware.com/s/article/1009458)
2. [Red Pill Anti-VM Technique](http://invisiblethings.org/papers/redpill.html)
3. [VMware Backdoor I/O Ports](https://sites.google.com/site/chitchatvmback/)
4. [DMI/SMBIOS Virtualization Detection](https://www.dmtf.org/standards/smbios)
5. [Intel CPUID Documentation](https://www.intel.com/content/www/us/en/develop/documentation/vtune-help/top/reference/cpu-architecture-specifics/cpuid.html)

### Related Research

- "Detecting Virtualization" - T. Garfinkel, Stanford
- "Anti-Virtualization Techniques" - D. Dai Zovi
- "Hardware Virtualization Detection" - M. Polychronakis
- "Sandbox Evasion Techniques" - FireEye Research

### Tools Similar to This Project

- **pafish** - Paranoid Fish (Windows)
- **vmdetect** - Virtual machine detection
- **al-khaser** - Anti-analysis detection
- **unveil** - Sandbox detection

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

```
MIT License

Copyright (c) 2024 Security Research

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions...

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

## 📞 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/sandbox-detection/issues)
- **Security Research**: For research collaboration
- **Documentation**: See [docs/](docs/) directory

## 🙏 Acknowledgments

- Open source community
- Security researchers in virtualization detection
- Malware analysis community

---

## ⭐ Star History

If you find this tool useful, please consider giving it a star on GitHub!

---

**Disclaimer**: This tool is for research purposes only. The authors are not responsible for misuse or damage caused by this software. Use responsibly and in accordance with applicable laws.

```

This complete README.md file includes:
- Professional formatting with badges
- Detailed table of contents
- Comprehensive feature documentation
- Installation and usage instructions
- Multiple output format examples
- Architecture diagrams
- Legal disclaimers
- Contributing guidelines
- Technical references
- Professional formatting with emojis and tables
