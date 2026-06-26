# 🛡️ SentinelRecon AI

**AI-Powered Intelligent Network Reconnaissance & Threat Intelligence Toolkit**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> ⚠️ **DISCLAIMER:** SentinelRecon AI is designed strictly for **authorized** security auditing, defensive analysis, and CTF environments. Scanning third-party networks without explicit, written consent is illegal and unethical. The developers assume no liability for misuse.

## 🌟 Overview

**SentinelRecon** transcends traditional port scanners by combining network mapping with Real-Time Threat Intelligence (AbuseIPDB, VirusTotal) and Generative AI (Anthropic Claude). It not only tells you *what* is open, but also analyzes the security implications, scores the risk, and generates enterprise-grade HTML/PDF reports.

### ✨ Key Features

- **Advanced Port Scanning:** SYN, Connect, and UDP scanning with dynamic service detection.
- **Global Threat Intelligence (v2.0):** Real-time IP reputation checks using AbuseIPDB and VirusTotal.
- **Vulnerability Mapping (CVEs):** Automatic cross-referencing of detected services against known CVEs.
- **AI-Powered Analysis:** Context-aware vulnerability summaries and remediation steps via AI analysis.
- **Stunning UI & Reporting:** Rich terminal UI and beautifully styled HTML/PDF report generation (Jinja2).
- **SQLite Persistence:** Automatically saves all scan history and metrics locally.

## 🚀 Installation

### 1. Prerequisites
- **Python 3.9+**
- For PDF Report Generation, you must have [WeasyPrint dependencies (GTK3)](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation) installed on your system. 

### 2. Setup

Clone the repository and install dependencies:

```bash
git clone https://github.com/shlok926/SentinelReconAI.git
cd SentinelReconAI
pip install -r requirements.txt
```

### 3. Environment Configuration

SentinelRecon relies on API keys for Threat Intel and AI features. Create a `.env` file in the root directory:

```bash
cp .env.example .env
```
Edit the `.env` file and add your keys (All are optional, but required for advanced features):
```env
# AI Analysis (Optional but recommended)
CLAUDE_API_KEY="your-anthropic-key-here"

# Threat Intelligence (Optional, Free)
ABUSEIPDB_API_KEY="your-abuseipdb-key-here"
VT_API_KEY="your-virustotal-key-here"
```

## 💻 Usage

SentinelRecon is executed via a powerful CLI interface.

### Basic Scan
Scan a target using default options (Ports 1-1024):
```bash
python -m sentinelrecon.cli.main scan --target 192.168.1.1
```

### Advanced Scan
Scan specific ports, skip AI, and output professional reports to a custom directory:
```bash
python -m sentinelrecon.cli.main scan --target scanme.nmap.org --ports 22,80,443 --type connect --no-ai --output ./my_reports
```

*Note: Threat Intelligence queries are automatically skipped for private/local IP ranges to save your API quota.*

## 📁 Repository Structure
```text
SentinelReconAI/
├── sentinelrecon/
│   ├── cli/            # Rich Terminal Interface (Commands & Display)
│   ├── core/           # Port Scanner & Threat Intel Managers
│   ├── data/           # SQLite Database Operations
│   ├── reports/        # HTML/PDF Jinja2 Report Generators
│   └── analysis/       # AI Integration & Risk Scoring
├── output/             # Generated HTML/PDF Reports go here
└── .env.example        # Environment Variables Template
```

## 🤝 Contributing
Contributions, issues, and feature requests are welcome!
Feel free to check the [issues page](https://github.com/shlok926/SentinelReconAI/issues).

## 📝 License
This project is [MIT](LICENSE) licensed.
