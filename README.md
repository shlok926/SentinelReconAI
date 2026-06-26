<div align="center">
  
  <img src="docs/images/logo.png" alt="SentinelRecon Logo" width="200">

  # SentinelRecon AI 🛡️

  **Enterprise-Grade AI-Powered Network Reconnaissance & Threat Intelligence Toolkit**
  
  *An advanced security auditor that performs intelligent port scanning, real-time threat intelligence correlation (AbuseIPDB, VirusTotal), CVE mapping, and AI-driven vulnerability remediation.*

  [![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
  [![AI Powered](https://img.shields.io/badge/AI-Claude_3-7C3AED?style=for-the-badge&logo=anthropic)](https://anthropic.com/)
  [![License MIT](https://img.shields.io/badge/License-MIT-F59E0B?style=for-the-badge)](LICENSE)
  [![Status](https://img.shields.io/badge/Status-Production_Ready-10B981?style=for-the-badge)]()

  [🚀 Quick Start](#-quick-start) • [📚 Architecture](#%EF%B8%8F-architecture) • [⚙️ Configuration](#%EF%B8%8F-configuration) • [🤝 Contribute](#-contributing)

</div>

---

## 🎯 Key Features at a Glance

| 🔍 Intelligent Recon | 🚨 Threat Intelligence | 🤖 AI Analysis | 📊 Enterprise Reports |
| :--- | :--- | :--- | :--- |
| **Multi-mode Scanning** (SYN, Connect, UDP) with service/banner grabbing. | **Real-time API Checks** via AbuseIPDB and VirusTotal to detect malicious IPs. | **Claude Integration** to provide context-aware risk scoring and remediation steps. | **Beautiful UI/UX** with Rich Terminal outputs and HTML/PDF Jinja2 Reports. |

---

## 📑 Table of Contents
- [Disclaimer](#%EF%B8%8F-disclaimer)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [Architecture](#%EF%B8%8F-architecture)
- [Configuration](#%EF%B8%8F-configuration)
- [Repository Structure](#-repository-structure)

---

## ⚠️ Disclaimer
> **SentinelRecon AI is designed strictly for authorized security auditing, defensive analysis, and CTF environments.** Scanning third-party networks without explicit, written consent is illegal and unethical. The developers assume no liability for misuse.

---

## 🚀 Quick Start

### 1. Prerequisites
- **Python 3.9+**
- For PDF Report Generation, you must have [WeasyPrint dependencies (GTK3)](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation) installed on your system. 

### 2. Installation
```bash
git clone https://github.com/shlok926/SentinelReconAI.git
cd SentinelReconAI
pip install -r requirements.txt
```

---

## 💻 Usage Guide

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

---

## ⚙️ Configuration

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

---

## 🏗️ Architecture

```mermaid
graph TD
    %% Define Styles
    classDef user fill:#2d3748,stroke:#4a5568,stroke-width:2px,color:#fff,rx:5px
    classDef core fill:#2b6cb0,stroke:#3182ce,stroke-width:2px,color:#fff,rx:5px
    classDef intel fill:#805ad5,stroke:#9f7aea,stroke-width:2px,color:#fff,rx:5px
    classDef ai fill:#00a3c4,stroke:#0bc5ea,stroke-width:2px,color:#fff,rx:5px
    classDef data fill:#c53030,stroke:#f56565,stroke-width:2px,color:#fff,rx:5px
    classDef report fill:#38a169,stroke:#48bb78,stroke-width:2px,color:#fff,rx:5px

    %% Nodes
    U[User / Terminal]:::user
    O(ScanOrchestrator):::core

    subgraph Core Engines
        PS[Port Scanner]:::core
        CM[CVE Mapper]:::core
        TI[Threat Intel Manager]:::intel
    end

    subgraph External APIs
        VT[(VirusTotal)]:::intel
        AB[(AbuseIPDB)]:::intel
        NVD[(NVD DB)]:::core
    end

    subgraph Analysis Layer
        AI[Claude AI Analyzer]:::ai
        RS[Risk Scorer]:::ai
    end

    subgraph Data & Presentation
        DB[(SQLite Database)]:::data
        RG[Report Generator]:::report
        UI[Rich CLI Display]:::report
    end

    %% Connections
    U -->|Initiates Scan| O
    O -->|1. Scans Ports| PS
    O -->|2. Maps Vulns| CM
    O -->|3. Fetches IP Rep| TI

    TI -.->|API Call| VT
    TI -.->|API Call| AB
    CM -.->|Lookup| NVD

    O -->|4. Generates Context| AI
    O -->|5. Calculates Score| RS

    O -->|6. Saves History| DB
    O -->|7. Renders Output| RG
    O -->|8. Shows Table| UI
```

---

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

---

## 🤝 Contributing
Contributions, issues, and feature requests are welcome!
Feel free to check the [issues page](https://github.com/shlok926/SentinelReconAI/issues).

## 📝 License
This project is [MIT](LICENSE) licensed.
