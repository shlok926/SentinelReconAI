<div align="center">
  
  <img src="docs/images/cli_hero.svg" alt="SentinelRecon Terminal Banner" width="100%">

  # SentinelRecon AI

  **Enterprise-Grade AI-Powered Network Reconnaissance, Threat Intelligence & Cloud Enumeration Toolkit**

  [![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
  [![AI Powered](https://img.shields.io/badge/AI-Claude_3-7C3AED?style=for-the-badge&logo=anthropic)](https://anthropic.com/)
  [![License MIT](https://img.shields.io/badge/License-MIT-F59E0B?style=for-the-badge)](LICENSE)
  [![Build](https://img.shields.io/github/actions/workflow/status/shlok926/SentinelReconAI/ci.yml?branch=main&style=for-the-badge&logo=github)](https://github.com/shlok926/SentinelReconAI/actions)
  [![Status](https://img.shields.io/badge/Status-v2.0_Released-10B981?style=for-the-badge)]()

  [Quickstart](#quickstart) • [Architecture](#architecture-overview) • [Contribute](#contributing)

</div>

---

## Table of Contents

| | |
|---|---|
| 1. [Executive Summary](#executive-summary) | 10. [Design Decisions](#design-decisions) |
| 2. [Purpose](#purpose) | 11. [Engineering Considerations](#engineering-considerations) |
| 3. [Scope](#scope) | 12. [Documentation Index](#documentation-index) |
| 4. [Background](#background) | 13. [Risks](#risks) |
| 5. [Key Capabilities](#key-capabilities) | 14. [Assumptions](#assumptions) |
| 6. [Architecture Overview](#architecture-overview) | 15. [Future Improvements](#future-improvements) |
| 7. [Tech Stack](#tech-stack) | 16. [Contributing](#contributing--feedback) |
| 8. [Repository Structure](#repository-structure) | 17. [References](#references) |
| 9. [Quickstart](#quickstart) | |

---

## Executive Summary
**SentinelRecon AI** is a next-generation security auditing tool that bridges the gap between raw network reconnaissance, actionable threat intelligence, and cloud misconfiguration discovery. By orchestrating port scanning, global OSINT feeds (Shodan, AlienVault OTX, AbuseIPDB, VirusTotal), Cloud enumeration (AWS, Azure, GCP), and Large Language Model (LLM) analysis, it provides defenders and security researchers with context-rich, enterprise-grade vulnerability reports in seconds.

## Purpose
Traditional scanners (like Nmap) output raw data that requires manual interpretation and cross-referencing against CVE databases. SentinelRecon's purpose is to **automate the complete attack surface correlation process**. It instantly maps open ports to known vulnerabilities, checks IP reputation globally, evaluates cloud assets for public exposure, and generates AI-driven remediation strategies—saving SOC analysts hours of manual triage.

## Scope
**In-Scope:**
- TCP SYN, Connect, and UDP port scanning.
- Banner grabbing and service enumeration.
- Automated CVE lookups via NVD.
- Real-time IP reputation & historical OSINT (Shodan, AlienVault OTX, AbuseIPDB, VirusTotal).
- **[NEW in v2.0]** Cloud Asset Enumeration (AWS S3/EC2/IAM, Azure, GCP).
- Generative AI analysis for context and remediation.
- Local SQLite tracking and rich HTML/PDF report generation.

**Out-of-Scope:**
- Active exploitation or payload delivery (strict read-only reconnaissance).
- Distributed denial of service (DDoS) testing.

## Background
As cyber threats become more sophisticated, the "Time to Remediate" (TTR) metric is critical. SentinelRecon was built to unify disjointed workflows—network scanning, CVE lookup, threat intelligence, and cloud auditing—into a single, powerful CLI command.

## Key Capabilities
| Capability | Description |
| :--- | :--- |
| **Intelligent Recon** | Multi-mode port scanning with dynamic service detection. |
| **Threat Intelligence** | OSINT correlation with Shodan, OTX, VirusTotal, and AbuseIPDB. |
| **Cloud Enumeration** | Automated discovery of misconfigured AWS, Azure, and GCP assets. |
| **AI Triage** | Claude-3 integration for risk scoring and plain-English remediation advice. |
| **Reporting** | Beautiful Jinja2-powered HTML/PDF enterprise reports. |

---

## 📸 Screenshots & Demos

### Rich Terminal Interface
<p align="center">
  <img src="docs/images/cli_banner.png" alt="CLI Banner" width="48%">
  <img src="docs/images/cli_threat_intel.png" alt="CLI Threat Intel" width="48%">
</p>

### Enterprise HTML Reports
<p align="center">
  <img src="docs/images/html_report_ports.png" alt="HTML Report Ports" width="48%">
  <img src="docs/images/html_report_intel.png" alt="HTML Threat Intel" width="48%">
</p>

---

## Architecture Overview

```mermaid
graph TD
    classDef core fill:#2b6cb0,stroke:#3182ce,stroke-width:2px,color:#fff,rx:5px
    classDef intel fill:#805ad5,stroke:#9f7aea,stroke-width:2px,color:#fff,rx:5px
    classDef ai fill:#00a3c4,stroke:#0bc5ea,stroke-width:2px,color:#fff,rx:5px
    classDef data fill:#c53030,stroke:#f56565,stroke-width:2px,color:#fff,rx:5px
    classDef cloud fill:#38a169,stroke:#48bb78,stroke-width:2px,color:#fff,rx:5px

    U[User CLI]:::core --> O(Scan Orchestrator):::core
    
    subgraph Core Engines
        O --> PS[Port Scanner]:::core
        O --> CM[CVE Mapper]:::core
    end
    
    subgraph Threat Intelligence
        O --> TI[Threat Intel Manager]:::intel
        TI -.-> SH[(Shodan API)]:::intel
        TI -.-> OT[(AlienVault OTX)]:::intel
        TI -.-> VT[(VirusTotal API)]:::intel
        TI -.-> AB[(AbuseIPDB API)]:::intel
    end
    
    subgraph Cloud Enumeration
        O --> CE[Cloud Enumerators]:::cloud
        CE -.-> AWS[(AWS S3/EC2/IAM)]:::cloud
        CE -.-> AZ[(Azure Resources)]:::cloud
        CE -.-> GCP[(GCP Resources)]:::cloud
    end
    
    subgraph Analysis & Storage
        O --> AI[Claude AI Analyzer]:::ai
        O --> DB[(SQLite Local DB)]:::data
        O --> RG[Jinja2 Report Generator]:::data
    end
```

## Tech Stack
- **Core Language:** Python 3.9+
- **CLI Framework:** Click, Rich (for terminal UI)
- **Cloud SDKs:** boto3, azure-identity, google-cloud
- **APIs & AI:** Requests, Anthropic Claude 3 API
- **Reporting:** Jinja2 (HTML), WeasyPrint (PDF)
- **Data Persistence:** SQLite3

## Repository Structure
```text
SentinelReconAI/
├── sentinelrecon/
│   ├── cli/            # Rich Terminal Interface & Commands
│   ├── core/           # Port Scanner, CVE Mapper, Threat Intel
│   ├── integrations/   # Cloud & External OSINT Clients (v1.5 & v2.0)
│   ├── data/           # SQLite Database Operations
│   ├── reports/        # HTML/PDF Jinja2 Report Generators
│   └── analysis/       # AI Integration & Risk Scoring
├── output/             # Generated HTML/PDF Reports
└── .env.example        # Environment Configuration
```

## Quickstart

### Method 1: Direct Install (Recommended)
You can install SentinelRecon globally via pip without cloning the repository manually:
```bash
pip install git+https://github.com/shlok926/SentinelReconAI.git
```
This enables the `sentinelrecon` command globally in your terminal.

### Method 2: Clone & Editable Install
```bash
git clone https://github.com/shlok926/SentinelReconAI.git
cd SentinelReconAI
pip install -e .
```

### Configuration & Secrets
Set up your API keys to unlock full capabilities (AI, Threat Intel, Cloud):
```bash
sentinelrecon config --set shodan_api_key YOUR_KEY
sentinelrecon config --set otx_api_key YOUR_KEY
# Or manually edit the .env file in your working directory
```

### Example Scans

**1. Basic Network & Threat Intel Scan:**
```bash
sentinelrecon scan --target 8.8.8.8 --ports 1-1000 --type connect
```

**2. Complete Cloud Enumeration Scan (AWS):**
```bash
sentinelrecon scan --target example.com --cloud aws --aws-region us-east-1
```
*(Ensure AWS credentials like `AWS_ACCESS_KEY_ID` are set in your environment).*

## Design Decisions
1. **Modular Architecture:** The system is heavily decoupled. External modules like Cloud Enumerators and AI Analysis can be skipped gracefully if credentials are not provided.
2. **Local SQLite Over Postgres:** Designed as a private auditing tool, SQLite provides zero-configuration state persistence, ensuring scan history remains entirely local.
3. **Jinja2 Static Reporting:** HTML static reports provide highly portable, shareable, and instantly rendering dashboards containing detailed network, cloud, and intelligence telemetry.

## Engineering Considerations
- **Graceful Degradation:** If an API rate limit is hit (e.g., VirusTotal), the tool catches the error, marks the module as "Skipped," and successfully compiles the final report using the remaining data.
- **Data Privacy:** Internal IP addresses (192.168.x.x, 10.x.x.x) are automatically detected, and Threat Intelligence API calls are dynamically skipped to prevent leaking internal infrastructure maps to global databases.

## Documentation Index
- [Configuration Guide](docs/CONFIG.md)
- [API Reference](docs/API.md)
- [Ethical Guidelines](docs/ETHICS.md)

## Risks
- **LLM Hallucinations:** Generative AI may occasionally suggest outdated remediation steps.
- **API Quotas:** Aggressive scanning on large subnets will rapidly exhaust free-tier API limits on OSINT feeds.

## Assumptions
- The user has legal authorization to scan the target IP/Domain.
- The user possesses the necessary API keys for advanced context generation.
- The host system can resolve DNS hostnames to IPv4 addresses.

## Future Improvements
- **Active Vulnerability Exploitation (DAST):** Implementing safe, permissioned active tests like XSS payload firing and Directory Brute-forcing.
- **Async Scanning:** Migrating the socket scanner to `asyncio` for a 10x performance boost on /24 subnets.
- **Kubernetes Auditing:** Adding enumerators for K8s clusters and container registries.

## 🤝 Contributing & Feedback
Contributions, suggestions, and feedback are highly welcome!

- **Got suggestions or feature requests?** Feel free to open a new [Issue](https://github.com/shlok926/SentinelReconAI/issues) or share your ideas.
- **Want to contribute?** Feel free to fork this repository, make your changes, and submit a Pull Request.

---

## ⭐ Show Your Support

<div align="center">
  <b>Love this tool? Help us grow:</b>
</div>

```text
✨ Star the repository   (GitHub Star Button)
🐛 Report bugs           (GitHub Issues)
💡 Suggest features      (GitHub Discussions)
📣 Share with others     (LinkedIn/Twitter)
🤝 Contribute code       (Pull Requests)
```

---

## 👤 Author & Contact

<div align="center">
  👨‍💻 <b>Shlok Thorat</b><br>
  <i>Let's connect on LinkedIn, collaborate, and build amazing things together!</i><br><br>

  [![Email](https://img.shields.io/badge/Email-shlokthorat29075@gmail.com-EA4335?style=flat&logo=gmail&logoColor=white)](mailto:shlokthorat29075@gmail.com)
  [![GitHub](https://img.shields.io/badge/GitHub-@shlok926-181717?style=flat&logo=github&logoColor=white)](https://github.com/shlok926)
  [![LinkedIn](https://img.shields.io/badge/LinkedIn-shlok--thorat--39916a405-0A66C2?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/shlok-thorat-39916a405/)

  <br><br>
  Made with ❤️ by Shlok! for Cybersecurity Innovation • <a href="#sentinelrecon-ai">Back to Top</a>
</div>
