<div align="center">
  
  <img src="docs/images/cli_hero.svg?v=4" alt="SentinelRecon Terminal Banner" width="100%">

  # SentinelRecon v2.0

  **Enterprise-Grade Cloud Infrastructure Enumeration & Security Analysis Platform**

  [![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
  [![License MIT](https://img.shields.io/badge/License-MIT-F59E0B?style=for-the-badge)](LICENSE)
  [![Build](https://img.shields.io/github/actions/workflow/status/shlok926/SentinelReconAI/ci.yml?branch=main&style=for-the-badge&logo=github)](https://github.com/shlok926/SentinelReconAI/actions)
  [![Status](https://img.shields.io/badge/Status-v2.0_Released-10B981?style=for-the-badge)]()
  [![Coverage](https://img.shields.io/badge/coverage-80%25+-success?style=for-the-badge)]()

  [Features](#-features) • [Architecture](#-architecture) • [Installation](#-installation)

</div>

---

## 🎯 Overview

**SentinelRecon** is a professional cloud security scanning tool that automates the enumeration of cloud resources and identifies security misconfigurations across AWS, Azure, and Google Cloud Platform.

Built with enterprise patterns, comprehensive testing, and security-first principles.

### Key Capabilities

| Cloud | Resources | Checks |
|-------|-----------|--------|
| **AWS** | S3 Buckets, EC2 Instances, IAM Users/Roles | Encryption, Public Access, Versioning, MFA, Access Keys |
| **Azure** | Virtual Machines, Storage Accounts | Encryption, HTTPS-only, Network Config |
| **GCP** | Compute Instances, Storage Buckets | Uniform Access, Versioning, Public IP |

---

## ✨ Features

### 🔍 Comprehensive Enumeration
- **AWS S3:** Bucket enumeration with encryption, versioning, logging, and public access checks
- **AWS EC2:** Multi-region instance scanning with security group analysis
- **AWS IAM:** User/role audit with access key age and MFA validation
- **Azure VMs:** Virtual machine enumeration with encryption and network checks
- **Azure Storage:** Storage account scanning with HTTPS and encryption validation
- **GCP Compute:** Instance enumeration across zones and regions
- **GCP Storage:** Bucket scanning with uniform access and versioning checks

### 📊 Intelligent Risk Scoring
Every resource gets a risk rating (LOW → CRITICAL) based on:
- Encryption status
- Public accessibility
- Authentication requirements
- Configuration best practices

### 📋 Multiple Report Formats
- **JSON:** Machine-readable, API-friendly format
- **HTML:** Professional dashboard with styling and statistics
- **Summary:** Executive overview of findings

### 🛡️ Security-First Design
- SSL/TLS verification enabled on all API calls
- Configurable timeouts (default: 30 seconds)
- Secure file permissions (0o600 for sensitive files)
- Symlink attack detection
- Type hints and comprehensive docstrings (100%)
- No hardcoded credentials
- No disabled security warnings

### 🧪 Production-Ready Testing
- 28+ unit tests with comprehensive coverage
- Security validation tests (verify=True checks, timeout validation)
- Integration tests for complete workflows
- Automated security checks in CI/CD pipeline
- 80%+ code coverage

### 🚀 CI/CD Pipeline
- GitHub Actions workflow on push/PR
- Automated testing on Python 3.10, 3.11, 3.12
- Code quality checks
- Security scanning

---

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- AWS credentials (for AWS scanning)
- Azure credentials (for Azure scanning)
- GCP credentials (for GCP scanning)

### Quick Start

```bash
# Clone repository
git clone https://github.com/shlok926/SentinelReconAI.git
cd SentinelReconAI

# Install dependencies
pip install -r requirements.txt

# Configure credentials
export AWS_PROFILE=your-profile
export AZURE_SUBSCRIPTION_ID=your-subscription
export GOOGLE_APPLICATION_CREDENTIALS=path/to/gcp-key.json

# Run a scan
python -m sentinelrecon.v2.main --account 123456789012 --scan all
```

---

## 🚀 Usage

### Basic Scan (All Clouds)
```bash
python -m sentinelrecon.v2.main --account 123456789012 --scan all
```

### AWS Only Scan
```bash
# S3 enumeration
python -m sentinelrecon.v2.main --account 123456789012 --scan s3

# Multiple services
python -m sentinelrecon.v2.main --account 123456789012 --scan s3,ec2,iam
```

### Azure Scan
```bash
python -m sentinelrecon.v2.main --cloud azure --subscription your-subscription-id
```

### GCP Scan
```bash
python -m sentinelrecon.v2.main --cloud gcp --project your-project-id
```

---

## 🏗️ Architecture

### Layered Design
```
┌─────────────────────────────────┐
│  Presentation Layer             │  main.py, CLI argument parsing
├─────────────────────────────────┤
│  Business Logic Layer           │  Orchestrator, Scanners
├─────────────────────────────────┤
│  Data Access Layer              │  Models, Output Manager
├─────────────────────────────────┤
│  Infrastructure Layer           │  AWS/Azure/GCP Clients
└─────────────────────────────────┘
```

### Design Patterns
- **Dependency Injection:** ServiceContainer for loose coupling
- **Factory Pattern:** Cloud client creation
- **Strategy Pattern:** Scanner implementations
- **Repository Pattern:** Output management

---

## 🔐 Security Considerations

### AWS Credentials
- Use IAM roles when running on EC2
- Use AWS profiles for local development
- Never commit credentials to version control

### Azure Credentials
- Use DefaultAzureCredential (supports multiple auth methods)
- Set AZURE_SUBSCRIPTION_ID environment variable

### GCP Credentials
- Use Application Default Credentials (ADC)
- Set GOOGLE_APPLICATION_CREDENTIALS to service account key path

---

## 🛣️ Roadmap

- [x] AWS S3 enumeration
- [x] AWS EC2 scanning
- [x] AWS IAM audit
- [x] Azure VMs + Storage (v2.1)
- [x] GCP Compute + Storage (v2.1)
- [ ] Real-time scanning dashboard
- [ ] Automated remediation suggestions
- [ ] Multi-cloud compliance reporting
- [ ] Integration with SIEM platforms
- [ ] Slack/Teams notifications

---

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
  Made with ❤️ by Shlok! for Cybersecurity Innovation • <a href="#sentinelrecon-v20">Back to Top</a>
</div>
