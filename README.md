# SentinelRecon

**AI-Powered Intelligent Reconnaissance Toolkit**

🔍 Advanced network reconnaissance and vulnerability insight tool for security learners and professionals.

## Overview

SentinelRecon combines **port scanning**, **service detection**, **CVE mapping**, and **AI-powered analysis** into a single, beginner-friendly tool. Instead of raw scan output, get intelligent insights in seconds.

### Key Features

✅ **Fast Port Scanning** - SYN, TCP Connect, UDP scans  
✅ **Service Detection** - Identify services and versions  
✅ **Banner Grabbing** - Extract service information  
✅ **CVE Lookup** - Integrated NVD database queries  
✅ **AI Analysis** - Claude-powered intelligent insights  
✅ **Risk Scoring** - Automatic severity assessment  
✅ **Professional Reports** - HTML, PDF, JSON exports  
✅ **Scan History** - SQLite-backed persistence  
✅ **Dual Interface** - CLI + optional Web UI  

## Installation

### Requirements
- Python 3.9+
- pip or conda

### Quick Start

```bash
# Clone repository
git clone https://github.com/sentinelrecon/sentinelrecon.git
cd sentinelrecon

# Install dependencies
pip install -r requirements.txt

# Set up configuration
cp .env.example .env
# Edit .env with your API keys

# Initialize database
python scripts/setup_db.py
```

## Usage

### CLI Commands

```bash
# Scan a target
sentinelrecon scan --target 192.168.1.1

# Scan with options
sentinelrecon scan --target example.com --ports 1-1024 --type syn

# View scan history
sentinelrecon history --last 10

# Configure settings
sentinelrecon config --set-api-key claude

# Generate report from past scan
sentinelrecon report --scan-id abc123 --format pdf
```

### Web UI

```bash
# Start Flask web server
python -m sentinelrecon.web.app

# Open browser to http://localhost:5000
```

## Configuration

Edit `.env` file with:
- `CLAUDE_API_KEY` - Your Anthropic API key
- `NVD_API_KEY` - Your NVD API key (optional)
- `DEFAULT_SCAN_TIMEOUT` - Timeout in seconds
- `DEFAULT_THREAD_COUNT` - Number of scanner threads

## Architecture

```
sentinelrecon/
├── core/              # Scanning engine, banner grabber
├── analysis/          # CVE mapper, risk scorer, AI analyzer
├── data/              # Database models and operations
├── reports/           # Report generation (HTML/PDF/JSON)
├── web/               # Flask web UI (optional)
├── cli/               # Click CLI interface
└── utils/             # Helper utilities and validators
```

## Development

```bash
# Install dev dependencies
make install-dev

# Run tests
make test

# Format code
make format

# Run linter
make lint
```

## Documentation

See [docs/](docs/) for complete documentation:
- [INSTALL.md](docs/INSTALL.md) - Detailed installation guide
- [USAGE.md](docs/USAGE.md) - Complete usage guide
- [API.md](docs/API.md) - API reference
- [ETHICS.md](docs/ETHICS.md) - Legal and ethical policy

## License

MIT License - see LICENSE file for details

## Contributing

Contributions welcome! Please open issues or submit pull requests.

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review sample scans in docs/

## Status

**v1.0.0** - May 2026
- Initial release with core features
- CLI fully functional
- Web UI included
- Database persistence working
