# SentinelRecon AI Configuration Guide

SentinelRecon AI uses a `.env` file to manage sensitive API keys and configuration parameters. This prevents hardcoding credentials into the source code.

## Setting Up Environment Variables

1. Copy the example configuration file:
   ```bash
   cp .env.example .env
   ```

2. Open the `.env` file in your preferred text editor and add the required API keys.

## API Key Requirements

### 1. Anthropic Claude (AI Analysis)
- **Variable**: `CLAUDE_API_KEY`
- **Purpose**: Powers the Generative AI analysis, context-aware vulnerability mapping, and remediation strategies.
- **Get a Key**: [Anthropic Console](https://console.anthropic.com/)
- **Note**: If left empty, SentinelRecon will skip the AI analysis phase but continue with port scanning and threat intelligence.

### 2. AbuseIPDB (Threat Intelligence)
- **Variable**: `ABUSEIPDB_API_KEY`
- **Purpose**: Checks the target IP address against a global database of reported malicious IPs to generate a Confidence Score.
- **Get a Key**: [AbuseIPDB API](https://www.abuseipdb.com/api)
- **Note**: Free tier provides 1,000 queries per day.

### 3. VirusTotal (Threat Intelligence)
- **Variable**: `VT_API_KEY`
- **Purpose**: Cross-references the target IP against multiple antivirus engines and dataset vendors to detect malicious or suspicious activity.
- **Get a Key**: [VirusTotal API](https://www.virustotal.com/gui/user/username/apikey)
- **Note**: Free tier is rate-limited to 4 requests per minute. SentinelRecon handles rate-limit errors gracefully.

## Best Practices
- **NEVER** commit your `.env` file to version control (it is ignored by `.gitignore` by default).
- Avoid scanning private subnets (`192.168.x.x`, `10.x.x.x`) if you do not want to query public threat intel databases, though SentinelRecon automatically attempts to filter RFC1918 addresses before querying external APIs.
