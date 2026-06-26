# Ethical Guidelines & Rules of Engagement

SentinelRecon AI is an extremely powerful reconnaissance tool designed to identify network vulnerabilities, query global threat intelligence feeds, and leverage AI for security auditing. 

Because of its capabilities, it must be used responsibly.

## 🔴 The Golden Rule
**NEVER scan a target (IP, Domain, or Subnet) without explicit, written authorization from the owner.**

## Acceptable Use Cases
- **Authorized Penetration Testing**: Scanning client networks under a signed Statement of Work (SOW) or Rules of Engagement (RoE).
- **Internal Security Auditing**: Scanning your own home network, lab environment, or corporate infrastructure (with permission).
- **Capture The Flag (CTF)**: Using the tool against designated target machines in environments like HackTheBox or TryHackMe.
- **Bug Bounty Programs**: Scanning in-scope assets on platforms like HackerOne or Bugcrowd, strictly adhering to the program's defined scope and rate limits.

## Unacceptable Use Cases
- **Random Internet Scanning**: Do not run the tool against random public IPs or domains to "see what's out there."
- **Malicious Reconnaissance**: Do not use the tool as a precursor to unauthorized exploitation, DDoS, or data exfiltration.
- **Denial of Service (DoS)**: While SentinelRecon is a passive/active scanner (not a DoS tool), aggressive UDP scanning or extremely high-rate SYN scanning can disrupt fragile legacy IoT systems. Always tune your scans appropriately.

## Built-in Safety Mechanisms
SentinelRecon includes several features to promote safe usage:
1. **Consent Prompt**: By default, the CLI requires the user to explicitly type `yes` to confirm they have authorization before a scan initiates.
2. **Private IP Filtering**: The `ThreatIntelManager` automatically aborts external API queries (AbuseIPDB, VirusTotal) for private IP ranges (e.g., `192.168.x.x`) to prevent leaking internal infrastructure maps to public databases.

## Disclaimer of Liability
The creators and contributors of SentinelRecon AI assume **zero liability** and are not responsible for any misuse, damage, or legal consequences caused by this tool. The end-user is solely responsible for ensuring compliance with all local, state, and federal laws.
