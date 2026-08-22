# SentinelRecon API Reference

This document provides a high-level overview of the internal APIs and modules used within SentinelRecon AI. It is intended for developers who want to extend or integrate the toolkit into other pipelines.

## Core Modules

### `ScanOrchestrator`
The central brain of the application. It coordinates the execution sequence: Scanning -> Threat Intel -> AI Analysis -> Reporting.
- **Location**: `sentinelrecon/orchestrator.py`
- **Primary Method**: `run_scan(target: str, ports: list, scan_type: str, skip_ai: bool)`
- **Returns**: A populated `ScanReport` dataclass.

### `ThreatIntelManager`
Handles all external OSINT API communications.
- **Location**: `sentinelrecon/core/threat_intel.py`
- **Primary Method**: `analyze_target(target: str)`
- **Behavior**: Automatically skips RFC1918 private IP addresses. Returns a dictionary containing AbuseIPDB and VirusTotal metrics.

### `ClaudeAIAnalyzer`
Interfaces with the Anthropic Claude API for vulnerability contextualization.
- **Location**: `sentinelrecon/core/claude_ai.py`
- **Primary Method**: `analyze_scan(scan_data: dict)`
- **Behavior**: Compiles raw scan JSON into a system prompt, queries Claude-3, and parses the structured response (Risk Score, Executive Summary, Remediation).

### `ReportGenerator`
Converts internal `ScanReport` objects into shareable HTML/PDF formats.
- **Location**: `sentinelrecon/reports/report_generator.py`
- **Primary Method**: `generate_report(report_data: ScanReport, output_dir: str)`
- **Template**: Uses `sentinelrecon/reports/templates/report.html.j2` for static rendering.

## Extending the Tool
To add a new Threat Intelligence source (e.g., Shodan):
1. Add the API Key variable to `.env.example`.
2. Create a new fetch method in `ThreatIntelManager`.
3. Update the `run_scan` method in `ScanOrchestrator` to include the new data.
4. Update the Jinja2 template to render the new metrics.
