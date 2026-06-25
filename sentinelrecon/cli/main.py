"""
SentinelRecon CLI - Main Entry Point

Usage:
    sentinelrecon scan --target 192.168.1.1
    sentinelrecon history --last 10
    sentinelrecon config --set-api-key
"""

import click
from typing import Optional


@click.group()
@click.version_option(version="1.0.0", prog_name="SentinelRecon")
@click.pass_context
def cli(ctx):
    """
    SentinelRecon - AI-Powered Intelligent Reconnaissance Toolkit
    
    Advanced network reconnaissance with AI-driven vulnerability analysis.
    """
    ctx.ensure_object(dict)


@cli.command()
@click.option('--target', '-t', required=True, help='Target IP, hostname, or CIDR range')
@click.option('--ports', '-p', default='1-1024', help='Port range (e.g., 1-1024 or 22,80,443)')
@click.option('--type', 'scan_type', default='connect', 
              type=click.Choice(['syn', 'connect', 'udp']), 
              help='Scan type')
@click.option('--timeout', default=5, type=int, help='Connection timeout in seconds')
@click.option('--threads', default=10, type=int, help='Number of scanner threads')
@click.option('--banner/--no-banner', default=True, help='Enable banner grabbing')
@click.option('--cve/--no-cve', default=True, help='Enable CVE lookup')
@click.option('--ai/--no-ai', default=True, help='Enable AI analysis')
@click.option('--profile', help='Use saved scan profile')
@click.option('--output', '-o', help='Output directory for reports')
def scan(target: str, ports: str, scan_type: str, timeout: int, threads: int,
         banner: bool, cve: bool, ai: bool, profile: Optional[str], output: Optional[str]):
    """
    Run a reconnaissance scan on target(s).
    
    Examples:
        sentinelrecon scan --target 192.168.1.1
        sentinelrecon scan --target example.com --type syn
        sentinelrecon scan --target 10.0.0.0/24 --ports 22,80,443
    """
    click.echo(f"[*] SentinelRecon Scan")
    click.echo(f"[*] Target: {target}")
    click.echo(f"[*] Ports: {ports}")
    click.echo(f"[*] Scan Type: {scan_type}")
    click.echo(f"[*] Banner Grab: {banner}")
    click.echo(f"[*] CVE Lookup: {cve}")
    click.echo(f"[*] AI Analysis: {ai}")
    click.echo("\n[!] Scan functionality coming in Phase 4...")


@cli.command()
@click.option('--last', type=int, default=10, help='Number of recent scans to show')
@click.option('--target', help='Filter by target')
@click.option('--compare', nargs=2, help='Compare two scans by ID')
def history(last: int, target: Optional[str], compare: Optional[tuple]):
    """
    View scan history and past results.
    
    Examples:
        sentinelrecon history
        sentinelrecon history --last 20
        sentinelrecon history --target 192.168.1.1
        sentinelrecon history --compare scan1_id scan2_id
    """
    click.echo(f"[*] Scan History")
    click.echo(f"[*] Last {last} scans")
    if target:
        click.echo(f"[*] Filtered by target: {target}")
    click.echo("\n[!] History functionality coming in Phase 2...")


@cli.command()
@click.option('--set-api-key', nargs=2, help='Set API key (PROVIDER KEY)')
@click.option('--get-api-key', help='Get API key for provider')
@click.option('--list-profiles', is_flag=True, help='List saved scan profiles')
@click.option('--save-profile', help='Save current config as profile')
@click.option('--provider', default='claude', help='AI provider (claude or openai)')
def config(set_api_key: Optional[tuple], get_api_key: Optional[str], 
           list_profiles: bool, save_profile: Optional[str], provider: str):
    """
    Manage configuration and settings.
    
    Examples:
        sentinelrecon config --set-api-key claude your_api_key_here
        sentinelrecon config --get-api-key claude
        sentinelrecon config --list-profiles
        sentinelrecon config --save-profile my_fast_scan
    """
    click.echo("[*] Configuration Management")
    if set_api_key:
        click.echo(f"[*] Setting API key for {set_api_key[0]}")
    click.echo("\n[!] Config functionality coming in Phase 3...")


@cli.command()
@click.option('--scan-id', required=True, help='Scan ID to regenerate report for')
@click.option('--format', 'report_format', default='html', 
              type=click.Choice(['html', 'pdf', 'json']), 
              help='Report format')
@click.option('--output', '-o', help='Output file path')
def report(scan_id: str, report_format: str, output: Optional[str]):
    """
    Generate or regenerate reports from past scans.
    
    Examples:
        sentinelrecon report --scan-id abc123
        sentinelrecon report --scan-id abc123 --format pdf --output report.pdf
    """
    click.echo(f"[*] Report Generation")
    click.echo(f"[*] Scan ID: {scan_id}")
    click.echo(f"[*] Format: {report_format}")
    click.echo("\n[!] Report functionality coming in Phase 6...")


if __name__ == '__main__':
    cli(obj={})
