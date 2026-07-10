import click
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from typing import Optional
from sentinelrecon.orchestrator import ScanOrchestrator
from sentinelrecon.cli.display import (
    print_banner, print_scan_header, print_port_table, 
    print_cve_table, print_ai_summary, print_risk_score, 
    print_report_saved, print_threat_intel
)

console = Console()

@click.command()
@click.option('--target', '-t', required=True, help='Target IP, hostname, or CIDR range')
@click.option('--ports', '-p', default='1-1024', help='Port range (format: "start-end" or "80,443,8080")')
@click.option('--type', 'scan_type', default='connect', 
              type=click.Choice(['syn', 'connect', 'udp']), 
              help='Scan type')
@click.option('--banner/--no-banner', default=True, help='Enable banner grabbing')
@click.option('--ai/--no-ai', default=True, help='Enable AI analysis')
@click.option('--cve/--no-cve', default=True, help='Enable CVE lookup')
@click.option('--output', '-o', default='./output', help='Output directory for reports')
@click.option('--format', 'report_format', default='html,pdf', help='Report formats (e.g., "html,pdf,json")')
@click.option('--mode', default='expert', type=click.Choice(['beginner', 'expert']), help='AI Analysis mode')
@click.option('--profile', help='Use a saved scan profile name')
@click.option('--cloud', type=click.Choice(['aws', 'azure', 'gcp']), help='Scan cloud infrastructure')
@click.option('--aws-access-key', envvar='AWS_ACCESS_KEY_ID', help='AWS access key')
@click.option('--aws-secret-key', envvar='AWS_SECRET_ACCESS_KEY', help='AWS secret key')
@click.option('--aws-region', default='us-east-1', help='AWS region')
@click.option('--azure-subscription', help='Azure subscription ID')
@click.option('--azure-client-id', help='Azure client ID')
@click.option('--azure-client-secret', help='Azure client secret')
@click.option('--azure-tenant', help='Azure tenant ID')
@click.option('--gcp-project', help='GCP project ID')
def scan(target: str, ports: str, scan_type: str, banner: bool, ai: bool, 
         cve: bool, output: str, report_format: str, mode: str, profile: Optional[str],
         cloud: Optional[str], aws_access_key: Optional[str], aws_secret_key: Optional[str],
         aws_region: Optional[str], azure_subscription: Optional[str], azure_client_id: Optional[str],
         azure_client_secret: Optional[str], azure_tenant: Optional[str], gcp_project: Optional[str]):
    """
    Run an intelligent reconnaissance scan on target(s).
    """
    print_banner()
    
    # Ethical Use Warning
    warning_text = (
        "[bold red]ETHICAL USE WARNING:[/bold red]\n"
        "SentinelRecon is a powerful network reconnaissance tool. "
        "Scanning targets without explicit permission is illegal and unethical.\n\n"
        f"Ensure you have authorization to scan the target: [bold yellow]{target}[/bold yellow]."
    )
    console.print(Panel(warning_text, title="Warning", border_style="red"))
    
    confirm = Prompt.ask("Do you have permission to scan this target? Type 'yes' to continue")
    if confirm.strip().lower() != 'yes':
        console.print("[bold red]Scan aborted by user.[/bold red]")
        return

    print_scan_header(target, scan_type, ports)
    
    # Run Orchestrator
    config = {
        'ports': ports,
        'scan_type': scan_type,
        'banner': banner,
        'ai': ai,
        'cve': cve,
        'output_dir': output,
        'formats': report_format.split(','),
        'mode': mode,
        'profile': profile,
        'cloud_scan': cloud,
        'aws_access_key': aws_access_key,
        'aws_secret_key': aws_secret_key,
        'aws_region': aws_region,
        'azure_subscription_id': azure_subscription,
        'azure_client_id': azure_client_id,
        'azure_client_secret': azure_client_secret,
        'azure_tenant_id': azure_tenant,
        'gcp_project_id': gcp_project
    }
    
    orchestrator = ScanOrchestrator()
    results = None
    
    # Rich status spinner
    with console.status("[bold cyan]Running SentinelRecon analysis...[/bold cyan]") as status:
        try:
            results = orchestrator.run_scan(target=target, config=config)
        except Exception as e:
            console.print(f"[bold red]An error occurred during scanning: {str(e)}[/bold red]")
            return

    # Display Results using Rich Display UI
    if results:
        console.print("\n[bold green]Scan and analysis completed successfully![/bold green]\n")
        
        # 1. Print Open Ports
        print_port_table(results.port_results)
        
        # 1.5 Print Threat Intel
        if getattr(results, 'threat_intel', None):
            print_threat_intel(results.threat_intel)
            
        # 1.8 Print Cloud Findings
        if getattr(results, 'cloud_findings', None):
            console.print(Panel(f"Cloud Risk Score: {results.cloud_findings.overall_risk_score}/100", title=f"{results.cloud_findings.cloud_provider} Cloud Findings", border_style="cyan"))
        
        # 2. Print CVEs (Flattening the dict for the table)
        if results.cve_results:
            all_cves = []
            for port, cves in results.cve_results.items():
                all_cves.extend(cves)
            print_cve_table(all_cves)
            
        # 3. Print Risk Score
        print_risk_score(results.risk_score)
        
        # 4. Print AI Summary
        if results.ai_analysis:
            print_ai_summary(results.ai_analysis)
            
        # 5. Print Output Paths
        print_report_saved(results.report_paths)
