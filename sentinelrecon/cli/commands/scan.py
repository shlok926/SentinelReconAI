import click
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from typing import Optional
from sentinelrecon.orchestrator import ScanOrchestrator

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
def scan(target: str, ports: str, scan_type: str, banner: bool, ai: bool, 
         cve: bool, output: str, report_format: str, mode: str, profile: Optional[str]):
    """
    Run an intelligent reconnaissance scan on target(s).
    """
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

    console.print(f"\n[bold green]Initializing {scan_type.upper()} scan on {target}...[/bold green]")
    
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
        'profile': profile
    }
    
    orchestrator = ScanOrchestrator()
    
    # Rich status spinner
    with console.status("[bold cyan]Running SentinelRecon analysis...[/bold cyan]") as status:
        if ai:
            status.update("[bold cyan]Performing AI-driven vulnerability analysis...[/bold cyan]")
            
        try:
            # Calling the orchestrator (this will be implemented fully in Prompt 12)
            results = orchestrator.run_scan(target=target, config=config)
            console.print("[bold green]Scan and analysis completed successfully![/bold green]")
        except NotImplementedError:
            console.print("[bold yellow]Note: Orchestrator run_scan is not fully implemented yet (Pending Phase 7).[/bold yellow]")
        except Exception as e:
            console.print(f"[bold red]An error occurred during scanning: {str(e)}[/bold red]")
