from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

def get_risk_color(risk_level: str) -> str:
    """Helper to map risk string to Rich color."""
    risk_level = str(risk_level).upper()
    if risk_level == "CRITICAL":
        return "bold red"
    elif risk_level == "HIGH":
        return "orange1"
    elif risk_level == "MEDIUM":
        return "yellow"
    elif risk_level == "LOW":
        return "green"
    return "cyan"

def print_banner():
    """Prints the ASCII art banner."""
    ascii_art = """
   _____            _   _            _______                     
  / ____|          | | (_)          |  __ \\                    
 | (___   ___ _ __ | |_ _ _ __   ___| |__) |___  ___ ___  _ __ 
  \\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\  _  // _ \\/ __/ _ \\| '_ \\
  ____) |  __/ | | | |_| | | | |  __/ | \\ \\  __/ (_| (_) | | | |
 |_____/ \\___|_| |_|\\__|_|_| |_|\\___|_|  \\_\\___|\\___\\___/|_| |_|
            AI-Powered Intelligent Reconnaissance Toolkit
    """
    console.print(ascii_art, style="bold cyan")

def print_scan_header(target: str, scan_type: str, port_range: str):
    """Prints the scan initialization header."""
    header_text = Text()
    header_text.append("[*] Target      : ", style="bold")
    header_text.append(f"{target}\n", style="cyan")
    header_text.append("[*] Scan Type   : ", style="bold")
    header_text.append(f"{scan_type.upper()}\n", style="cyan")
    header_text.append("[*] Port Range  : ", style="bold")
    header_text.append(f"{port_range}", style="cyan")
    
    console.print(Panel(header_text, title="Scan Details", border_style="blue", box=box.ROUNDED))

def print_port_table(port_results: List[Dict[str, Any]]):
    """Prints the results of the port scan in a formatted table."""
    table = Table(title="Open Ports & Services", box=box.SIMPLE_HEAVY, border_style="blue")
    
    table.add_column("PORT", justify="right", style="cyan", no_wrap=True)
    table.add_column("STATE", style="white")
    table.add_column("SERVICE", style="cyan")
    table.add_column("VERSION", style="white")
    table.add_column("RISK", justify="center")

    if not port_results:
        console.print("[yellow]No open ports found.[/yellow]")
        return

    for result in port_results:
        # Support both dict and object syntax for robustness
        port_num = str(result.get('port', '-')) if isinstance(result, dict) else str(getattr(result, 'port', '-'))
        state = result.get('state', '-') if isinstance(result, dict) else getattr(result, 'state', '-')
        service = result.get('service_name', '-') if isinstance(result, dict) else getattr(result, 'service_name', '-')
        version = result.get('service_version', '-') if isinstance(result, dict) else getattr(result, 'service_version', '-')
        risk = result.get('risk_level', 'INFO') if isinstance(result, dict) else getattr(result, 'risk_level', 'INFO')

        state_val = state.value if hasattr(state, 'value') else str(state)
        color = get_risk_color(risk)
        
        table.add_row(
            port_num,
            state_val.upper(),
            service,
            version,
            f"[{color}]{risk}[/{color}]"
        )
        
    console.print(table)

def print_cve_table(cves: List[Dict[str, Any]]):
    """Prints the CVE findings in a formatted table."""
    if not cves:
        return
        
    table = Table(title="Vulnerability Findings (CVEs)", box=box.SIMPLE_HEAVY, border_style="red")
    
    table.add_column("CVE ID", style="bold red", no_wrap=True)
    table.add_column("SEVERITY", justify="center")
    table.add_column("CVSS", justify="right", style="cyan")
    table.add_column("DESCRIPTION", style="white")

    # Assuming cves might be a list of CVE objects or dicts
    for cve in cves:
        cve_id = cve.get('cve_id', '-') if isinstance(cve, dict) else getattr(cve, 'cve_id', '-')
        severity = cve.get('severity', 'UNKNOWN') if isinstance(cve, dict) else getattr(cve, 'severity', 'UNKNOWN')
        cvss = str(cve.get('cvss_score', '-')) if isinstance(cve, dict) else str(getattr(cve, 'cvss_score', '-'))
        desc = cve.get('description', '-') if isinstance(cve, dict) else getattr(cve, 'description', '-')
        
        # Truncate description for terminal view
        if len(desc) > 80:
            desc = desc[:77] + "..."
            
        color = get_risk_color(severity)
        
        table.add_row(
            cve_id,
            f"[{color}]{severity}[/{color}]",
            cvss,
            desc
        )
        
    console.print(table)

def print_threat_intel(intel_data: Dict[str, Any]):
    """Prints threat intelligence in a panel."""
    if not intel_data or intel_data.get('status') == 'skipped':
        return
        
    abuse = intel_data.get('abuseipdb', {})
    if abuse.get('status') == 'success':
        score = abuse.get('abuse_confidence_score', 0)
        reports = abuse.get('total_reports', 0)
        country = abuse.get('country', 'Unknown')
        
        # Color coding the score
        score_color = "green" if score == 0 else "yellow" if score < 50 else "bold red"
        
        text = Text()
        text.append(f"AbuseIPDB Confidence Score : ", style="bold")
        text.append(f"{score}%\n", style=score_color)
        text.append(f"Total Malicious Reports    : ", style="bold")
        text.append(f"{reports}\n", style="white")
        text.append(f"Origin Country             : ", style="bold")
        text.append(f"{country}", style="white")
        
        console.print(Panel(text, title="[bold magenta]AbuseIPDB[/bold magenta]", border_style="magenta", padding=(1, 2)))
        
    vt = intel_data.get('virustotal', {})
    if vt.get('status') == 'success':
        mal = vt.get('malicious', 0)
        sus = vt.get('suspicious', 0)
        harm = vt.get('harmless', 0)
        net = vt.get('network', 'Unknown')
        
        mal_color = "green" if mal == 0 else "bold red"
        sus_color = "green" if sus == 0 else "yellow"
        
        text = Text()
        text.append(f"Malicious Flags            : ", style="bold")
        text.append(f"{mal}\n", style=mal_color)
        text.append(f"Suspicious Flags           : ", style="bold")
        text.append(f"{sus}\n", style=sus_color)
        text.append(f"Harmless Votes             : ", style="bold")
        text.append(f"{harm}\n", style="green")
        text.append(f"Network Owner              : ", style="bold")
        text.append(f"{net}", style="cyan")
        
        console.print(Panel(text, title="[bold blue]VirusTotal[/bold blue]", border_style="blue", padding=(1, 2)))

def print_ai_summary(ai_analysis: Any):
    """Prints the AI Analysis summary in a styled panel."""
    if not ai_analysis:
        return
        
    # Extract text from object or dict
    if isinstance(ai_analysis, dict):
        text = ai_analysis.get('summary', ai_analysis.get('ai_analysis', str(ai_analysis)))
    elif hasattr(ai_analysis, 'summary'):
        text = ai_analysis.summary
    else:
        text = str(ai_analysis)

    console.print(Panel(text, title="[bold cyan]AI Analysis & Remediation[/bold cyan]", border_style="cyan", padding=(1, 2)))

def print_risk_score(risk_score: Any):
    """Prints the overall risk score."""
    if not risk_score:
        return
        
    score = risk_score.get('overall_score', 0) if isinstance(risk_score, dict) else getattr(risk_score, 'overall_score', 0)
    label = risk_score.get('label', 'INFO') if isinstance(risk_score, dict) else getattr(risk_score, 'label', 'INFO')
    
    color = get_risk_color(label)
    
    text = f"[{color} bold]System Risk Assessment: {score}/100 ({label})[/{color} bold]"
    console.print(Panel(text, title="Risk Score", border_style=color.split()[0], expand=False))

def print_report_saved(paths: List[str]):
    """Prints success message with generated report paths."""
    if not paths:
        return
        
    console.print("\n[bold green][*] Reports Successfully Generated:[/bold green]")
    for path in paths:
        console.print(f"  [cyan]>[/cyan] {path}")
