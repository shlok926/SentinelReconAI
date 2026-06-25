"""
SentinelRecon Orchestrator - Central Coordinator
Sequences all scanning, analysis, and reporting steps
"""

import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from datetime import datetime

# Import all our modules
try:
    from sentinelrecon.core.scanner import PortScanner
    from sentinelrecon.core.banner_grabber import BannerGrabber
    from sentinelrecon.core.service_detector import ServiceDetector
    from sentinelrecon.core.cve_lookup import CVELookup
    from sentinelrecon.core.risk_scorer import RiskScorer
    from sentinelrecon.core.claude_ai import ClaudeAIAnalyzer
    from sentinelrecon.reports.report_generator import ReportGenerator
    # Assuming Database is in sentinelrecon.data.database
    from sentinelrecon.data.database import Database
except ImportError:
    pass # Will handle gracefully if some modules are mocked/missing


@dataclass
class ScanReport:
    """Dataclass holding the full report of a scan."""
    target: str
    scan_type: str
    started_at: str
    completed_at: str
    port_results: List[Dict[str, Any]]
    cve_results: Dict[str, Any]
    ai_analysis: Any
    risk_score: Any
    report_paths: List[str]


class ScanOrchestrator:
    """
    Central coordinator for the entire reconnaissance workflow.
    """
    
    def __init__(self, global_config: Optional[Dict] = None):
        """
        Initialize the orchestrator with global configuration (API keys, etc.)
        """
        self.global_config = global_config or {}
        self.logger = logging.getLogger("SentinelRecon.Orchestrator")
        
        # Initialize modules (delaying exact instantiation to handle missing dependencies gracefully)
        self.scanner = None
        self.banner_grabber = None
        self.service_detector = None
        self.cve_lookup = None
        self.risk_scorer = None
        self.ai_analyzer = None
        self.report_generator = None
        self.db = None
        
        self._initialize_modules()

    def _initialize_modules(self):
        """Initialize all backend modules."""
        try:
            from sentinelrecon.core.scanner import PortScanner
            self.scanner = PortScanner()
        except ImportError:
            self.logger.warning("PortScanner module not found.")

        try:
            from sentinelrecon.core.banner_grabber import BannerGrabber
            self.banner_grabber = BannerGrabber()
        except ImportError:
            self.logger.warning("BannerGrabber module not found.")

        try:
            from sentinelrecon.core.service_detector import ServiceDetector
            self.service_detector = ServiceDetector()
        except ImportError:
            self.logger.warning("ServiceDetector module not found.")

        try:
            from sentinelrecon.core.cve_lookup import CVELookup
            self.cve_lookup = CVELookup()
        except ImportError:
            self.logger.warning("CVELookup module not found.")

        try:
            from sentinelrecon.core.risk_scorer import RiskScorer
            self.risk_scorer = RiskScorer()
        except ImportError:
            self.logger.warning("RiskScorer module not found.")

        try:
            from sentinelrecon.core.claude_ai import ClaudeAIAnalyzer
            # Expecting API key to be in env or config, ClaudeAIAnalyzer usually handles fetching it
            self.ai_analyzer = ClaudeAIAnalyzer() 
        except ImportError:
            self.logger.warning("ClaudeAIAnalyzer module not found.")

        try:
            from sentinelrecon.reports.report_generator import ReportGenerator
            self.report_generator = ReportGenerator()
        except ImportError:
            self.logger.warning("ReportGenerator module not found.")

        try:
            from sentinelrecon.data.database import Database
            self.db = Database()
        except ImportError:
            self.logger.warning("Database module not found.")

    def run_scan(self, target: str, config: Dict[str, Any]) -> ScanReport:
        """
        Main entry point for running a complete reconnaissance scan.
        
        Args:
            target: IP address, hostname, or CIDR range
            config: Dictionary containing scan configuration:
                - ports: str (e.g. "1-1024")
                - scan_type: str ("syn", "connect", "udp")
                - banner: bool
                - cve: bool
                - ai: bool
                - output_dir: str
                - formats: list of str
                - mode: str ("expert", "beginner")
                
        Returns:
            ScanReport dataclass
        """
        started_at = datetime.now().isoformat()
        self.logger.info(f"Starting scan on target: {target}")
        
        # 1. Validate Target (Simplified for orchestrator, usually handled in scanner or CLI)
        if not target:
            raise ValueError("Target must be specified.")
            
        # 2. Port Scanning
        port_results = []
        try:
            if self.scanner:
                # Parse ports
                port_str = config.get('ports', '1-1024')
                port_range_start, port_range_end = 1, 1024
                if '-' in port_str:
                    parts = port_str.split('-')
                    port_range_start, port_range_end = int(parts[0]), int(parts[1])
                
                scan_type = config.get('scan_type', 'connect')
                self.logger.info(f"Running {scan_type} scan on ports {port_str}")
                
                from sentinelrecon.core.scanner import ScanType
                scan_enum = ScanType(scan_type.lower()) if isinstance(scan_type, str) else scan_type
                port_list = list(range(port_range_start, port_range_end + 1))
                
                raw_ports_dict = self.scanner.scan(target, port_list, scan_type=scan_enum)
                raw_ports = raw_ports_dict.values() if isinstance(raw_ports_dict, dict) else raw_ports_dict
                
                # Normalizing results to dict if needed
                for p in raw_ports:
                    port_results.append({
                        'port': getattr(p, 'port', p.get('port', 0) if isinstance(p, dict) else p),
                        'protocol': getattr(p, 'protocol', p.get('protocol', 'tcp') if isinstance(p, dict) else 'tcp'),
                        'state': getattr(p, 'state', p.get('state', 'open') if isinstance(p, dict) else 'open')
                    })
            else:
                self.logger.warning("Scanner not loaded, skipping port scan.")
        except Exception as e:
            self.logger.error(f"Port scanning failed: {e}")

        # 3. Banner Grabbing & 4. Service Detection
        if config.get('banner', True) and self.banner_grabber and self.service_detector:
            for port_info in port_results:
                if port_info.get('state') == 'open':
                    try:
                        port_num = port_info['port']
                        banner = self.banner_grabber.grab(target, port_num)
                        port_info['banner'] = banner
                        
                        service_info = self.service_detector.detect(port_num, banner)
                        # Assuming service_info is a dict or object with name and version
                        if isinstance(service_info, dict):
                            port_info['service_name'] = service_info.get('name', 'unknown')
                            port_info['service_version'] = service_info.get('version', '')
                        else:
                            port_info['service_name'] = getattr(service_info, 'name', 'unknown')
                            port_info['service_version'] = getattr(service_info, 'version', '')
                            
                    except Exception as e:
                        self.logger.error(f"Service detection failed for port {port_info.get('port')}: {e}")

        # 5. CVE Lookup
        cve_results = {}
        if config.get('cve', True) and self.cve_lookup:
            for port_info in port_results:
                service = port_info.get('service_name')
                version = port_info.get('service_version')
                if service and service != 'unknown' and version:
                    try:
                        port_cves = self.cve_lookup.lookup_by_service(service, version)
                        if port_cves:
                            # Convert CVE objects to dicts if they aren't already
                            cve_results[str(port_info['port'])] = [
                                c.__dict__ if hasattr(c, '__dict__') else c for c in port_cves
                            ]
                    except Exception as e:
                        self.logger.error(f"CVE lookup failed for {service} {version}: {e}")

        # 6. Risk Scoring
        risk_score = {'overall_score': 0, 'label': 'INFO'}
        if self.risk_scorer and cve_results:
            try:
                # Passing findings to risk scorer, exact signature based on Phase 5
                # We'll use a mocked calculation if the exact method differs
                if hasattr(self.risk_scorer, 'calculate_system_risk'):
                    # The Phase 5 script uses calculate_system_risk
                    risk_assessment = self.risk_scorer.calculate_system_risk(cve_results)
                    risk_score = {
                        'overall_score': getattr(risk_assessment, 'overall_score', 0),
                        'label': getattr(risk_assessment, 'level', 'INFO')
                    }
                else:
                    risk_score = self.risk_scorer.score_host(port_results, cve_results)
            except Exception as e:
                self.logger.error(f"Risk scoring failed: {e}")

        # 7. AI Analysis
        ai_analysis = None
        if config.get('ai', True) and self.ai_analyzer:
            try:
                # Prepare findings summary for AI
                findings_summary = {
                    'target': target,
                    'ports': port_results,
                    'cves': cve_results,
                    'risk': risk_score
                }
                
                # Check if it's the Phase 6 AIVulnerabilityAnalyzer or ClaudeAIAnalyzer
                if hasattr(self.ai_analyzer, 'assess_security_posture'):
                    ai_analysis = self.ai_analyzer.assess_security_posture(findings_summary)
                elif hasattr(self.ai_analyzer, 'analyze'):
                    ai_analysis = self.ai_analyzer.analyze(target, port_results, cve_results)
            except Exception as e:
                self.logger.error(f"AI analysis failed: {e}")

        completed_at = datetime.now().isoformat()

        # Build scan_data dict for reporting
        scan_data = {
            'target': target,
            'target_input': target,
            'scan_type': config.get('scan_type', 'connect'),
            'started_at': started_at,
            'completed_at': completed_at,
            'port_results': port_results,
            'cve_results': cve_results,
            'ai_analysis': ai_analysis,
            'risk_score': risk_score,
            'port_range_start': port_range_start,
            'port_range_end': port_range_end
        }

        # 8. Report Generation
        report_paths = []
        if self.report_generator:
            output_dir = config.get('output_dir', './output')
            formats = config.get('formats', ['html', 'pdf'])
            
            for fmt in formats:
                try:
                    fmt = fmt.strip().lower()
                    if fmt == 'html':
                        content = self.report_generator.generate_html(scan_data)
                        path = self.report_generator.save(content, 'html', output_dir)
                        report_paths.append(path)
                    elif fmt == 'pdf':
                        content = self.report_generator.generate_pdf(scan_data)
                        path = self.report_generator.save(content, 'pdf', output_dir)
                        report_paths.append(path)
                    elif fmt == 'json':
                        content = self.report_generator.generate_json(scan_data)
                        path = self.report_generator.save(content, 'json', output_dir)
                        report_paths.append(path)
                except Exception as e:
                    self.logger.error(f"Report generation for {fmt} failed: {e}")

        # 9. Database Persistence
        if self.db:
            try:
                db_scan_data = scan_data.copy()
                db_scan_data['risk_score'] = risk_score.get('overall_score', 0.0)
                db_scan_data['risk_label'] = risk_score.get('label', 'INFO')
                self.db.save_scan(db_scan_data)
            except Exception as e:
                self.logger.error(f"Database persistence failed: {e}")

        # 10. Return ScanReport
        return ScanReport(
            target=target,
            scan_type=config.get('scan_type', 'connect'),
            started_at=started_at,
            completed_at=completed_at,
            port_results=port_results,
            cve_results=cve_results,
            ai_analysis=ai_analysis,
            risk_score=risk_score,
            report_paths=report_paths
        )
