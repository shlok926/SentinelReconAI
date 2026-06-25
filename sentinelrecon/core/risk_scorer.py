"""
Risk scoring module for vulnerability assessment and prioritization.
"""
from typing import Dict, List, Optional, Tuple
from enum import Enum
from sentinelrecon.utils.logger import LoggerSetup


class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskScorer:
    """Calculate risk scores for vulnerabilities and systems"""

    # Weights for different risk factors
    CVSS_WEIGHT = 0.4  # 40% - CVSS score is primary factor
    EXPLOITABILITY_WEIGHT = 0.25  # 25% - Ease of exploitation
    SERVICE_WEIGHT = 0.15  # 15% - Service criticality
    PORT_WEIGHT = 0.1  # 10% - Port exposure
    EXPOSURE_WEIGHT = 0.1  # 10% - Number of affected assets

    # Service criticality scores (0-10)
    SERVICE_CRITICALITY = {
        # Authentication/Access
        "ssh": 9.0,
        "rdp": 9.0,
        "telnet": 8.5,
        "vnc": 8.5,

        # Web services
        "http": 8.0,
        "https": 8.0,
        "http-alt": 7.5,

        # Databases
        "mysql": 8.5,
        "postgresql": 8.5,
        "mongodb": 8.5,
        "redis": 7.5,
        "couchdb": 7.0,

        # File/Mail services
        "ftp": 7.0,
        "smtp": 6.5,
        "pop3": 6.0,
        "imap": 6.0,

        # Network/System services
        "dns": 7.5,
        "ldap": 7.0,
        "smb": 8.0,

        # Search/APIs
        "elasticsearch": 8.0,

        # Default
        "unknown": 5.0,
    }

    # Port exposure scores (0-10)
    # Well-known ports = higher exposure
    PORT_EXPOSURE = {
        # Immediately exploitable
        22: 10.0,  # SSH
        80: 10.0,  # HTTP
        443: 9.5,  # HTTPS
        3306: 9.0,  # MySQL
        5432: 9.0,  # PostgreSQL
        27017: 9.0,  # MongoDB
        6379: 8.5,  # Redis
        389: 8.0,  # LDAP
        445: 9.0,  # SMB
        3389: 9.0,  # RDP
        23: 8.5,  # Telnet
        21: 7.5,  # FTP
        25: 7.0,  # SMTP
        53: 7.5,  # DNS
        5984: 7.0,  # CouchDB
        9200: 8.5,  # Elasticsearch
        139: 8.5,  # NetBIOS
        # Default for unknown ports
        "default": 5.0,
    }

    # Exploitability scores for severity levels (0-10)
    SEVERITY_EXPLOITABILITY = {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 6.0,
        "LOW": 3.0,
        "NONE": 0.0,
    }

    def __init__(self, verbose: bool = False):
        """
        Initialize risk scorer.

        Args:
            verbose: Enable verbose logging
        """
        self.logger = LoggerSetup.setup_logger(__name__)
        self.verbose = verbose

    def calculate_vulnerability_risk(
        self,
        cvss_score: float,
        severity: str,
        affected_service: str,
        affected_port: int,
        num_affected_hosts: int = 1,
    ) -> Dict:
        """
        Calculate risk score for a vulnerability.

        Args:
            cvss_score: CVSS score (0-10)
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, NONE)
            affected_service: Service name
            affected_port: Port number
            num_affected_hosts: Number of affected hosts

        Returns:
            Risk assessment dictionary
        """
        # Normalize CVSS score to 0-10 range
        cvss_normalized = max(0.0, min(10.0, cvss_score))

        # Get component scores
        cvss_factor = self._get_cvss_factor(cvss_normalized)
        exploitability_factor = self._get_exploitability_factor(severity)
        service_factor = self._get_service_factor(affected_service)
        port_factor = self._get_port_factor(affected_port)
        exposure_factor = self._get_exposure_factor(num_affected_hosts)

        # Calculate weighted risk score
        risk_score = (
            (cvss_factor * self.CVSS_WEIGHT) +
            (exploitability_factor * self.EXPLOITABILITY_WEIGHT) +
            (service_factor * self.SERVICE_WEIGHT) +
            (port_factor * self.PORT_WEIGHT) +
            (exposure_factor * self.EXPOSURE_WEIGHT)
        )

        # Clamp to 0-100 range
        risk_score = max(0.0, min(100.0, risk_score * 10))

        # Determine risk level
        risk_level = self._score_to_level(risk_score)

        if self.verbose:
            self.logger.debug(
                f"Risk calculation for {affected_service}:{affected_port} - "
                f"CVSS: {cvss_normalized}, Score: {risk_score:.1f}, Level: {risk_level}"
            )

        return {
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level,
            "cvss_score": cvss_normalized,
            "severity": severity,
            "components": {
                "cvss_factor": round(cvss_factor, 2),
                "exploitability_factor": round(exploitability_factor, 2),
                "service_factor": round(service_factor, 2),
                "port_factor": round(port_factor, 2),
                "exposure_factor": round(exposure_factor, 2),
            },
        }

    def calculate_system_risk(
        self,
        findings: List[Dict],
    ) -> Dict:
        """
        Calculate overall system risk from multiple findings.

        Args:
            findings: List of vulnerability findings with risk data

        Returns:
            System risk assessment

        Raises:
            ValueError: If findings list is empty
        """
        if not findings:
            raise ValueError("No findings provided")

        risk_scores = [f.get("risk_score", 0) for f in findings]
        risk_levels = [f.get("risk_level", "INFO") for f in findings]

        # Calculate metrics
        total_score = sum(risk_scores)
        max_score = max(risk_scores) if risk_scores else 0
        avg_score = total_score / len(findings) if findings else 0

        # Count by severity
        level_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for level in risk_levels:
            level_lower = level.lower() if level else "info"
            if level_lower in level_counts:
                level_counts[level_lower] += 1

        # Determine overall system risk level
        if level_counts["critical"] > 0:
            system_risk_level = "CRITICAL"
        elif level_counts["high"] > 0:
            system_risk_level = "HIGH"
        elif level_counts["medium"] > 0:
            system_risk_level = "MEDIUM"
        else:
            system_risk_level = "LOW"

        # Calculate system score (normalized)
        system_score = (max_score * 0.5) + (avg_score * 0.5)
        system_score = min(100.0, system_score * 1.2)  # Slight boost for multiple findings

        return {
            "system_risk_score": round(system_score, 2),
            "system_risk_level": system_risk_level,
            "total_findings": len(findings),
            "findings_by_level": {
                "critical": level_counts["critical"],
                "high": level_counts["high"],
                "medium": level_counts["medium"],
                "low": level_counts["low"],
                "info": level_counts["info"],
            },
            "max_vulnerability_score": round(max_score, 2),
            "avg_vulnerability_score": round(avg_score, 2),
            "total_risk_score": round(total_score, 2),
        }

    def prioritize_findings(
        self,
        findings: List[Dict],
        limit: Optional[int] = None,
    ) -> List[Dict]:
        """
        Prioritize findings by risk score.

        Args:
            findings: List of findings
            limit: Maximum number of results

        Returns:
            Sorted list of findings
        """
        sorted_findings = sorted(
            findings,
            key=lambda x: x.get("risk_score", 0),
            reverse=True,
        )

        if limit:
            sorted_findings = sorted_findings[:limit]

        return sorted_findings

    def get_remediation_priority(self, risk_score: float) -> Dict:
        """
        Get remediation recommendations based on risk score.

        Args:
            risk_score: Risk score (0-100)

        Returns:
            Remediation recommendations
        """
        if risk_score >= 80:
            return {
                "priority": "IMMEDIATE",
                "timeline_days": 1,
                "actions": [
                    "Isolate affected system immediately",
                    "Apply security patch or mitigation",
                    "Monitor for exploitation attempts",
                    "Review access logs",
                ],
            }
        elif risk_score >= 60:
            return {
                "priority": "URGENT",
                "timeline_days": 3,
                "actions": [
                    "Schedule immediate patching",
                    "Implement network controls",
                    "Review system logs",
                    "Prepare patch deployment",
                ],
            }
        elif risk_score >= 40:
            return {
                "priority": "HIGH",
                "timeline_days": 7,
                "actions": [
                    "Plan security updates",
                    "Review vulnerability details",
                    "Implement mitigations if available",
                    "Schedule maintenance window",
                ],
            }
        elif risk_score >= 20:
            return {
                "priority": "MEDIUM",
                "timeline_days": 30,
                "actions": [
                    "Schedule routine patching",
                    "Document vulnerability details",
                    "Monitor for exploits",
                ],
            }
        else:
            return {
                "priority": "LOW",
                "timeline_days": 90,
                "actions": [
                    "Include in regular updates",
                    "Monitor CVE publications",
                ],
            }

    def _get_cvss_factor(self, cvss_score: float) -> float:
        """Convert CVSS score to 0-10 factor."""
        return cvss_score

    def _get_exploitability_factor(self, severity: str) -> float:
        """Get exploitability factor from severity."""
        return self.SEVERITY_EXPLOITABILITY.get(severity, 0.0)

    def _get_service_factor(self, service: str) -> float:
        """Get service criticality factor."""
        return self.SERVICE_CRITICALITY.get(
            service.lower(),
            self.SERVICE_CRITICALITY["unknown"],
        )

    def _get_port_factor(self, port: int) -> float:
        """Get port exposure factor."""
        return self.PORT_EXPOSURE.get(port, self.PORT_EXPOSURE["default"])

    def _get_exposure_factor(self, num_hosts: int) -> float:
        """Get exposure factor based on number of affected hosts."""
        # More hosts = higher exposure
        if num_hosts >= 100:
            return 10.0
        elif num_hosts >= 50:
            return 9.0
        elif num_hosts >= 10:
            return 7.5
        elif num_hosts >= 5:
            return 5.0
        elif num_hosts >= 2:
            return 3.0
        else:
            return 1.0

    def _score_to_level(self, score: float) -> str:
        """Convert numeric score to risk level."""
        if score >= 80:
            return RiskLevel.CRITICAL.value
        elif score >= 60:
            return RiskLevel.HIGH.value
        elif score >= 40:
            return RiskLevel.MEDIUM.value
        elif score >= 20:
            return RiskLevel.LOW.value
        else:
            return RiskLevel.INFO.value

    def score_comparison(
        self,
        risk1: Dict,
        risk2: Dict,
    ) -> Dict:
        """
        Compare two risk assessments.

        Args:
            risk1: First risk assessment
            risk2: Second risk assessment

        Returns:
            Comparison analysis
        """
        score_diff = risk1.get("risk_score", 0) - risk2.get("risk_score", 0)
        level_diff = 0

        levels = [RiskLevel.INFO.value, RiskLevel.LOW.value, RiskLevel.MEDIUM.value,
                  RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]

        try:
            level_diff = (
                levels.index(risk1.get("risk_level", "INFO")) -
                levels.index(risk2.get("risk_level", "INFO"))
            )
        except ValueError:
            pass

        return {
            "score_difference": round(score_diff, 2),
            "level_difference": level_diff,
            "risk1_higher": score_diff > 0,
            "percentage_increase": (
                (score_diff / risk2.get("risk_score", 1)) * 100
                if risk2.get("risk_score", 0) > 0
                else 0
            ),
        }
