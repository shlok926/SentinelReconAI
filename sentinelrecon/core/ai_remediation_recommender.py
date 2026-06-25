"""
AI-powered remediation recommendation engine.
"""
from typing import Dict, List, Optional
from dataclasses import dataclass

from sentinelrecon.core.claude_ai import ClaudeAIAnalyzer
from sentinelrecon.utils.logger import LoggerSetup
from sentinelrecon.utils.exceptions import APIException


@dataclass
class RemediationAction:
    """Single remediation action"""
    title: str
    description: str
    priority: str  # immediate, urgent, high, medium, low
    estimated_hours: int
    tools_needed: List[str]
    risks: List[str]


class AIRemediationRecommender:
    """AI-powered remediation recommendation engine"""

    def __init__(self, api_key: Optional[str] = None, verbose: bool = False):
        """
        Initialize remediation recommender.

        Args:
            api_key: Claude API key
            verbose: Enable verbose logging
        """
        self.logger = LoggerSetup.setup_logger(__name__)
        self.ai = ClaudeAIAnalyzer(api_key, verbose)
        self.verbose = verbose

    def recommend_remediation(
        self,
        vulnerability: Dict,
        environment: Optional[Dict] = None,
    ) -> Dict:
        """
        Generate AI remediation recommendations.

        Args:
            vulnerability: Vulnerability data
            environment: System environment info

        Returns:
            Remediation recommendations
        """
        try:
            # Get AI recommendations
            ai_result = self.ai.recommend_remediation(vulnerability, environment)
            recommendations = ai_result["remediation_plan"]

            # Parse into structured actions
            actions = self._parse_remediation_plan(recommendations)

            return {
                "cve_id": vulnerability.get("cve_id"),
                "service": vulnerability.get("service"),
                "version": vulnerability.get("affected_version"),
                "remediation_plan": recommendations,
                "actions": actions,
                "priority": vulnerability.get("remediation_priority"),
                "timeline_days": vulnerability.get("remediation_timeline_days"),
            }

        except Exception as e:
            self.logger.error(f"Remediation recommendation failed: {e}")
            raise APIException(f"Remediation failed: {str(e)}")

    def recommend_for_multiple(
        self,
        vulnerabilities: List[Dict],
        environment: Optional[Dict] = None,
    ) -> Dict:
        """
        Generate prioritized remediation plan for multiple vulnerabilities.

        Args:
            vulnerabilities: List of vulnerabilities
            environment: System environment

        Returns:
            Consolidated remediation roadmap
        """
        try:
            recommendations = []
            critical_issues = []
            urgent_issues = []
            high_issues = []

            for vuln in vulnerabilities:
                try:
                    rec = self.recommend_remediation(vuln, environment)
                    recommendations.append(rec)

                    # Categorize by priority
                    priority = vuln.get("remediation_priority", "medium").upper()
                    if priority == "IMMEDIATE":
                        critical_issues.append(vuln.get("cve_id"))
                    elif priority == "URGENT":
                        urgent_issues.append(vuln.get("cve_id"))
                    elif priority in ["HIGH"]:
                        high_issues.append(vuln.get("cve_id"))

                except Exception as e:
                    self.logger.warning(f"Failed to recommend for {vuln.get('cve_id')}: {e}")

            # Create remediation roadmap
            roadmap = self._create_remediation_roadmap(
                critical_issues,
                urgent_issues,
                high_issues,
            )

            return {
                "total_vulnerabilities": len(vulnerabilities),
                "recommendations": recommendations,
                "roadmap": roadmap,
                "critical_count": len(critical_issues),
                "urgent_count": len(urgent_issues),
                "high_count": len(high_issues),
            }

        except Exception as e:
            self.logger.error(f"Multi-remediation failed: {e}")
            raise APIException(f"Multi-remediation failed: {str(e)}")

    def generate_remediation_timeline(
        self,
        vulnerabilities: List[Dict],
    ) -> Dict:
        """
        Generate realistic remediation timeline.

        Args:
            vulnerabilities: List of vulnerabilities

        Returns:
            Timeline with phases
        """
        # Group by timeline requirements
        immediate = [v for v in vulnerabilities if v.get("remediation_timeline_days", 30) <= 1]
        urgent = [v for v in vulnerabilities if 1 < v.get("remediation_timeline_days", 30) <= 3]
        high = [v for v in vulnerabilities if 3 < v.get("remediation_timeline_days", 30) <= 7]
        medium = [v for v in vulnerabilities if v.get("remediation_timeline_days", 30) > 7]

        timeline = {
            "phase_1_immediate_0_1_days": {
                "vulnerabilities": [v.get("cve_id") for v in immediate],
                "count": len(immediate),
                "focus": "Critical vulnerabilities requiring immediate action",
                "actions": [
                    "Implement emergency patches",
                    "Deploy temporary mitigations",
                    "Enable enhanced monitoring",
                    "Notify stakeholders",
                ],
            },
            "phase_2_urgent_1_3_days": {
                "vulnerabilities": [v.get("cve_id") for v in urgent],
                "count": len(urgent),
                "focus": "High-risk vulnerabilities needing quick remediation",
                "actions": [
                    "Prepare patch deployment",
                    "Test in staging",
                    "Schedule maintenance windows",
                    "Update runbooks",
                ],
            },
            "phase_3_high_3_7_days": {
                "vulnerabilities": [v.get("cve_id") for v in high],
                "count": len(high),
                "focus": "Medium-risk issues for planned remediation",
                "actions": [
                    "Coordinate with teams",
                    "Plan upgrades",
                    "Test compatibility",
                    "Schedule deployments",
                ],
            },
            "phase_4_medium_7_30_days": {
                "vulnerabilities": [v.get("cve_id") for v in medium],
                "count": len(medium),
                "focus": "Lower-priority items for regular update cycles",
                "actions": [
                    "Include in standard updates",
                    "Monitor for exploits",
                    "Document changes",
                    "Track completion",
                ],
            },
        }

        return {
            "timeline": timeline,
            "total_phases": 4,
            "critical_path_days": 1 if immediate else (3 if urgent else 7),
            "estimated_completion_days": 30,
        }

    def get_remediation_checklist(
        self,
        vulnerability: Dict,
    ) -> Dict:
        """
        Generate remediation checklist.

        Args:
            vulnerability: Vulnerability data

        Returns:
            Step-by-step checklist
        """
        try:
            # Get remediation details
            rec = self.recommend_remediation(vulnerability)
            plan = rec["remediation_plan"]

            # Create checklist items
            checklist = {
                "vulnerability_id": vulnerability.get("cve_id"),
                "service": vulnerability.get("service"),
                "priority": vulnerability.get("remediation_priority"),
                "estimated_hours": 2,  # Default estimate
                "steps": [
                    {
                        "number": 1,
                        "title": "Assessment",
                        "tasks": [
                            "Verify vulnerability impact",
                            "Check patch availability",
                            "Assess dependencies",
                            "Plan implementation",
                        ],
                        "owner": "Security Team",
                        "completed": False,
                    },
                    {
                        "number": 2,
                        "title": "Preparation",
                        "tasks": [
                            "Backup current configuration",
                            "Document baseline metrics",
                            "Prepare rollback plan",
                            "Communicate to stakeholders",
                        ],
                        "owner": "Operations Team",
                        "completed": False,
                    },
                    {
                        "number": 3,
                        "title": "Implementation",
                        "tasks": [
                            "Apply patch/upgrade",
                            "Verify functionality",
                            "Monitor system metrics",
                            "Test affected services",
                        ],
                        "owner": "Operations Team",
                        "completed": False,
                    },
                    {
                        "number": 4,
                        "title": "Validation",
                        "tasks": [
                            "Confirm vulnerability is patched",
                            "Run security validation",
                            "Performance verification",
                            "Update documentation",
                        ],
                        "owner": "Security Team",
                        "completed": False,
                    },
                    {
                        "number": 5,
                        "title": "Closure",
                        "tasks": [
                            "Archive evidence",
                            "Update vulnerability tracker",
                            "Conduct retrospective",
                            "Archive documentation",
                        ],
                        "owner": "Security Team",
                        "completed": False,
                    },
                ],
                "plan_summary": plan[:500],  # Summary of AI recommendation
            }

            return checklist

        except Exception as e:
            self.logger.warning(f"Checklist generation failed: {e}")
            return {
                "error": str(e),
                "vulnerability_id": vulnerability.get("cve_id"),
            }

    def _parse_remediation_plan(self, plan: str) -> List[Dict]:
        """Parse remediation plan into actions."""
        actions = []
        sections = plan.split("\n")

        for section in sections:
            section = section.strip()
            if section and len(section) > 10:
                actions.append({
                    "description": section,
                    "completed": False,
                })

        return actions

    def _create_remediation_roadmap(
        self,
        critical: List[str],
        urgent: List[str],
        high: List[str],
    ) -> Dict:
        """Create remediation roadmap."""
        return {
            "phases": [
                {
                    "phase": "Immediate (0-1 days)",
                    "focus": "Critical issues",
                    "items": critical,
                    "objectives": [
                        "Contain critical vulnerabilities",
                        "Implement emergency mitigations",
                        "Enable enhanced monitoring",
                    ],
                },
                {
                    "phase": "Urgent (1-3 days)",
                    "focus": "High-risk issues",
                    "items": urgent,
                    "objectives": [
                        "Deploy verified patches",
                        "Complete planned upgrades",
                        "Update security controls",
                    ],
                },
                {
                    "phase": "High Priority (3-7 days)",
                    "focus": "Medium-risk issues",
                    "items": high,
                    "objectives": [
                        "Systematic remediation",
                        "Dependency resolution",
                        "Testing and validation",
                    ],
                },
            ],
            "success_criteria": [
                "All critical issues remediated",
                "No exploitable vulnerabilities",
                "Systems operational and monitored",
                "Evidence archived and validated",
            ],
        }
