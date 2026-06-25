"""
Anthropic Claude AI integration for vulnerability analysis.
"""
from typing import Optional, Dict, List
import json
from anthropic import Anthropic

from sentinelrecon.utils.logger import LoggerSetup
from sentinelrecon.utils.config_manager import ConfigManager
from sentinelrecon.utils.exceptions import APIException


class ClaudeAIAnalyzer:
    """Claude AI integration for security analysis"""

    # Model selection
    MODEL = "claude-3-5-sonnet-20241022"  # Latest Claude model
    MAX_TOKENS = 2048

    # System prompts for different analysis types
    SYSTEM_PROMPTS = {
        "vulnerability": """You are an expert cybersecurity analyst specializing in vulnerability assessment. 
Your role is to analyze security vulnerabilities and provide actionable insights.
Provide concise, technical analysis focusing on:
1. Root cause analysis of the vulnerability
2. Attack vector and exploitation likelihood
3. Business impact assessment
4. Immediate mitigation steps
Keep responses focused and technical. Avoid verbose explanations.""",

        "remediation": """You are a senior security engineer providing remediation guidance.
Your role is to recommend prioritized, practical remediation strategies.
For each recommendation provide:
1. Specific technical steps (2-5 steps max)
2. Implementation priority (immediate/urgent/high/medium/low)
3. Estimated effort (hours/days)
4. Tools or resources needed
Be concise and actionable. Focus on practical solutions.""",

        "attack_scenario": """You are a threat intelligence analyst creating attack scenarios.
Your role is to model realistic attack paths and security impacts.
Provide:
1. Attack chain (step-by-step exploitation)
2. Prerequisites for attacker
3. Detection indicators
4. Business impact
5. Required defenses
Keep technical and realistic. Avoid overly complex scenarios.""",

        "security_posture": """You are a security architect assessing organizational posture.
Your role is to evaluate overall security maturity and recommendations.
Analyze:
1. Current security gaps
2. Risk prioritization
3. Capability gaps vs industry baseline
4. Strategic recommendations
5. Roadmap priorities (next 3-6 months)
Be balanced and forward-looking. Provide stakeholder-ready insights.""",
    }

    def __init__(self, api_key: Optional[str] = None, verbose: bool = False):
        """
        Initialize Claude AI analyzer.

        Args:
            api_key: Anthropic API key (uses config if not provided)
            verbose: Enable verbose logging
        """
        self.logger = LoggerSetup.setup_logger(__name__)
        self.verbose = verbose

        # Get API key from config if not provided
        if not api_key:
            config = ConfigManager()
            api_key = config.get_api_key("claude")

        if not api_key:
            raise APIException(
                "Claude API key not found. Set ANTHROPIC_API_KEY environment variable "
                "or use: sentinelrecon config --set-api-key claude <key>"
            )

        self.client = Anthropic(api_key=api_key)
        self.conversation_history = []

    def analyze_vulnerability(
        self,
        vulnerability_data: Dict,
        context: Optional[str] = None,
    ) -> Dict:
        """
        Analyze a vulnerability with AI.

        Args:
            vulnerability_data: Vulnerability details dict
            context: Additional context (e.g., affected systems)

        Returns:
            AI analysis result with insights
        """
        # Build analysis prompt
        prompt = self._build_vulnerability_prompt(vulnerability_data, context)

        # Get AI analysis
        response = self._call_claude(
            prompt,
            system_prompt=self.SYSTEM_PROMPTS["vulnerability"],
        )

        return {
            "vulnerability_id": vulnerability_data.get("cve_id"),
            "ai_analysis": response,
            "model": self.MODEL,
            "analysis_type": "vulnerability",
        }

    def recommend_remediation(
        self,
        vulnerability_data: Dict,
        environment_info: Optional[Dict] = None,
    ) -> Dict:
        """
        Get AI-powered remediation recommendations.

        Args:
            vulnerability_data: Vulnerability details
            environment_info: System/environment details

        Returns:
            Remediation recommendations
        """
        prompt = self._build_remediation_prompt(vulnerability_data, environment_info)

        response = self._call_claude(
            prompt,
            system_prompt=self.SYSTEM_PROMPTS["remediation"],
        )

        return {
            "vulnerability_id": vulnerability_data.get("cve_id"),
            "remediation_plan": response,
            "model": self.MODEL,
            "analysis_type": "remediation",
        }

    def analyze_attack_scenario(
        self,
        vulnerability_data: Dict,
        threat_actor: Optional[str] = None,
    ) -> Dict:
        """
        Generate attack scenario for vulnerability.

        Args:
            vulnerability_data: Vulnerability details
            threat_actor: Type of threat actor (e.g., "cybercriminal", "nation-state")

        Returns:
            Attack scenario analysis
        """
        prompt = self._build_attack_scenario_prompt(vulnerability_data, threat_actor)

        response = self._call_claude(
            prompt,
            system_prompt=self.SYSTEM_PROMPTS["attack_scenario"],
        )

        return {
            "vulnerability_id": vulnerability_data.get("cve_id"),
            "attack_scenario": response,
            "threat_actor": threat_actor or "generic",
            "model": self.MODEL,
            "analysis_type": "attack_scenario",
        }

    def assess_security_posture(
        self,
        findings_summary: Dict,
        organization_context: Optional[str] = None,
    ) -> Dict:
        """
        Assess overall security posture.

        Args:
            findings_summary: Summary of findings (count by severity)
            organization_context: Org details (size, industry, etc.)

        Returns:
            Security posture assessment
        """
        prompt = self._build_posture_prompt(findings_summary, organization_context)

        response = self._call_claude(
            prompt,
            system_prompt=self.SYSTEM_PROMPTS["security_posture"],
        )

        return {
            "posture_assessment": response,
            "model": self.MODEL,
            "analysis_type": "posture",
        }

    def chat(self, message: str, context_type: str = "general") -> str:
        """
        Chat with Claude for general security questions.

        Args:
            message: User question
            context_type: Type of analysis context

        Returns:
            Claude response
        """
        system_prompt = self.SYSTEM_PROMPTS.get(
            context_type,
            "You are a helpful cybersecurity expert.",
        )

        response = self._call_claude(message, system_prompt=system_prompt)
        return response

    def batch_analyze(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Analyze multiple vulnerabilities.

        Args:
            vulnerabilities: List of vulnerability dicts

        Returns:
            List of analysis results
        """
        results = []
        for vuln in vulnerabilities:
            try:
                analysis = self.analyze_vulnerability(vuln)
                results.append(analysis)
            except Exception as e:
                self.logger.warning(f"Failed to analyze {vuln.get('cve_id')}: {e}")
                results.append({
                    "vulnerability_id": vuln.get("cve_id"),
                    "error": str(e),
                })

        return results

    def _call_claude(self, message: str, system_prompt: str) -> str:
        """
        Call Claude API with message.

        Args:
            message: Message to send
            system_prompt: System context

        Returns:
            Claude response text
        """
        try:
            # Add to conversation history
            self.conversation_history.append({
                "role": "user",
                "content": message,
            })

            # Call Claude
            response = self.client.messages.create(
                model=self.MODEL,
                max_tokens=self.MAX_TOKENS,
                system=system_prompt,
                messages=self.conversation_history,
            )

            # Extract response text
            response_text = response.content[0].text

            # Add to conversation history
            self.conversation_history.append({
                "role": "assistant",
                "content": response_text,
            })

            self.logger.debug(f"Claude API call successful")
            return response_text

        except Exception as e:
            self.logger.error(f"Claude API call failed: {e}")
            raise APIException(f"Claude API error: {str(e)}")

    def _build_vulnerability_prompt(
        self,
        vuln_data: Dict,
        context: Optional[str] = None,
    ) -> str:
        """Build vulnerability analysis prompt."""
        prompt = f"""Analyze this vulnerability:

CVE ID: {vuln_data.get('cve_id', 'UNKNOWN')}
Service: {vuln_data.get('service', 'UNKNOWN')}
Version: {vuln_data.get('affected_version', 'UNKNOWN')}
CVSS Score: {vuln_data.get('cvss_score', 'N/A')}
Severity: {vuln_data.get('severity', 'UNKNOWN')}
Description: {vuln_data.get('description', 'No description')}
Published: {vuln_data.get('published_date', 'UNKNOWN')}

{f'Additional Context: {context}' if context else ''}

Provide a concise analysis including:
1. What makes this vulnerability critical
2. Who would likely exploit it and why
3. What immediate actions are needed
4. Key detection indicators"""

        return prompt

    def _build_remediation_prompt(
        self,
        vuln_data: Dict,
        env_info: Optional[Dict] = None,
    ) -> str:
        """Build remediation recommendation prompt."""
        env_details = ""
        if env_info:
            env_details = f"""
System Environment:
- OS: {env_info.get('os', 'UNKNOWN')}
- Architecture: {env_info.get('architecture', 'UNKNOWN')}
- Constraints: {env_info.get('constraints', 'NONE')}"""

        prompt = f"""Create a remediation plan for this vulnerability:

CVE ID: {vuln_data.get('cve_id', 'UNKNOWN')}
Service: {vuln_data.get('service', 'UNKNOWN')}
Version: {vuln_data.get('affected_version', 'UNKNOWN')}
CVSS Score: {vuln_data.get('cvss_score', 'N/A')}
Risk Level: {vuln_data.get('risk_level', 'UNKNOWN')}{env_details}

Provide:
1. Immediate mitigation steps (if no patch available)
2. Permanent fix (patching/upgrading strategy)
3. Implementation timeline
4. Rollback plan if issues arise
5. Monitoring/validation steps"""

        return prompt

    def _build_attack_scenario_prompt(
        self,
        vuln_data: Dict,
        threat_actor: Optional[str] = None,
    ) -> str:
        """Build attack scenario prompt."""
        actor = threat_actor or "generic attacker"

        prompt = f"""Create an attack scenario for this vulnerability:

CVE ID: {vuln_data.get('cve_id', 'UNKNOWN')}
Service: {vuln_data.get('service', 'UNKNOWN')}
Port: {vuln_data.get('port', 'UNKNOWN')}
CVSS Score: {vuln_data.get('cvss_score', 'N/A')}
Threat Actor: {actor}

Describe:
1. How the {actor} would discover this vulnerability
2. Step-by-step exploitation process
3. Post-exploitation objectives
4. Difficulty level and tools required
5. Detection and response indicators"""

        return prompt

    def _build_posture_prompt(
        self,
        findings: Dict,
        org_context: Optional[str] = None,
    ) -> str:
        """Build security posture assessment prompt."""
        org_details = f"\nOrganization: {org_context}" if org_context else ""

        prompt = f"""Assess security posture based on findings:

Vulnerability Summary:
- Critical: {findings.get('critical', 0)}
- High: {findings.get('high', 0)}
- Medium: {findings.get('medium', 0)}
- Low: {findings.get('low', 0)}
- Total: {findings.get('total', 0)}{org_details}

Provide:
1. Current maturity level assessment
2. Key gaps vs industry baseline
3. Top 3-5 strategic priorities
4. 6-month improvement roadmap
5. Success metrics and KPIs
6. Resource requirements estimate"""

        return prompt

    def reset_conversation(self) -> None:
        """Reset conversation history."""
        self.conversation_history = []
        self.logger.info("Conversation history cleared")

    def get_conversation_length(self) -> int:
        """Get current conversation length."""
        return len(self.conversation_history)
