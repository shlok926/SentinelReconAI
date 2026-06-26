import os
import requests
import logging
from typing import Dict, Any, Optional
from datetime import datetime

class ThreatIntelManager:
    """
    Integrates with Real-Time Threat Intelligence Feeds
    (Shodan, AbuseIPDB, VirusTotal, AlienVault OTX)
    """
    
    def __init__(self):
        self.logger = logging.getLogger("SentinelRecon.ThreatIntel")
        
        # Load API keys from environment (if available)
        self.keys = {
            "shodan": os.environ.get("SHODAN_API_KEY", ""),
            "abuseipdb": os.environ.get("ABUSEIPDB_API_KEY", ""),
            "virustotal": os.environ.get("VT_API_KEY", "")
        }
        
    def is_public_ip(self, ip: str) -> bool:
        """Check if an IP is public. Threat Intel only works on public IPs."""
        import ipaddress
        try:
            return not ipaddress.ip_address(ip).is_private
        except ValueError:
            return False # Invalid IP or domain (we should resolve domains first)
            
    def check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation on AbuseIPDB"""
        key = self.keys.get("abuseipdb")
        if not key:
            return {"status": "skipped", "reason": "No API key"}
            
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
        headers = {
            'Accept': 'application/json',
            'Key': key
        }
        
        try:
            response = requests.request(method='GET', url=url, headers=headers, params=querystring)
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    "status": "success",
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "is_public": data.get("isPublic", True),
                    "country": data.get("countryCode", "Unknown"),
                    "domain": data.get("domain", "Unknown")
                }
            return {"status": "error", "reason": f"HTTP {response.status_code}"}
        except Exception as e:
            self.logger.error(f"AbuseIPDB request failed: {e}")
            return {"status": "error", "reason": str(e)}

    def gather_intelligence(self, target_ip: str) -> Dict[str, Any]:
        """Main method to query all available threat intel feeds"""
        
        # Threat intel only works on public IPs. We can't query Shodan for 192.168.1.1
        if not self.is_public_ip(target_ip):
            self.logger.info(f"Target {target_ip} is private. Skipping Threat Intel.")
            return {"status": "skipped", "reason": "Private IP"}
            
        self.logger.info(f"Gathering Threat Intelligence for {target_ip}...")
        
        intel_report = {
            "target": target_ip,
            "timestamp": datetime.now().isoformat(),
            "abuseipdb": self.check_abuseipdb(target_ip),
            # Shodan and VirusTotal will be added here!
        }
        
        return intel_report
