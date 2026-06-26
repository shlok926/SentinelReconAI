import os
import socket
import requests
import logging
from typing import Dict, Any, Optional
from datetime import datetime

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

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
        
    def is_public_ip(self, ip_or_domain: str) -> bool:
        """Check if an IP is public. Threat Intel only works on public IPs."""
        import ipaddress
        try:
            # Resolve domain to IP first
            ip = socket.gethostbyname(ip_or_domain)
            return not ipaddress.ip_address(ip).is_private
        except Exception:
            return False # Invalid IP or domain
            
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

    def check_virustotal(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation on VirusTotal"""
        key = self.keys.get("virustotal")
        if not key:
            return {"status": "skipped", "reason": "No API key"}
            
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "accept": "application/json",
            "x-apikey": key
        }
        
        try:
            response = requests.request("GET", url, headers=headers)
            if response.status_code == 200:
                data = response.json()['data']['attributes']
                stats = data.get("last_analysis_stats", {})
                return {
                    "status": "success",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "network": data.get("network", "Unknown"),
                    "country": data.get("country", "Unknown")
                }
            return {"status": "error", "reason": f"HTTP {response.status_code}"}
        except Exception as e:
            self.logger.error(f"VirusTotal request failed: {e}")
            return {"status": "error", "reason": str(e)}

    def gather_intelligence(self, target_ip: str) -> Dict[str, Any]:
        """Main method to query all available threat intel feeds"""
        
        # Threat intel only works on public IPs. We can't query Shodan for 192.168.1.1
        if not self.is_public_ip(target_ip):
            self.logger.info(f"Target {target_ip} is private. Skipping Threat Intel.")
            return {"status": "skipped", "reason": "Private IP"}
            
        self.logger.info(f"Gathering Threat Intelligence for {target_ip}...")
        
        # Resolve target to an actual IP for AbuseIPDB
        try:
            resolved_ip = socket.gethostbyname(target_ip)
        except Exception:
            resolved_ip = target_ip
        
        intel_report = {
            "target": target_ip,
            "resolved_ip": resolved_ip,
            "timestamp": datetime.now().isoformat(),
            "abuseipdb": self.check_abuseipdb(resolved_ip),
            "virustotal": self.check_virustotal(resolved_ip)
        }
        
        return intel_report
