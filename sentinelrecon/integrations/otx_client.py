import requests
import logging
from dataclasses import dataclass
from typing import Optional, Dict

logger = logging.getLogger("SentinelRecon.OTX")

@dataclass
class OTXThreat:
    indicator: str
    type: str
    reputation: int
    threat_details: Dict

class OTXClient:
    def __init__(self, api_key: str = None):
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.api_key = api_key or ""  # OTX has free tier
        self.headers = {"X-OTX-API-KEY": self.api_key} if self.api_key else {}
    
    def lookup_ip(self, ip: str) -> Optional[dict]:
        """Query OTX for IP threat intelligence"""
        try:
            url = f"{self.base_url}/indicators/IPv4/{ip}/general"
            response = requests.get(url, headers=self.headers, timeout=5)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"OTX lookup failed for {ip}: {e}")
            return None
    
    def lookup_domain(self, domain: str) -> Optional[dict]:
        """Query OTX for domain threat intelligence"""
        try:
            url = f"{self.base_url}/indicators/domain/{domain}/general"
            response = requests.get(url, headers=self.headers, timeout=5)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"OTX lookup failed for {domain}: {e}")
            return None
