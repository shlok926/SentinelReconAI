import shodan
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("SentinelRecon.Shodan")

@dataclass
class ShodanData:
    ip: str
    hostnames: list
    org: str
    isp: str
    country: str
    ports: list
    cves: list
    last_update: str

class ShodanClient:
    def __init__(self, api_key: str):
        self.api = shodan.Shodan(api_key)
    
    def lookup(self, ip: str) -> Optional[ShodanData]:
        """Query Shodan for IP information"""
        if not self.api.api_key:
            logger.info("Shodan API key not provided, skipping.")
            return None
            
        try:
            host = self.api.host(ip)
            return ShodanData(
                ip=ip,
                hostnames=host.get('hostnames', []),
                org=host.get('org', 'N/A'),
                isp=host.get('isp', 'N/A'),
                country=host.get('country_code', 'N/A'),
                ports=host.get('ports', []),
                cves=host.get('vulns', []),
                last_update=host.get('last_update', 'N/A')
            )
        except Exception as e:
            logger.error(f"Shodan lookup failed for {ip}: {e}")
            return None
