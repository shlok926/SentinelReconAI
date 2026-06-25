"""
Service detection module for identifying services and versions.
"""
import json
import re
from typing import Optional, Dict, List
from pathlib import Path

from sentinelrecon.utils.logger import LoggerSetup


class ServiceDetector:
    """Detect services and parse versions from banners"""

    # Default service signatures
    DEFAULT_SIGNATURES = {
        "ssh": {
            "patterns": [
                r"(?:OpenSSH|libssh|Twisted conch|ROSSSH)",
                r"(?:OpenSSH|SSH)[\s_]([0-9.pP0-9]+)",
            ],
            "ports": [22],
        },
        "http": {
            "patterns": [
                r"(?:Apache|nginx|IIS|Tomcat|Jetty|lighttpd)",
                r"(?:Apache|nginx|Microsoft-IIS)(?:/| )([0-9.]+)",
            ],
            "ports": [80, 8080, 8000],
        },
        "https": {
            "patterns": [
                r"(?:Apache|nginx|IIS|Tomcat)",
                r"(?:Apache|nginx|Microsoft-IIS)(?:/| )([0-9.]+)",
            ],
            "ports": [443, 8443],
        },
        "ftp": {
            "patterns": [
                r"(?:vsFTPd|ProFTPD|FileZilla|Serv-U)",
                r"(?:vsFTPd|ProFTPD)\s+([0-9.]+)",
            ],
            "ports": [21],
        },
        "smtp": {
            "patterns": [
                r"(?:Sendmail|Postfix|Exim|Exchange)",
                r"ESMTP(?:\s+(.+?))?(?:\r|$)",
            ],
            "ports": [25, 587],
        },
        "pop3": {
            "patterns": [
                r"(?:Cyrus|Dovecot|Courier)",
                r"POP3(?:\s+(.+?))?(?:\r|$)",
            ],
            "ports": [110, 995],
        },
        "imap": {
            "patterns": [
                r"(?:Cyrus|Dovecot|Courier)",
                r"IMAP(?:\s+(.+?))?(?:\r|$)",
            ],
            "ports": [143, 993],
        },
        "mysql": {
            "patterns": [
                r"MySQL",
                r"(?:MySQL|MariaDB).*?([0-9.]+[0-9])",
            ],
            "ports": [3306],
        },
        "postgresql": {
            "patterns": [
                r"PostgreSQL",
                r"PostgreSQL\s+([0-9.]+)",
            ],
            "ports": [5432],
        },
        "mongodb": {
            "patterns": [
                r"MongoDB",
                r"MongoDB\s+([0-9.]+)",
            ],
            "ports": [27017],
        },
        "redis": {
            "patterns": [
                r"Redis",
                r"redis_version:([0-9.]+)",
            ],
            "ports": [6379],
        },
        "smb": {
            "patterns": [
                r"(?:Samba|Windows)",
                r"Samba\s+([0-9.]+)",
            ],
            "ports": [445, 139],
        },
        "ldap": {
            "patterns": [
                r"LDAP",
                r"LDAP(?:\s+(.+?))?(?:\r|$)",
            ],
            "ports": [389, 636],
        },
        "dns": {
            "patterns": [
                r"(?:BIND|dnsmasq|Unbound)",
                r"BIND\s+([0-9.]+)",
            ],
            "ports": [53],
        },
        "telnet": {
            "patterns": [
                r"telnet",
                r"telnet",
            ],
            "ports": [23],
        },
        "vnc": {
            "patterns": [
                r"RFB",
                r"RFB\s+([0-9.]+)",
            ],
            "ports": [5900],
        },
        "rdp": {
            "patterns": [
                r"rdp|Microsoft",
                r"rdp",
            ],
            "ports": [3389],
        },
        "elasticsearch": {
            "patterns": [
                r"Elasticsearch",
                r"Elasticsearch.*?([0-9.]+)",
            ],
            "ports": [9200, 9300],
        },
        "couchdb": {
            "patterns": [
                r"CouchDB",
                r"CouchDB/([0-9.]+)",
            ],
            "ports": [5984],
        },
    }

    def __init__(self, service_db_path: Optional[str] = None):
        """
        Initialize service detector.

        Args:
            service_db_path: Path to custom service database JSON
        """
        self.logger = LoggerSetup.setup_logger(__name__)
        self.signatures = self.DEFAULT_SIGNATURES.copy()

        # Load custom database if provided
        if service_db_path and Path(service_db_path).exists():
            try:
                with open(service_db_path, "r") as f:
                    custom_sigs = json.load(f)
                    self.signatures.update(custom_sigs)
                    self.logger.info(
                        f"Loaded custom services from {service_db_path}"
                    )
            except Exception as e:
                self.logger.warning(
                    f"Failed to load service database: {e}"
                )

    def detect_service(
        self,
        banner: str,
        port: int = None,
        service_hint: str = None,
    ) -> Optional[Dict]:
        """
        Detect service from banner.

        Args:
            banner: Banner string
            port: Port number (optional, for heuristics)
            service_hint: Service name hint

        Returns:
            Dict with service name and version, or None
        """
        if not banner:
            return None

        # Try service hint first
        if service_hint and service_hint in self.signatures:
            result = self._match_signature(banner, service_hint)
            if result:
                return result

        # Try all signatures
        best_match = None
        highest_score = 0

        for service_name, sig in self.signatures.items():
            result = self._match_signature(banner, service_name)
            if result:
                # Score by port match
                score = 1.0
                if port and port in sig.get("ports", []):
                    score = 2.0

                if score > highest_score:
                    highest_score = score
                    best_match = result

        return best_match

    def _match_signature(self, banner: str, service_name: str) -> Optional[Dict]:
        """
        Match banner against service signature.

        Args:
            banner: Banner string
            service_name: Service name

        Returns:
            Dict with service info if matched
        """
        if service_name not in self.signatures:
            return None

        sig = self.signatures[service_name]
        patterns = sig.get("patterns", [])

        if not patterns:
            return None

        # Try main pattern (service identification)
        main_pattern = patterns[0]
        if not re.search(main_pattern, banner, re.IGNORECASE):
            return None

        # Try version pattern if available
        version = None
        if len(patterns) > 1:
            version_pattern = patterns[1]
            match = re.search(version_pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else None

        return {
            "service": service_name,
            "version": version,
            "confidence": "high" if version else "medium",
        }

    def detect_from_port(self, port: int) -> Optional[str]:
        """
        Guess service from port number.

        Args:
            port: Port number

        Returns:
            Service name or None
        """
        for service_name, sig in self.signatures.items():
            if port in sig.get("ports", []):
                return service_name

        # Common port defaults
        default_ports = {
            22: "ssh",
            80: "http",
            443: "https",
            3306: "mysql",
            5432: "postgresql",
            6379: "redis",
            27017: "mongodb",
        }

        return default_ports.get(port)

    def get_default_ports(self, service: str = None) -> Dict[int, str]:
        """
        Get default ports for services.

        Args:
            service: Specific service name (optional)

        Returns:
            Dictionary mapping port -> service
        """
        ports = {}

        if service:
            if service in self.signatures:
                for port in self.signatures[service].get("ports", []):
                    ports[port] = service
        else:
            for service_name, sig in self.signatures.items():
                for port in sig.get("ports", []):
                    ports[port] = service_name

        return ports

    def parse_version(self, banner: str, service: str) -> Optional[str]:
        """
        Extract version from service banner.

        Args:
            banner: Banner string
            service: Service name

        Returns:
            Version string or None
        """
        if service not in self.signatures:
            return None

        sig = self.signatures[service]
        patterns = sig.get("patterns", [])

        if len(patterns) > 1:
            version_pattern = patterns[1]
            match = re.search(version_pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1) if match.lastindex else None

        return None

    def extract_all_services(self, banner: str) -> List[Dict]:
        """
        Extract all possible services from banner.

        Args:
            banner: Banner string

        Returns:
            List of possible services
        """
        results = []

        for service_name, sig in self.signatures.items():
            result = self._match_signature(banner, service_name)
            if result:
                results.append(result)

        # Sort by confidence
        return sorted(
            results,
            key=lambda x: (
                x["confidence"] == "high",
                x["version"] is not None,
            ),
            reverse=True,
        )

    def add_custom_signature(
        self,
        service_name: str,
        patterns: List[str],
        ports: List[int],
    ) -> None:
        """
        Add custom service signature.

        Args:
            service_name: Service name
            patterns: List of regex patterns
            ports: List of ports
        """
        self.signatures[service_name] = {
            "patterns": patterns,
            "ports": ports,
        }
        self.logger.info(f"Added custom signature for {service_name}")

    def export_signatures(self, path: str) -> None:
        """
        Export signatures to JSON file.

        Args:
            path: Output file path
        """
        try:
            with open(path, "w") as f:
                json.dump(self.signatures, f, indent=2)
            self.logger.info(f"Exported signatures to {path}")
        except Exception as e:
            self.logger.error(f"Failed to export signatures: {e}")

    def import_signatures(self, path: str) -> None:
        """
        Import signatures from JSON file.

        Args:
            path: Input file path
        """
        try:
            with open(path, "r") as f:
                custom_sigs = json.load(f)
                self.signatures.update(custom_sigs)
            self.logger.info(f"Imported signatures from {path}")
        except Exception as e:
            self.logger.error(f"Failed to import signatures: {e}")
