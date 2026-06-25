"""
Banner grabbing module for service identification.
"""
import socket
import ssl
import re
from typing import Optional, Dict, Tuple
from dataclasses import dataclass
import time

from sentinelrecon.utils.logger import LoggerSetup
from sentinelrecon.utils.exceptions import ScanException


@dataclass
class BannerData:
    """Banner grab result"""
    raw: str
    parsed: str
    service: Optional[str] = None
    version: Optional[str] = None
    protocol: str = "tcp"
    timestamp: Optional[float] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "raw": self.raw,
            "parsed": self.parsed,
            "service": self.service,
            "version": self.version,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
        }


class BannerGrabber:
    """Grab service banners for version detection"""

    # Common port -> service mappings
    DEFAULT_PORTS = {
        21: "ftp",
        22: "ssh",
        25: "smtp",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5984: "couchdb",
        6379: "redis",
        8080: "http-alt",
        8443: "https-alt",
        9200: "elasticsearch",
        27017: "mongodb",
    }

    # Service-specific probes
    PROBES = {
        "http": b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "https": b"",  # SSL/TLS handshake
        "smtp": b"EHLO localhost\r\n",
        "ftp": b"USER anonymous\r\n",
        "ssh": b"",  # No probe needed - gets banner on connect
        "pop3": b"QUIT\r\n",
        "imap": b"LOGOUT\r\n",
        "mysql": b"",  # No probe - banner sent on connect
        "postgresql": b"",  # No probe - banner sent on connect
        "redis": b"INFO\r\n",
        "mongodb": b"",  # No probe
    }

    def __init__(self, timeout: int = 5, verbose: bool = False):
        """
        Initialize banner grabber.

        Args:
            timeout: Socket timeout in seconds
            verbose: Enable verbose logging
        """
        self.timeout = timeout
        self.verbose = verbose
        self.logger = LoggerSetup.setup_logger(__name__)

    def grab(
        self,
        host: str,
        port: int,
        service: Optional[str] = None,
    ) -> Optional[BannerData]:
        """
        Grab banner from service.

        Args:
            host: Target host IP or domain
            port: Target port
            service: Service name (optional, for targeted probes)

        Returns:
            BannerData if successful, None otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # Determine service if not provided
            if not service:
                service = self.DEFAULT_PORTS.get(port, "unknown")

            # Special handling for HTTPS
            if port == 443 or service == "https":
                return self._grab_ssl(host, port)

            # Connect to service
            sock.connect((host, port))

            # Get initial banner (some services send immediately)
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                banner = b""

            # Send probe if service requires it
            probe = self.PROBES.get(service)
            if probe and probe != b"":
                try:
                    sock.send(probe)
                    response = sock.recv(4096)
                    banner += response
                except (socket.timeout, socket.error):
                    pass

            sock.close()

            # Parse banner
            if banner:
                parsed = self._parse_banner(banner.decode("utf-8", errors="ignore"))
                return BannerData(
                    raw=banner.decode("utf-8", errors="ignore"),
                    parsed=parsed,
                    service=service,
                    version=self._extract_version(parsed, service),
                    protocol="tcp",
                    timestamp=time.time(),
                )

        except socket.timeout:
            self.logger.debug(f"Timeout grabbing banner from {host}:{port}")
        except ConnectionRefusedError:
            self.logger.debug(f"Connection refused: {host}:{port}")
        except Exception as e:
            self.logger.debug(f"Error grabbing banner: {e}")

        return None

    def grab_ssl(self, host: str, port: int = 443) -> Optional[BannerData]:
        """
        Grab SSL/TLS certificate information.

        Args:
            host: Target host IP or domain
            port: Target port (default 443)

        Returns:
            BannerData with certificate info
        """
        return self._grab_ssl(host, port)

    def _grab_ssl(self, host: str, port: int) -> Optional[BannerData]:
        """
        Internal SSL/TLS grabber.

        Args:
            host: Target host
            port: Target port

        Returns:
            BannerData with certificate info
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

                    # Extract certificate info
                    info_parts = []

                    if cert:
                        if "subject" in cert:
                            cn = None
                            for subject_tuple in cert["subject"]:
                                for key, value in subject_tuple:
                                    if key == "commonName":
                                        cn = value
                            if cn:
                                info_parts.append(f"CN={cn}")

                        if "notAfter" in cert:
                            info_parts.append(f"Expires={cert['notAfter']}")

                    if cipher:
                        info_parts.append(f"Cipher={cipher[0]}")

                    banner_str = " | ".join(info_parts) if info_parts else "SSL/TLS"

                    return BannerData(
                        raw=banner_str,
                        parsed=banner_str,
                        service="https",
                        version="TLS",
                        protocol="tcp",
                        timestamp=time.time(),
                    )

        except ssl.SSLError as e:
            self.logger.debug(f"SSL error grabbing from {host}:{port}: {e}")
        except socket.timeout:
            self.logger.debug(f"Timeout grabbing SSL from {host}:{port}")
        except Exception as e:
            self.logger.debug(f"Error grabbing SSL: {e}")

        return None

    def _parse_banner(self, banner: str) -> str:
        """
        Parse and clean banner string.

        Args:
            banner: Raw banner string

        Returns:
            Cleaned banner string
        """
        # Remove non-printable characters
        banner = "".join(c if c.isprintable() or c in "\n\r\t" else " " for c in banner)

        # Take first line (usually contains version info)
        first_line = banner.split("\n")[0].strip()

        return first_line

    def _extract_version(self, banner: str, service: str) -> Optional[str]:
        """
        Extract version from banner.

        Args:
            banner: Parsed banner string
            service: Service name

        Returns:
            Version string if found
        """
        if not banner:
            return None

        # SSH: OpenSSH_7.4
        if service == "ssh":
            match = re.search(r"OpenSSH[_\s]([0-9.]+)", banner, re.IGNORECASE)
            if match:
                return match.group(1)

        # FTP: 220 vsFTPd 3.0.2
        if service == "ftp":
            match = re.search(r"(?:vsFTPd|ProFTPD)\s+([0-9.]+)", banner)
            if match:
                return match.group(1)

        # HTTP: Server: Apache/2.4.41
        if service in ["http", "http-alt"]:
            match = re.search(r"Server:\s+([^\r\n]+)", banner)
            if match:
                return match.group(1)

        # SMTP: 220 mail.example.com ESMTP
        if service == "smtp":
            match = re.search(r"(\w+)\s+([0-9.]+)?", banner)
            if match:
                return match.group(1)

        # MySQL: 5.7.27-0ubuntu0.18.04.1-log
        if service == "mysql":
            match = re.search(r"mysql.*?([0-9.]+)", banner, re.IGNORECASE)
            if match:
                return match.group(1)

        # PostgreSQL: PostgreSQL 9.6.15
        if service == "postgresql":
            match = re.search(r"PostgreSQL\s+([0-9.]+)", banner)
            if match:
                return match.group(1)

        # Generic version pattern
        match = re.search(r"(?:version|v|ver)[\s:]([0-9.]+[0-9])", banner, re.IGNORECASE)
        if match:
            return match.group(1)

        return None

    def grab_multiple(
        self,
        host: str,
        ports: Dict[int, str],
    ) -> Dict[int, Optional[BannerData]]:
        """
        Grab banners from multiple ports.

        Args:
            host: Target host
            ports: Dictionary mapping port -> service name

        Returns:
            Dictionary mapping port -> BannerData
        """
        results = {}
        for port, service in ports.items():
            try:
                banner = self.grab(host, port, service)
                results[port] = banner
            except Exception as e:
                self.logger.warning(f"Error grabbing port {port}: {e}")
                results[port] = None

        return results
