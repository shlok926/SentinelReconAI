"""
Port scanning module supporting SYN, Connect, and UDP scans.
"""
import socket
import asyncio
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum
import time

try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1, sr
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from sentinelrecon.utils.logger import LoggerSetup
from sentinelrecon.utils.exceptions import (
    ScanException,
    NetworkException,
    ValidationException,
)
from sentinelrecon.utils.validator import Validator
from sentinelrecon.utils.network_utils import NetworkUtils


class ScanType(Enum):
    """Port scan types"""
    SYN = "syn"  # Requires root/admin
    CONNECT = "connect"  # TCP three-way handshake
    UDP = "udp"  # UDP scan


class PortState(Enum):
    """Port states"""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"
    UNKNOWN = "unknown"


@dataclass
class PortScanResult:
    """Port scan result"""
    port: int
    state: PortState
    service: Optional[str] = None
    protocol: str = "tcp"
    timestamp: Optional[float] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "port": self.port,
            "state": self.state.value,
            "service": self.service,
            "protocol": self.protocol,
            "timestamp": self.timestamp,
        }


class PortScanner:
    """Port scanner supporting multiple scan types"""

    def __init__(self, timeout: int = 5, threads: int = 10, verbose: bool = False):
        """
        Initialize port scanner.

        Args:
            timeout: Socket timeout in seconds
            threads: Number of concurrent threads
            verbose: Enable verbose logging
        """
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.logger = LoggerSetup.setup_logger(__name__)

    def validate_target(self, target: str) -> str:
        """
        Validate and resolve target.

        Args:
            target: Target IP, domain, or CIDR

        Returns:
            Resolved IP address

        Raises:
            ValidationException: If target is invalid
            NetworkException: If DNS resolution fails
        """
        target_type, normalized = Validator.validate_target(target)

        # Check if reserved IP
        if Validator.is_reserved_ip(normalized):
            raise ValidationException(
                f"Cannot scan reserved IP: {normalized}"
            )

        # For domains, resolve to IP
        if target_type == "domain":
            try:
                ip = NetworkUtils.resolve_hostname(
                    normalized, timeout=self.timeout
                )
                self.logger.info(f"Resolved {normalized} to {ip}")
                return ip
            except NetworkException as e:
                raise NetworkException(f"DNS resolution failed: {str(e)}")

        return normalized

    def syn_scan(self, target_ip: str, ports: List[int]) -> Dict[int, PortScanResult]:
        """
        Perform SYN scan using Scapy (requires root/admin).

        Args:
            target_ip: Target IP address
            ports: List of ports to scan

        Returns:
            Dictionary mapping port -> PortScanResult

        Raises:
            ScanException: If Scapy not available or scan fails
        """
        if not SCAPY_AVAILABLE:
            raise ScanException(
                "Scapy not available. Install with: pip install scapy"
            )

        results = {}
        try:
            for port in ports:
                try:
                    # Create TCP SYN packet
                    packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

                    # Send packet and wait for response
                    response = sr1(
                        packet,
                        timeout=self.timeout,
                        verbose=False,
                    )

                    if response is None:
                        results[port] = PortScanResult(
                            port=port,
                            state=PortState.FILTERED,
                            protocol="tcp",
                            timestamp=time.time(),
                        )
                    elif response.haslayer(TCP):
                        tcp_layer = response.getlayer(TCP)
                        # Check SYN-ACK (flags 18 = SYN+ACK)
                        if tcp_layer.flags & 0x12:
                            results[port] = PortScanResult(
                                port=port,
                                state=PortState.OPEN,
                                protocol="tcp",
                                timestamp=time.time(),
                            )
                        # RST (flags 4)
                        elif tcp_layer.flags & 0x04:
                            results[port] = PortScanResult(
                                port=port,
                                state=PortState.CLOSED,
                                protocol="tcp",
                                timestamp=time.time(),
                            )
                    elif response.haslayer(ICMP):
                        results[port] = PortScanResult(
                            port=port,
                            state=PortState.FILTERED,
                            protocol="tcp",
                            timestamp=time.time(),
                        )
                except Exception as e:
                    self.logger.warning(f"SYN scan failed for port {port}: {e}")
                    results[port] = PortScanResult(
                        port=port,
                        state=PortState.UNKNOWN,
                        protocol="tcp",
                        timestamp=time.time(),
                    )

            return results

        except Exception as e:
            raise ScanException(f"SYN scan failed: {str(e)}")

    def connect_scan(
        self, target_ip: str, ports: List[int]
    ) -> Dict[int, PortScanResult]:
        """
        Perform TCP Connect scan (no root required).

        Args:
            target_ip: Target IP address
            ports: List of ports to scan

        Returns:
            Dictionary mapping port -> PortScanResult
        """
        results = {}

        def scan_port(port: int) -> Tuple[int, PortScanResult]:
            """Scan single port"""
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            try:
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    state = PortState.OPEN
                else:
                    state = PortState.CLOSED
            except socket.timeout:
                state = PortState.FILTERED
            except Exception as e:
                self.logger.warning(
                    f"Connect scan failed for port {port}: {e}"
                )
                state = PortState.UNKNOWN
            finally:
                sock.close()

            return port, PortScanResult(
                port=port,
                state=state,
                protocol="tcp",
                timestamp=time.time(),
            )

        # Use thread pool for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [
                executor.submit(scan_port, port) for port in ports
            ]
            for future in as_completed(futures):
                try:
                    port, result = future.result()
                    results[port] = result
                except Exception as e:
                    self.logger.error(f"Thread error: {e}")

        return results

    def udp_scan(self, target_ip: str, ports: List[int]) -> Dict[int, PortScanResult]:
        """
        Perform UDP scan.

        Args:
            target_ip: Target IP address
            ports: List of ports to scan

        Returns:
            Dictionary mapping port -> PortScanResult
        """
        results = {}

        def scan_port(port: int) -> Tuple[int, PortScanResult]:
            """Scan single UDP port"""
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            try:
                # Send UDP packet
                sock.sendto(b"probe", (target_ip, port))

                # Try to receive response
                try:
                    data, _ = sock.recvfrom(1024)
                    state = PortState.OPEN
                except socket.timeout:
                    state = PortState.OPEN_FILTERED
            except socket.error as e:
                if e.errno == 111:  # Connection refused
                    state = PortState.CLOSED
                else:
                    state = PortState.FILTERED
            except Exception as e:
                self.logger.warning(
                    f"UDP scan failed for port {port}: {e}"
                )
                state = PortState.UNKNOWN
            finally:
                sock.close()

            return port, PortScanResult(
                port=port,
                state=state,
                protocol="udp",
                timestamp=time.time(),
            )

        # Use thread pool for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [
                executor.submit(scan_port, port) for port in ports
            ]
            for future in as_completed(futures):
                try:
                    port, result = future.result()
                    results[port] = result
                except Exception as e:
                    self.logger.error(f"Thread error: {e}")

        return results

    def scan(
        self,
        target: str,
        ports: List[int],
        scan_type: ScanType = ScanType.CONNECT,
    ) -> Dict[int, PortScanResult]:
        """
        Perform port scan.

        Args:
            target: Target IP, domain, or CIDR
            ports: List of ports to scan
            scan_type: Type of scan (SYN, CONNECT, UDP)

        Returns:
            Dictionary mapping port -> PortScanResult

        Raises:
            ValidationException: If target or ports are invalid
            ScanException: If scan fails
        """
        # Validate target
        target_ip = self.validate_target(target)

        # Validate ports
        if not ports or not all(1 <= p <= 65535 for p in ports):
            raise ValidationException("Invalid port range")

        self.logger.info(
            f"Starting {scan_type.value} scan on {target_ip} for {len(ports)} ports"
        )

        # Perform scan based on type
        if scan_type == ScanType.SYN:
            results = self.syn_scan(target_ip, ports)
        elif scan_type == ScanType.UDP:
            results = self.udp_scan(target_ip, ports)
        else:  # CONNECT
            results = self.connect_scan(target_ip, ports)

        # Log summary
        open_ports = [p for p, r in results.items() if r.state == PortState.OPEN]
        self.logger.info(
            f"Scan completed: {len(open_ports)} open ports found"
        )

        return results

    def scan_with_progress(
        self,
        target: str,
        ports: List[int],
        scan_type: ScanType = ScanType.CONNECT,
        progress_callback=None,
    ) -> Dict[int, PortScanResult]:
        """
        Perform port scan with progress callback.

        Args:
            target: Target IP, domain, or CIDR
            ports: List of ports to scan
            scan_type: Type of scan
            progress_callback: Callable(current, total) for progress updates

        Returns:
            Dictionary mapping port -> PortScanResult
        """
        # Validate target
        target_ip = self.validate_target(target)

        # Validate ports
        if not ports or not all(1 <= p <= 65535 for p in ports):
            raise ValidationException("Invalid port range")

        results = {}
        total = len(ports)

        if scan_type == ScanType.CONNECT:
            # For connect scan, we can report progress
            def scan_port(port: int) -> Tuple[int, PortScanResult]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)

                try:
                    result = sock.connect_ex((target_ip, port))
                    state = PortState.OPEN if result == 0 else PortState.CLOSED
                except socket.timeout:
                    state = PortState.FILTERED
                except Exception:
                    state = PortState.UNKNOWN
                finally:
                    sock.close()

                return port, PortScanResult(
                    port=port,
                    state=state,
                    protocol="tcp",
                    timestamp=time.time(),
                )

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {
                    executor.submit(scan_port, port): port
                    for port in ports
                }
                completed = 0
                for future in as_completed(futures):
                    try:
                        port, result = future.result()
                        results[port] = result
                        completed += 1
                        if progress_callback:
                            progress_callback(completed, total)
                    except Exception as e:
                        self.logger.error(f"Thread error: {e}")
        else:
            # Fallback to regular scan for other types
            results = self.scan(target, ports, scan_type)

        return results
