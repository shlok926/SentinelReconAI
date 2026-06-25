"""
Network utilities for SentinelRecon
DNS resolution, IP parsing, CIDR expansion, etc.
"""

import socket
import ipaddress
from typing import List, Optional, Tuple
from sentinelrecon.utils.exceptions import NetworkException


class NetworkUtils:
    """Network utility functions"""

    @staticmethod
    def resolve_hostname(hostname: str, timeout: float = 5.0) -> Optional[str]:
        """
        Resolve hostname to IP address using DNS
        
        Args:
            hostname: Hostname or domain to resolve
            timeout: DNS query timeout in seconds
            
        Returns:
            IPv4 address string or None if resolution fails
            
        Raises:
            NetworkException: On resolution errors
        """
        try:
            socket.setdefaulttimeout(timeout)
            ip = socket.gethostbyname(hostname)
            socket.setdefaulttimeout(None)
            return ip
        except socket.gaierror as e:
            raise NetworkException(f"Failed to resolve hostname '{hostname}': {e}") from e
        except socket.timeout:
            raise NetworkException(f"DNS resolution timeout for '{hostname}'") from None
        except Exception as e:
            raise NetworkException(f"DNS resolution error for '{hostname}': {e}") from e

    @staticmethod
    def reverse_dns_lookup(ip: str, timeout: float = 5.0) -> Optional[str]:
        """
        Reverse DNS lookup (IP to hostname)
        
        Args:
            ip: IP address to reverse lookup
            timeout: Timeout in seconds
            
        Returns:
            Hostname or None if reverse lookup fails
        """
        try:
            socket.setdefaulttimeout(timeout)
            hostname, _, _ = socket.gethostbyaddr(ip)
            socket.setdefaulttimeout(None)
            return hostname
        except (socket.herror, socket.timeout, OSError):
            return None
        finally:
            socket.setdefaulttimeout(None)

    @staticmethod
    def expand_cidr(cidr: str) -> List[str]:
        """
        Expand CIDR notation to list of IP addresses
        
        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            List of IP addresses in the range
            
        Raises:
            NetworkException: If CIDR is invalid
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except (ipaddress.AddressValueError, ValueError) as e:
            raise NetworkException(f"Invalid CIDR notation: {cidr}") from e

    @staticmethod
    def get_ip_version(ip: str) -> Optional[int]:
        """
        Get IP version (4 or 6)
        
        Args:
            ip: IP address string
            
        Returns:
            4 for IPv4, 6 for IPv6, None if invalid
        """
        try:
            return ipaddress.ip_address(ip).version
        except (ipaddress.AddressValueError, ValueError):
            return None

    @staticmethod
    def get_network_info(ip: str) -> Optional[dict]:
        """
        Get network information for an IP address
        
        Args:
            ip: IP address
            
        Returns:
            Dictionary with network info or None if invalid IP
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return {
                "version": ip_obj.version,
                "is_private": ip_obj.is_private,
                "is_loopback": ip_obj.is_loopback,
                "is_multicast": ip_obj.is_multicast,
                "is_link_local": ip_obj.is_link_local,
                "is_reserved": ip_obj.is_reserved,
                "is_global": ip_obj.is_global,
            }
        except (ipaddress.AddressValueError, ValueError):
            return None

    @staticmethod
    def is_ip_reachable(ip: str, timeout: float = 2.0) -> bool:
        """
        Check if IP is reachable via ICMP ping
        
        Args:
            ip: IP address to check
            timeout: Timeout in seconds
            
        Returns:
            True if IP responds to ping, False otherwise
        """
        import os
        import platform
        
        # Determine ping command
        if platform.system().lower() == 'windows':
            ping_cmd = f'ping -n 1 -w {int(timeout * 1000)} {ip}'
        else:
            ping_cmd = f'ping -c 1 -W {int(timeout * 1000)} {ip}'
        
        try:
            response = os.system(ping_cmd + ' > /dev/null 2>&1')
            return response == 0
        except Exception:
            return False

    @staticmethod
    def get_interface_ips() -> List[str]:
        """
        Get all local interface IP addresses
        
        Returns:
            List of IP addresses
        """
        try:
            hostname = socket.gethostname()
            interfaces = socket.gethostbyname_ex(hostname)
            return interfaces[2] if len(interfaces) > 2 else []
        except socket.gaierror:
            return []

    @staticmethod
    def is_port_open(ip: str, port: int, timeout: float = 2.0) -> bool:
        """
        Check if port is open on target IP
        
        Args:
            ip: Target IP address
            port: Port number to check
            timeout: Connection timeout in seconds
            
        Returns:
            True if port is open, False otherwise
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        try:
            result = sock.connect_ex((ip, port))
            return result == 0
        except socket.error:
            return False
        finally:
            sock.close()

    @staticmethod
    def parse_target_and_ports(target: str, port_spec: str) -> Tuple[List[str], List[int]]:
        """
        Parse target and port specification into lists
        
        Args:
            target: Target specification (IP, domain, CIDR, hostname)
            port_spec: Port specification (e.g., "1-1024", "22,80,443")
            
        Returns:
            Tuple of (target_list, port_list)
        """
        from sentinelrecon.utils.validator import Validator
        
        # Parse target
        target_type, normalized_target = Validator.validate_target(target)
        
        if target_type == 'cidr':
            target_list = NetworkUtils.expand_cidr(normalized_target)
        elif target_type in ['domain', 'hostname']:
            try:
                target_list = [NetworkUtils.resolve_hostname(normalized_target)]
            except NetworkException as e:
                raise NetworkException(f"Cannot resolve {target}: {e}") from e
        else:
            target_list = [normalized_target]
        
        # Parse ports
        port_list = Validator.parse_port_string(port_spec)
        
        return target_list, port_list
