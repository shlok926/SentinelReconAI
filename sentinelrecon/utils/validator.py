"""
Input validation utilities for SentinelRecon
Validates IPs, domains, CIDR ranges, ports, etc.
"""

import re
import ipaddress
from typing import Union, List, Tuple
from sentinelrecon.utils.exceptions import ValidationException


class Validator:
    """Validation utilities for reconnaissance targets and configurations"""

    # Regular expressions
    DOMAIN_REGEX = re.compile(
        r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$',
        re.IGNORECASE
    )
    
    HOSTNAME_REGEX = re.compile(
        r'^(?!-)(?:[a-zA-Z0-9-]{1,63}(?<!-)\.)*(?!-)(?:[a-zA-Z0-9-]{1,63}(?<!-))$'
    )

    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        """Check if string is a valid IPv4 address"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_valid_ipv6(ip: str) -> bool:
        """Check if string is a valid IPv6 address"""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IP address (v4 or v6)"""
        return Validator.is_valid_ipv4(ip) or Validator.is_valid_ipv6(ip)

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Check if string is a valid domain name"""
        if len(domain) > 253:
            return False
        return Validator.DOMAIN_REGEX.match(domain) is not None

    @staticmethod
    def is_valid_hostname(hostname: str) -> bool:
        """Check if string is a valid hostname"""
        if len(hostname) > 253:
            return False
        return Validator.HOSTNAME_REGEX.match(hostname) is not None

    @staticmethod
    def is_valid_cidr(cidr: str) -> bool:
        """Check if string is a valid CIDR notation"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def is_valid_port(port: Union[int, str]) -> bool:
        """Check if value is a valid port number (1-65535)"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_valid_port_range(start: int, end: int) -> bool:
        """Check if port range is valid"""
        return (Validator.is_valid_port(start) and 
                Validator.is_valid_port(end) and 
                start <= end)

    @staticmethod
    def parse_port_string(port_string: str) -> List[int]:
        """
        Parse port string into list of ports
        
        Accepts:
        - Single port: "80"
        - Range: "1-1024"
        - List: "22,80,443"
        - Mixed: "22,80-90,443"
        
        Args:
            port_string: Port specification string
            
        Returns:
            List of valid port numbers
            
        Raises:
            ValidationException: If port string is invalid
        """
        ports = []
        
        try:
            for part in port_string.split(','):
                part = part.strip()
                
                if '-' in part:
                    # Range
                    start_str, end_str = part.split('-', 1)
                    start = int(start_str.strip())
                    end = int(end_str.strip())
                    
                    if not Validator.is_valid_port_range(start, end):
                        raise ValidationException(f"Invalid port range: {part}")
                    
                    ports.extend(range(start, end + 1))
                else:
                    # Single port
                    port = int(part)
                    if not Validator.is_valid_port(port):
                        raise ValidationException(f"Invalid port: {port}")
                    ports.append(port)
            
            return sorted(list(set(ports)))  # Remove duplicates and sort
        except ValueError as e:
            raise ValidationException(f"Invalid port specification: {port_string}") from e

    @staticmethod
    def validate_target(target: str) -> Tuple[str, str]:
        """
        Validate and identify target type
        
        Args:
            target: Target specification (IP, domain, CIDR, hostname)
            
        Returns:
            Tuple of (target_type, normalized_target)
            target_type: 'ipv4', 'ipv6', 'cidr', 'domain', 'hostname'
            
        Raises:
            ValidationException: If target is invalid
        """
        target = target.strip()
        
        # Check for CIDR notation
        if '/' in target:
            if Validator.is_valid_cidr(target):
                return ('cidr', target)
            else:
                raise ValidationException(f"Invalid CIDR notation: {target}")
        
        # Check for IPv6
        if ':' in target:
            if Validator.is_valid_ipv6(target):
                return ('ipv6', target)
        
        # Check for IPv4
        if Validator.is_valid_ipv4(target):
            return ('ipv4', target)
        
        # Check for domain
        if Validator.is_valid_domain(target):
            return ('domain', target)
        
        # Check for hostname
        if Validator.is_valid_hostname(target):
            return ('hostname', target)
        
        raise ValidationException(
            f"Invalid target: {target}. "
            f"Must be IP, domain, hostname, or CIDR range"
        )

    @staticmethod
    def validate_scan_type(scan_type: str) -> bool:
        """Check if scan type is valid"""
        return scan_type.lower() in ['syn', 'connect', 'udp']

    @staticmethod
    def validate_timeout(timeout: Union[int, float]) -> bool:
        """Check if timeout value is valid (0.1 to 300 seconds)"""
        try:
            timeout_val = float(timeout)
            return 0.1 <= timeout_val <= 300
        except (ValueError, TypeError):
            return False

    @staticmethod
    def validate_thread_count(threads: int) -> bool:
        """Check if thread count is valid (1 to 100)"""
        try:
            thread_val = int(threads)
            return 1 <= thread_val <= 100
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_reserved_ip(ip: str) -> bool:
        """
        Check if IP is reserved/private/loopback
        
        Returns:
            True if IP is reserved, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (ip_obj.is_private or 
                    ip_obj.is_loopback or 
                    ip_obj.is_link_local or
                    ip_obj.is_multicast or
                    ip_obj.is_reserved)
        except (ipaddress.AddressValueError, ValueError):
            return False

    @staticmethod
    def validate_api_key_format(api_key: str, provider: str = 'claude') -> bool:
        """
        Basic validation of API key format
        
        Args:
            api_key: API key string
            provider: 'claude' or 'openai'
            
        Returns:
            True if API key format looks valid
        """
        if not isinstance(api_key, str) or len(api_key) < 10:
            return False
        
        if provider.lower() == 'claude':
            # Claude API keys typically start with 'sk-' or similar
            return len(api_key) > 30
        elif provider.lower() == 'openai':
            # OpenAI API keys typically start with 'sk-'
            return api_key.startswith('sk-') and len(api_key) > 40
        
        return len(api_key) > 10
