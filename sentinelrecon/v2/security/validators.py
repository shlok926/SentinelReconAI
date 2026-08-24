"""Input and State Validators

Provides security validation utilities for user input and credential scanning.
"""

import re
from typing import Tuple
import logging

class InputValidator:
    """Validates user input for security and format compliance."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    @staticmethod
    def validate_aws_account_id(account_id: str) -> Tuple[bool, str]:
        """Validate AWS account ID format.
        
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not account_id:
            return False, "Account ID cannot be empty"
        
        if account_id.startswith("-"):
            return False, "Account ID cannot start with '-'"
        
        if not re.match(r'^\d{12}$', account_id):
            return False, "Account ID must be 12 digits"
        
        return True, ""
    
    @staticmethod
    def validate_aws_region(region: str) -> Tuple[bool, str]:
        """Validate AWS region format."""
        valid_regions = [
            "us-east-1", "us-west-2", "eu-west-1",
            "ap-southeast-1", "ca-central-1"
        ]
        
        if region not in valid_regions:
            return False, f"Region must be one of: {', '.join(valid_regions)}"
        
        return True, ""
    
    @staticmethod
    def validate_no_shell_injection(input_str: str) -> Tuple[bool, str]:
        """Validate input doesn't contain shell injection patterns."""
        dangerous_patterns = [
            r';\s*',
            r'\|\s*',
            r'&&',
            r'\$\(',
            r'`',
            r'\$\{',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, input_str):
                return False, f"Input contains dangerous pattern: {pattern}"
        
        return True, ""
    
    @staticmethod
    def validate_scan_name(scan_name: str) -> Tuple[bool, str]:
        """Validate scan name is safe for file system."""
        if not scan_name:
            return False, "Scan name cannot be empty"
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', scan_name):
            return False, "Scan name can only contain letters, numbers, _, -"
        
        if len(scan_name) > 50:
            return False, "Scan name must be <= 50 characters"
        
        return True, ""

class CredentialValidator:
    """Validates credential formats and security."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    @staticmethod
    def validate_no_hardcoded_aws_key(content: str) -> Tuple[bool, str]:
        """Check if content contains hardcoded AWS access key."""
        aws_key_pattern = r'AKIA[0-9A-Z]{16}'
        
        if re.search(aws_key_pattern, content):
            return False, "Content contains hardcoded AWS access key"
        
        return True, ""
    
    @staticmethod
    def validate_no_hardcoded_secret(content: str) -> Tuple[bool, str]:
        """Check if content contains hardcoded secrets."""
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
        ]
        
        for pattern in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return False, "Content appears to contain hardcoded secrets"
        
        return True, ""
