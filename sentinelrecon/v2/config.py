"""Configuration Management Module"""

from pathlib import Path
from typing import Optional, List
import logging
import os
from enum import Enum

class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"

class Config:
    """Centralized configuration management."""
    
    # Constants
    MAX_THREADS: int = 4  # Maximum number of threads for parallel scanning
    MAX_RETRIES: int = 3  # Maximum number of API retry attempts
    BACKOFF_BASE: float = 2.0  # Base multiplier for exponential backoff
    
    # Directories
    HOME_DIR: Path = Path.home()
    REPORTS_BASE_DIR: Path = HOME_DIR / "SentinelRecon-Reports"
    
    # AWS Configuration
    AWS_REGIONS: List[str] = [
        "us-east-1", "us-west-2", "eu-west-1", 
        "ap-southeast-1", "ca-central-1"
    ]
    AWS_TIMEOUT: int = 30
    AWS_RETRY_ATTEMPTS: int = 3
    AWS_BACKOFF_MULTIPLIER: float = 2.0
    
    # Security Settings (IMMUTABLE)
    # NEVER CHANGE THESE
    VERIFY_SSL: bool = True  # NEVER CHANGE THIS
    OUTPUT_DIR_PERMISSIONS: int = 0o755
    SENSITIVE_FILE_PERMISSIONS: int = 0o600
    
    # API Settings
    MAX_REDIRECTS: int = 5
    REQUEST_TIMEOUT: int = 30
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    def __init__(self):
        """Initialize configuration and validate security settings."""
        self.validate()
        
    @classmethod
    def get_report_dir(cls, scan_name: str) -> Path:
        """Get report directory for a scan."""
        report_dir = cls.REPORTS_BASE_DIR / scan_name
        report_dir.mkdir(mode=cls.OUTPUT_DIR_PERMISSIONS, parents=True, exist_ok=True)
        return report_dir
    
    @classmethod
    def validate(cls) -> bool:
        """Validate configuration is safe."""
        assert cls.VERIFY_SSL is True, "SSL verification MUST be enabled!"
        assert cls.SENSITIVE_FILE_PERMISSIONS == 0o600, "File permissions must be 0o600!"
        assert cls.OUTPUT_DIR_PERMISSIONS == 0o755, "Dir permissions must be 0o755!"
        return True
        
    def get_aws_timeout(self) -> int:
        """
        Get the configured AWS API timeout.
        
        Returns:
            int: The timeout value in seconds.
        """
        return self.AWS_TIMEOUT
        
    def get_logging_level(self) -> str:
        """
        Get the configured logging level.
        
        Returns:
            str: The logging level (e.g., 'INFO', 'DEBUG').
        """
        return self.LOG_LEVEL
        
    def get_sensitive_permissions(self) -> int:
        """
        Get the required octal permissions for sensitive files.
        
        Returns:
            int: The octal permission (0o600).
        """
        return self.SENSITIVE_FILE_PERMISSIONS

class LogConfig:
    """Logging configuration settings."""
    
    @staticmethod
    def get_logger(name: str, config: Config) -> logging.Logger:
        """
        Configure and return a logger.
        
        Args:
            name (str): The name of the logger.
            config (Config): The configuration object containing logging settings.
            
        Returns:
            logging.Logger: The configured logger instance.
        """
        logger = logging.getLogger(name)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(config.LOG_FORMAT)
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        logger.setLevel(getattr(logging, config.get_logging_level().upper(), logging.INFO))
        return logger

