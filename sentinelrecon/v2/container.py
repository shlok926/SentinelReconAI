"""Dependency Injection Container

This module provides the dependency injection container for SentinelRecon,
enabling loose coupling and easy testing across the application by lazy-loading components.
"""

from typing import Optional
from dataclasses import dataclass
import logging

@dataclass
class ServiceContainer:
    """Dependency injection container."""
    
    config: 'Config'
    logger: logging.Logger
    aws_client: Optional['AWSClient'] = None
    azure_client: Optional['AzureClient'] = None
    gcp_client: Optional['GCPClient'] = None
    report_manager: Optional['ReportManager'] = None
    credentials_manager: Optional['CredentialsManager'] = None
    output_manager: Optional['OutputManager'] = None
    
    _instance: Optional['ServiceContainer'] = None
    
    @classmethod
    def create(cls) -> 'ServiceContainer':
        """Create container with all dependencies."""
        # 1. Config
        from sentinelrecon.v2.config import Config, LogConfig
        config = Config()
        config.validate()
        
        # 2. Logger
        logger = LogConfig.get_logger("SentinelRecon", config)
        
        # 3. Create container
        return cls(config=config, logger=logger)
        
    @classmethod
    def create_with_custom_config(cls, custom_config: 'Config') -> 'ServiceContainer':
        """
        Factory method for testing purposes with a custom config.
        
        Args:
            custom_config (Config): Custom configuration object
            
        Returns:
            ServiceContainer: A new container with custom configuration.
        """
        from sentinelrecon.v2.config import LogConfig
        logger = LogConfig.get_logger("SentinelReconTest", custom_config)
        return cls(config=custom_config, logger=logger)
        
    @classmethod
    def get_instance(cls) -> 'ServiceContainer':
        """
        Get the global singleton instance of the container.
        Thread-safe lazy initialization is assumed.
        """
        if cls._instance is None:
            cls._instance = cls.create()
        return cls._instance
    
    def get_aws_client(self) -> 'AWSClient':
        """
        Get or create AWS client (lazy-loaded).
        
        Returns:
            AWSClient: The configured AWS client wrapper.
        """
        if self.aws_client is None:
            from sentinelrecon.v2.aws.client import AWSClient
            self.aws_client = AWSClient(config=self.config, logger=self.logger)
        return self.aws_client
        
    def get_azure_client(self) -> 'AzureClient':
        """
        Get or create Azure client (lazy-loaded).
        
        Returns:
            AzureClient: The configured Azure client wrapper.
        """
        if self.azure_client is None:
            from sentinelrecon.v2.azure.client import AzureClient
            self.azure_client = AzureClient(config=self.config, logger=self.logger)
        return self.azure_client
        
    def get_gcp_client(self) -> 'GCPClient':
        """
        Get or create GCP client (lazy-loaded).
        
        Returns:
            GCPClient: The configured GCP client wrapper.
        """
        if self.gcp_client is None:
            from sentinelrecon.v2.gcp.client import GCPClient
            self.gcp_client = GCPClient(config=self.config, logger=self.logger)
        return self.gcp_client
    
    def get_report_manager(self) -> 'ReportManager':
        """
        Get or create report manager (lazy-loaded).
        
        Returns:
            ReportManager: The configured report output manager.
        """
        if self.report_manager is None:
            from sentinelrecon.v2.output.manager import ReportManager
            self.report_manager = ReportManager(config=self.config, logger=self.logger)
        return self.report_manager
        
    def get_credentials_manager(self) -> 'CredentialsManager':
        """
        Get or create credentials manager (lazy-loaded).
        
        Returns:
            CredentialsManager: Manager handling secure credential logic.
        """
        if self.credentials_manager is None:
            from sentinelrecon.v2.security.credentials import CredentialsManager
            self.credentials_manager = CredentialsManager(config=self.config, logger=self.logger)
        return self.credentials_manager
        
    def get_output_manager(self) -> 'OutputManager':
        """
        Get or create generic output manager (lazy-loaded).
        
        Returns:
            OutputManager: Handler for safe file/output generation.
        """
        if self.output_manager is None:
            from sentinelrecon.v2.output.manager import OutputManager
            self.output_manager = OutputManager(config=self.config, logger=self.logger)
        return self.output_manager
