"""AWS API Client Wrapper

Provides a secure, factory-based client for AWS SDK (boto3) operations
with built-in timeouts and retries.
"""

import boto3
from botocore.config import Config as BotoConfig
import logging
from typing import Optional

class AWSClient:
    """AWS SDK client with security hardening."""
    
    def __init__(self, config: 'Config', logger: logging.Logger, account_id: Optional[str] = None):
        self.config = config
        self.logger = logger
        self.account_id = account_id
        
        # Configure boto3 with security
        self._boto_config = BotoConfig(
            connect_timeout=config.AWS_TIMEOUT,
            read_timeout=config.AWS_TIMEOUT,
            retries={'max_attempts': config.AWS_RETRY_ATTEMPTS, 'mode': 'adaptive'}
        )
    
    def get_s3_client(self, region: str = "us-east-1") -> object:
        """Create S3 client with security."""
        self.logger.info(f"Creating S3 client for region {region}")
        return boto3.client(
            "s3",
            region_name=region,
            config=self._boto_config,
            # SSL verification is default in boto3 (cannot disable)
        )
    
    def get_ec2_client(self, region: str = "us-east-1") -> object:
        """Create EC2 client with security."""
        self.logger.info(f"Creating EC2 client for region {region}")
        return boto3.client(
            "ec2",
            region_name=region,
            config=self._boto_config
        )
    
    def get_iam_client(self) -> object:
        """Create IAM client (global)."""
        self.logger.info("Creating IAM client")
        return boto3.client(
            "iam",
            config=self._boto_config
        )
    
    def validate_credentials(self) -> dict:
        """Validate AWS credentials are working."""
        try:
            sts = boto3.client("sts", config=self._boto_config)
            identity = sts.get_caller_identity()
            self.account_id = identity["Account"]
            self.logger.info(f"AWS authentication successful. Account: {self.account_id}")
            return identity
        except Exception as e:
            self.logger.error(f"AWS authentication failed: {e}")
            raise

    @staticmethod
    def create_for_account(account_id: str, config: 'Config', logger: logging.Logger) -> 'AWSClient':
        """Factory method to create AWSClient with account validation."""
        client = AWSClient(config, logger, account_id)
        client.validate_credentials()
        return client
