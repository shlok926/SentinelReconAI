"""S3 Scanner Implementation

AWS S3 enumeration and security analysis scanner.
"""

import logging
from typing import List, Optional, Dict
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError
from ..models import S3BucketData

class S3Scanner:
    """AWS S3 enumeration and security analysis scanner."""
    
    def __init__(self, aws_client: 'AWSClient', config: 'Config', logger: logging.Logger):
        self.aws_client = aws_client
        self.config = config
        self.logger = logger
        self.results: List[S3BucketData] = []
    
    def scan(self) -> List[S3BucketData]:
        """Scan all S3 buckets in account.
        
        Returns:
            List[S3BucketData]: Enumeration results for all buckets
        """
        self.logger.info("Starting S3 enumeration...")
        self.results = []
        
        try:
            s3_client = self.aws_client.get_s3_client()
            
            # List all buckets
            response = s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            
            self.logger.info(f"Found {len(buckets)} S3 buckets")
            
            # Analyze each bucket
            for bucket in buckets:
                try:
                    bucket_data = self._analyze_bucket(s3_client, bucket['Name'])
                    self.results.append(bucket_data)
                except ClientError as e:
                    self.logger.warning(f"Error analyzing bucket {bucket['Name']}: {e}")
                    continue
            
            self.logger.info(f"S3 enumeration complete. Analyzed {len(self.results)} buckets")
            return self.results
        
        except NoCredentialsError:
            self.logger.error("AWS credentials not found")
            raise
        except Exception as e:
            self.logger.error(f"S3 enumeration failed: {e}")
            raise
    
    def _analyze_bucket(self, s3_client: object, bucket_name: str) -> S3BucketData:
        """Analyze single S3 bucket for security.
        
        Args:
            s3_client: boto3 S3 client
            bucket_name: Name of bucket to analyze
            
        Returns:
            S3BucketData: Enumeration result for bucket
        """
        self.logger.debug(f"Analyzing bucket: {bucket_name}")
        
        findings = []
        recommendations = []
        
        # Get bucket location
        try:
            location_response = s3_client.get_bucket_location(Bucket=bucket_name)
            region = location_response.get('LocationConstraint') or 'us-east-1'
        except Exception as e:
            self.logger.warning(f"Could not get location for {bucket_name}: {e}")
            region = 'unknown'
        
        # Check public access
        public = self._check_public_access(s3_client, bucket_name, findings, recommendations)
        
        # Check encryption
        encrypted = self._check_encryption(s3_client, bucket_name, findings, recommendations)
        
        # Check versioning
        versioning = self._check_versioning(s3_client, bucket_name, findings, recommendations)
        
        # Check logging
        logging_enabled = self._check_logging(s3_client, bucket_name, findings, recommendations)
        
        # Calculate risk level
        risk_level = self._calculate_risk(public, encrypted, versioning, logging_enabled, len(findings))
        
        return S3BucketData(
            name=bucket_name,
            region=region,
            creation_date=datetime.now(),
            public=public,
            encrypted=encrypted,
            versioning=versioning,
            logging=logging_enabled,
            risk_level=risk_level,
            findings=findings,
            recommendations=recommendations
        )
    
    def _check_public_access(self, s3_client: object, bucket_name: str, findings: List[str], recommendations: List[str]) -> bool:
        """Check if bucket is publicly accessible.
        
        Returns:
            bool: True if bucket is public
        """
        try:
            # Check public access block
            try:
                pub_access = s3_client.get_public_access_block(Bucket=bucket_name)
                config = pub_access.get('PublicAccessBlockConfiguration', {})
                
                if not config.get('BlockPublicAcls', False):
                    findings.append("Public ACLs are not blocked")
                    recommendations.append("Enable 'Block public ACLs'")
                
                if not config.get('BlockPublicPolicy', False):
                    findings.append("Public bucket policy is not blocked")
                    recommendations.append("Enable 'Block public bucket policy'")
                
                is_blocked = config.get('BlockPublicAcls') and config.get('BlockPublicPolicy')
                return not is_blocked
            
            except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                findings.append("No public access block configuration")
                recommendations.append("Configure public access block")
                return True
        
        except Exception as e:
            self.logger.warning(f"Error checking public access for {bucket_name}: {e}")
            return False
    
    def _check_encryption(self, s3_client: object, bucket_name: str, findings: List[str], recommendations: List[str]) -> bool:
        """Check if server-side encryption is enabled.
        
        Returns:
            bool: True if encryption enabled
        """
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            
            if rules:
                self.logger.debug(f"Bucket {bucket_name} has encryption enabled")
                return True
            else:
                findings.append("No server-side encryption configured")
                recommendations.append("Enable default S3 encryption (AES-256 or KMS)")
                return False
        
        except s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            findings.append("No server-side encryption configured")
            recommendations.append("Enable default S3 encryption")
            return False
        
        except Exception as e:
            self.logger.warning(f"Error checking encryption for {bucket_name}: {e}")
            return False
    
    def _check_versioning(self, s3_client: object, bucket_name: str, findings: List[str], recommendations: List[str]) -> bool:
        """Check if versioning is enabled.
        
        Returns:
            bool: True if versioning enabled
        """
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get('Status')
            
            if status == 'Enabled':
                return True
            else:
                findings.append("Versioning is not enabled")
                recommendations.append("Enable bucket versioning for data recovery")
                return False
        
        except Exception as e:
            self.logger.warning(f"Error checking versioning for {bucket_name}: {e}")
            return False
    
    def _check_logging(self, s3_client: object, bucket_name: str, findings: List[str], recommendations: List[str]) -> bool:
        """Check if access logging is enabled.
        
        Returns:
            bool: True if logging enabled
        """
        try:
            logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
            
            if 'LoggingEnabled' in logging_config:
                return True
            else:
                findings.append("Access logging is not enabled")
                recommendations.append("Enable S3 access logging for audit trail")
                return False
        
        except Exception as e:
            self.logger.warning(f"Error checking logging for {bucket_name}: {e}")
            return False
    
    def _calculate_risk(self, public: bool, encrypted: bool, versioning: bool, logging: bool, finding_count: int) -> str:
        """Calculate risk level based on security configuration.
        
        Returns:
            str: Risk level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        if public and not encrypted:
            return "CRITICAL"
        
        if public or not encrypted:
            return "HIGH"
        
        if not versioning or not logging:
            return "MEDIUM"
        
        if finding_count > 0:
            return "LOW"
        
        return "LOW"
    
    def get_summary(self) -> Dict[str, object]:
        """Get summary statistics of S3 enumeration.
        
        Returns:
            dict: Summary statistics
        """
        total = len(self.results)
        public = sum(1 for b in self.results if b.public)
        encrypted = sum(1 for b in self.results if b.encrypted)
        critical = sum(1 for b in self.results if b.risk_level == 'CRITICAL')
        
        return {
            'total_buckets': total,
            'public_buckets': public,
            'encrypted_buckets': encrypted,
            'critical_risk': critical,
            'scan_time': datetime.now().isoformat()
        }
