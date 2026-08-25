import logging
from typing import Dict, List, Optional
from datetime import datetime
from .aws.client import AWSClient
from .aws.s3.scanner import S3Scanner
from .aws.ec2.scanner import EC2Scanner
from .aws.iam.auditor import IAMAuditor
from .output.manager import ReportManager
from .config import Config

class Orchestrator:
    """Orchestrates cloud scanning across multiple services.
    
    Coordinates:
    - Initialization of cloud clients
    - Execution of scanners
    - Result aggregation
    - Report generation
    """
    
    def __init__(self, container, logger: logging.Logger):
        self.container = container
        self.logger = logger
        self.config = container.config
    
    def execute_scan(
        self,
        account_id: Optional[str] = None,
        region: Optional[str] = None,
        scan_types: List[str] = None,
        report_manager: ReportManager = None,
        cloud_provider: str = "aws",
        azure_subscription_id: Optional[str] = None,
        gcp_project_id: Optional[str] = None
    ) -> Dict:
        """Execute cloud scan based on provider and types.
        
        Args:
            account_id: AWS account ID (required for AWS)
            region: AWS region (default: us-east-1)
            scan_types: List of scan types
            report_manager: Report manager instance
            cloud_provider: Cloud provider (aws, azure, gcp, all)
            azure_subscription_id: Azure subscription ID
            gcp_project_id: GCP project ID
            
        Returns:
            Dict: Aggregated scan results
        """
        if scan_types is None:
            scan_types = ['all']
        
        self.logger.info(f"Orchestrating {cloud_provider} scan")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'cloud_provider': cloud_provider,
            's3': None,
            'ec2': None,
            'iam': None,
            'azure': None,
            'gcp': None,
        }
        
        try:
            # AWS Scanning
            if cloud_provider in ['aws', 'all']:
                self.logger.info(f"Scanning AWS account {account_id}")
                
                aws_client = self.container.get_aws_client()
                identity = aws_client.validate_credentials()
                self.logger.info(f"Authenticated as: {identity['Arn']}")
                
                # S3 scan
                if 's3' in scan_types or 'all' in scan_types:
                    self.logger.info("Starting S3 enumeration...")
                    s3_results = self._execute_s3_scan(aws_client)
                    results['s3'] = s3_results
                    self.logger.info(f"S3 scan complete: {len(s3_results.get('buckets', []))} buckets found")
                
                # EC2 scan
                if 'ec2' in scan_types or 'all' in scan_types:
                    self.logger.info("Starting EC2 enumeration...")
                    ec2_results = self._execute_ec2_scan(aws_client, region or 'us-east-1')
                    results['ec2'] = ec2_results
                    total_instances = sum(len(instances) for instances in ec2_results.values())
                    self.logger.info(f"EC2 scan complete: {total_instances} instances found")
                
                # IAM scan
                if 'iam' in scan_types or 'all' in scan_types:
                    self.logger.info("Starting IAM audit...")
                    iam_results = self._execute_iam_audit(aws_client)
                    results['iam'] = iam_results
                    self.logger.info(f"IAM audit complete: {iam_results['user_count']} users")
            
            # Azure Scanning
            if cloud_provider in ['azure', 'all'] and azure_subscription_id:
                self.logger.info(f"Scanning Azure subscription {azure_subscription_id}")
                
                try:
                    from .azure.client import AzureClient
                    from .azure.scanner import AzureScanner
                    
                    azure_client = AzureClient(self.config, self.logger)
                    azure_client.authenticate()
                    
                    azure_scanner = AzureScanner(azure_client, self.config, self.logger)
                    azure_results = azure_scanner.scan()
                    results['azure'] = azure_results
                    
                    self.logger.info("Azure scan complete")
                
                except Exception as e:
                    self.logger.error(f"Azure scan failed: {e}")
                    results['azure'] = {'error': str(e)}
            
            # GCP Scanning
            if cloud_provider in ['gcp', 'all'] and gcp_project_id:
                self.logger.info(f"Scanning GCP project {gcp_project_id}")
                
                try:
                    from .gcp.client import GCPClient
                    from .gcp.scanner import GCPScanner
                    
                    gcp_client = GCPClient(self.config, self.logger, gcp_project_id)
                    gcp_client.authenticate(gcp_project_id)
                    
                    gcp_scanner = GCPScanner(gcp_client, self.config, self.logger)
                    gcp_results = gcp_scanner.scan()
                    results['gcp'] = gcp_results
                    
                    self.logger.info("GCP scan complete")
                
                except Exception as e:
                    self.logger.error(f"GCP scan failed: {e}")
                    results['gcp'] = {'error': str(e)}
            
            return results
        
        except Exception as e:
            self.logger.error(f"Orchestration failed: {e}", exc_info=True)
            raise
    
    def _execute_s3_scan(self, aws_client: AWSClient) -> Dict:
        """Execute S3 enumeration scan.
        
        Returns:
            Dict: S3 scan results
        """
        try:
            scanner = S3Scanner(aws_client, self.config, self.logger)
            buckets = scanner.scan()
            summary = scanner.get_summary()
            
            return {
                'buckets': [b.to_dict() for b in buckets],
                'summary': summary
            }
        
        except Exception as e:
            self.logger.error(f"S3 scan failed: {e}", exc_info=True)
            raise
    
    def _execute_ec2_scan(self, aws_client: AWSClient, region: str) -> Dict:
        """Execute EC2 enumeration scan.
        
        Returns:
            Dict: EC2 scan results by region
        """
        try:
            scanner = EC2Scanner(aws_client, self.config, self.logger)
            results_by_region = scanner.scan(regions=[region])
            
            return {
                reg: [i.to_dict() for i in instances]
                for reg, instances in results_by_region.items()
            }
        
        except Exception as e:
            self.logger.error(f"EC2 scan failed: {e}", exc_info=True)
            raise
    
    def _execute_iam_audit(self, aws_client: AWSClient) -> Dict:
        """Execute IAM audit.
        
        Returns:
            Dict: IAM audit results
        """
        try:
            auditor = IAMAuditor(aws_client, self.config, self.logger)
            results = auditor.audit()
            
            # Convert to serializable format
            return {
                'timestamp': results['timestamp'],
                'user_count': results['user_count'],
                'role_count': results['role_count'],
                'users': [u.to_dict() for u in results['users']],
                'roles': [r.to_dict() for r in results['roles']],
            }
        
        except Exception as e:
            self.logger.error(f"IAM audit failed: {e}", exc_info=True)
            raise
