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
        account_id: str,
        region: str,
        scan_types: List[str],
        report_manager: ReportManager
    ) -> Dict:
        """Execute complete scan based on types.
        
        Args:
            account_id: AWS account ID
            region: AWS region
            scan_types: List of scan types (s3, ec2, iam, or all)
            report_manager: Report manager for output
            
        Returns:
            Dict: Aggregated scan results
        """
        self.logger.info(f"Orchestrating scan for account {account_id}")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'account_id': account_id,
            'region': region,
            'scan_types': scan_types,
            's3': None,
            'ec2': None,
            'iam': None,
        }
        
        try:
            # Get AWS client
            aws_client = self.container.get_aws_client()
            
            # Validate credentials
            identity = aws_client.validate_credentials()
            self.logger.info(f"Authenticated as: {identity['Arn']}")
            
            # Execute S3 scan
            if 's3' in scan_types or 'all' in scan_types:
                self.logger.info("Starting S3 enumeration...")
                s3_results = self._execute_s3_scan(aws_client)
                results['s3'] = s3_results
                self.logger.info(f"S3 scan complete: {len(s3_results.get('buckets', []))} buckets found")
            
            # Execute EC2 scan
            if 'ec2' in scan_types or 'all' in scan_types:
                self.logger.info("Starting EC2 enumeration...")
                ec2_results = self._execute_ec2_scan(aws_client, region)
                results['ec2'] = ec2_results
                total_instances = sum(len(instances) for instances in ec2_results.values())
                self.logger.info(f"EC2 scan complete: {total_instances} instances found")
            
            # Execute IAM audit
            if 'iam' in scan_types or 'all' in scan_types:
                self.logger.info("Starting IAM audit...")
                iam_results = self._execute_iam_audit(aws_client)
                results['iam'] = iam_results
                self.logger.info(f"IAM audit complete: {iam_results['user_count']} users, {iam_results['role_count']} roles")
            
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
