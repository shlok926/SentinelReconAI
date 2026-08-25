import logging
import json
from typing import Dict, List
from datetime import datetime

class ReportGenerator:
    """Generates reports from scan results."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def generate_json_report(self, results: Dict) -> str:
        """Generate JSON report.
        
        Args:
            results: Scan results dict
            
        Returns:
            str: JSON formatted report
        """
        self.logger.info("Generating JSON report...")
        
        report = {
            'title': 'SentinelRecon v2.0 - AWS Cloud Enumeration Report',
            'timestamp': results.get('timestamp'),
            'account_id': results.get('account_id'),
            'region': results.get('region'),
            'scan_summary': self._generate_summary(results),
            'detailed_results': results
        }
        
        return json.dumps(report, indent=2, default=str)
    
    def generate_html_report(self, results: Dict) -> str:
        """Generate HTML report.
        
        Args:
            results: Scan results dict
            
        Returns:
            str: HTML formatted report
        """
        self.logger.info("Generating HTML report...")
        
        s3_summary = results.get('s3', {}).get('summary', {}) if results.get('s3') else {}
        ec2_summary = self._get_ec2_summary(results)
        iam_summary = results.get('iam', {}) if results.get('iam') else {}
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SentinelRecon v2.0 Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #e0e0e0; }}
        .header {{ background: #2d2d2d; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .section {{ background: #2d2d2d; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #007acc; }}
        .critical {{ border-left-color: #ff0000; }}
        .high {{ border-left-color: #ff9900; }}
        .medium {{ border-left-color: #ffff00; }}
        .low {{ border-left-color: #00aa00; }}
        h1 {{ color: #007acc; }}
        h2 {{ color: #4ec9b0; border-bottom: 1px solid #444; padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #444; }}
        th {{ background: #3d3d3d; }}
        .critical-text {{ color: #ff4444; font-weight: bold; }}
        .high-text {{ color: #ff9944; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 SentinelRecon v2.0 - AWS Cloud Enumeration Report</h1>
        <p><strong>Account:</strong> {results.get('account_id')}</p>
        <p><strong>Region:</strong> {results.get('region')}</p>
        <p><strong>Scan Time:</strong> {results.get('timestamp')}</p>
    </div>
    
    <div class="section">
        <h2>📊 Executive Summary</h2>
        <table>
            <tr>
                <th>Service</th>
                <th>Resources Found</th>
                <th>Critical Issues</th>
            </tr>
            <tr>
                <td>S3</td>
                <td>{s3_summary.get('total_buckets', 0)}</td>
                <td class="critical-text">{s3_summary.get('critical_risk', 0)}</td>
            </tr>
            <tr>
                <td>EC2</td>
                <td>{ec2_summary.get('total_instances', 0)}</td>
                <td class="critical-text">{ec2_summary.get('critical_instances', 0)}</td>
            </tr>
            <tr>
                <td>IAM</td>
                <td>{iam_summary.get('user_count', 0) + iam_summary.get('role_count', 0)}</td>
                <td>-</td>
            </tr>
"""

        # Azure summary
        if results.get('azure'):
            azure_vms = len(results.get('azure', {}).get('subscriptions', {}).values())
            html += f"""
            <tr>
                <td>Azure VMs</td>
                <td>{azure_vms}</td>
                <td>Check details</td>
            </tr>
            """
        
        # GCP summary
        if results.get('gcp'):
            gcp_instances = len(results.get('gcp', {}).get('instances', []))
            html += f"""
            <tr>
                <td>GCP Instances</td>
                <td>{gcp_instances}</td>
                <td>Check details</td>
            </tr>
            """
            
        html += """
        </table>
    </div>

    
    <div class="section critical">
        <h2>⚠️ Critical Findings</h2>
        <ul>
            <li>Public S3 Buckets: {s3_summary.get('public_buckets', 0)}</li>
            <li>Unencrypted S3 Buckets: {s3_summary.get('total_buckets', 0) - s3_summary.get('encrypted_buckets', 0)}</li>
            <li>EC2 Instances with Public IP: {ec2_summary.get('public_instances', 0)}</li>
            <li>IAM Users without MFA: (See detailed results)</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>📋 Recommendations</h2>
        <ul>
            <li>Enable server-side encryption on all S3 buckets</li>
            <li>Enable versioning on critical S3 buckets</li>
            <li>Enable access logging on all S3 buckets</li>
            <li>Review security groups for overly permissive rules</li>
            <li>Ensure all EC2 volumes are encrypted</li>
            <li>Enforce MFA on all IAM users</li>
            <li>Review and restrict admin policy attachments</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Generated by SentinelRecon v2.0</h2>
        <p>Advanced AWS Cloud Enumeration & Security Analysis</p>
        <p>GitHub: github.com/shlok926/SentinelReconAI</p>
    </div>
</body>
</html>
"""
        return html
    
    def _generate_summary(self, results: Dict) -> Dict:
        """Generate summary statistics.
        
        Returns:
            Dict: Summary of findings
        """
        summary = {
            's3': results.get('s3', {}).get('summary', {}) if results.get('s3') else {},
            'ec2': self._get_ec2_summary(results),
            'iam': {
                'users': results.get('iam', {}).get('user_count', 0) if results.get('iam') else 0,
                'roles': results.get('iam', {}).get('role_count', 0) if results.get('iam') else 0,
            }
        }
        return summary
    
    def _get_ec2_summary(self, results: Dict) -> Dict:
        """Get EC2 summary from results.
        
        Returns:
            Dict: EC2 statistics
        """
        ec2_data = results.get('ec2', {})
        if not ec2_data:
            return {
                'total_instances': 0,
                'public_instances': 0,
                'critical_instances': 0,
            }
            
        total_instances = 0
        public_instances = 0
        critical_instances = 0
        
        for region, instances in ec2_data.items():
            if isinstance(instances, list):
                total_instances += len(instances)
                public_instances += sum(1 for i in instances if i.get('public_ip'))
                critical_instances += sum(1 for i in instances if i.get('risk_level') == 'CRITICAL')
        
        return {
            'total_instances': total_instances,
            'public_instances': public_instances,
            'critical_instances': critical_instances,
        }
