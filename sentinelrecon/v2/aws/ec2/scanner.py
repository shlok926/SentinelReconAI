"""EC2 Scanner Implementation

AWS EC2 enumeration and security analysis scanner.
"""

import logging
from typing import List, Dict, Optional, TYPE_CHECKING
from datetime import datetime
from botocore.exceptions import ClientError
from .models import EC2InstanceData, SecurityGroupRule

if TYPE_CHECKING:
    from sentinelrecon.v2.config import Config
    from sentinelrecon.v2.aws.client import AWSClient

class EC2Scanner:
    """AWS EC2 enumeration and security analysis scanner."""
    
    def __init__(self, aws_client: 'AWSClient', config: 'Config', logger: logging.Logger):
        self.aws_client = aws_client
        self.config = config
        self.logger = logger
        self.results: List[EC2InstanceData] = []
    
    def scan(self, regions: Optional[List[str]] = None) -> Dict[str, List[EC2InstanceData]]:
        """Scan EC2 instances across regions.
        
        Args:
            regions: List of AWS regions to scan (default: config.AWS_REGIONS)
            
        Returns:
            Dict[str, List[EC2InstanceData]]: Results by region
        """
        if regions is None:
            regions = self.config.AWS_REGIONS
        
        self.logger.info(f"Starting EC2 enumeration for regions: {regions}")
        results_by_region = {}
        
        for region in regions:
            self.logger.info(f"Scanning EC2 in region: {region}")
            try:
                ec2_client = self.aws_client.get_ec2_client(region)
                results = self._scan_region(ec2_client, region)
                results_by_region[region] = results
                self.logger.info(f"Found {len(results)} instances in {region}")
            except ClientError as e:
                self.logger.warning(f"Error scanning {region}: {e}")
                results_by_region[region] = []
        
        self.logger.info(f"EC2 enumeration complete")
        return results_by_region
    
    def _scan_region(self, ec2_client: object, region: str) -> List[EC2InstanceData]:
        """Scan single region for EC2 instances.
        
        Args:
            ec2_client: boto3 EC2 client
            region: AWS region
            
        Returns:
            List[EC2InstanceData]: Instances in region
        """
        instances = []
        
        try:
            # Describe all instances (including stopped)
            response = ec2_client.describe_instances()
            
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_data = self._analyze_instance(ec2_client, instance, region)
                    instances.append(instance_data)
        
        except Exception as e:
            self.logger.error(f"Error scanning region {region}: {e}")
        
        return instances
    
    def _analyze_instance(self, ec2_client: object, instance: dict, region: str) -> EC2InstanceData:
        """Analyze single EC2 instance.
        
        Args:
            ec2_client: boto3 EC2 client
            instance: Instance data from describe_instances
            region: AWS region
            
        Returns:
            EC2InstanceData: Analysis result
        """
        instance_id = instance['InstanceId']
        findings = []
        
        # Basic info
        instance_type = instance['InstanceType']
        state = instance['State']['Name']
        public_ip = instance.get('PublicIpAddress')
        private_ip = instance['PrivateIpAddress']
        ami_id = instance['ImageId']
        
        # IAM role
        iam_role = None
        if instance.get('IamInstanceProfile'):
            iam_role = instance['IamInstanceProfile']['Arn'].split('/')[-1]
        
        # Security groups
        security_groups = [sg['GroupName'] for sg in instance.get('SecurityGroups', [])]
        
        # Check public IP + security
        if public_ip:
            findings.append(f"Instance has public IP: {public_ip}")
        
        # Check encryption
        encrypted = self._check_volumes_encrypted(ec2_client, instance_id)
        if not encrypted:
            findings.append("Root volume is not encrypted")
        
        # Security group rules
        sg_rules = self._check_security_groups(ec2_client, instance, findings)
        
        # Calculate risk
        risk_level = self._calculate_risk(public_ip, encrypted, sg_rules, len(findings))
        
        return EC2InstanceData(
            instance_id=instance_id,
            instance_type=instance_type,
            state=state,
            public_ip=public_ip,
            private_ip=private_ip,
            security_groups=security_groups,
            iam_role=iam_role,
            ami_id=ami_id,
            root_volume_encrypted=encrypted,
            security_group_rules=sg_rules,
            risk_level=risk_level,
            findings=findings
        )
    
    def _check_volumes_encrypted(self, ec2_client: object, instance_id: str) -> bool:
        """Check if instance volumes are encrypted.
        
        Returns:
            bool: True if root volume encrypted
        """
        try:
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            
            # Check root volume
            for mapping in instance.get('BlockDeviceMappings', []):
                if mapping.get('DeviceName') in ['/dev/xvda', '/dev/sda1']:
                    volume_id = mapping.get('Ebs', {}).get('VolumeId')
                    if volume_id:
                        vol_response = ec2_client.describe_volumes(VolumeIds=[volume_id])
                        encrypted = vol_response['Volumes'][0].get('Encrypted', False)
                        return encrypted
            
            return False
        except Exception as e:
            self.logger.warning(f"Error checking encryption for {instance_id}: {e}")
            return False
    
    def _check_security_groups(self, ec2_client: object, instance: dict, findings: List[str]) -> List[SecurityGroupRule]:
        """Check security group rules for instance.
        
        Returns:
            List[SecurityGroupRule]: Rules found
        """
        rules = []
        
        try:
            sg_ids = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
            
            for sg_id in sg_ids:
                sg_response = ec2_client.describe_security_groups(GroupIds=[sg_id])
                sg = sg_response['SecurityGroups'][0]
                
                # Check inbound rules
                for rule in sg.get('IpPermissions', []):
                    # Check for 0.0.0.0/0 (public)
                    for cidr in rule.get('IpRanges', []):
                        if cidr.get('CidrIp') == '0.0.0.0/0':
                            findings.append(f"Security group allows public access on port {rule.get('FromPort')}")
                            rules.append(SecurityGroupRule(
                                protocol=rule.get('IpProtocol') or 'all',
                                from_port=rule.get('FromPort', -1),
                                to_port=rule.get('ToPort', -1),
                                cidr='0.0.0.0/0',
                                is_public=True
                            ))
        
        except Exception as e:
            self.logger.warning(f"Error checking security groups: {e}")
        
        return rules
    
    def _calculate_risk(self, public_ip: Optional[str], encrypted: bool, sg_rules: List[SecurityGroupRule], finding_count: int) -> str:
        """Calculate risk level.
        
        Returns:
            str: Risk level
        """
        if public_ip and not encrypted:
            return "CRITICAL"
        
        if public_ip or not encrypted:
            return "HIGH"
        
        if len(sg_rules) > 0:
            return "MEDIUM"
        
        if finding_count > 0:
            return "MEDIUM"
        
        return "LOW"
