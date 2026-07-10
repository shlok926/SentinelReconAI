import boto3
from dataclasses import dataclass, field
from typing import List, Optional
import logging

logger = logging.getLogger("SentinelRecon.AWSEnumerator")

@dataclass
class S3Bucket:
    name: str
    public_accessible: bool
    encryption_enabled: bool
    versioning_enabled: bool
    objects_count: int
    size_bytes: float
    risk_level: str
    recommendations: List[str] = field(default_factory=list)

@dataclass
class EC2Instance:
    instance_id: str
    instance_name: str
    ip_private: str
    ip_public: Optional[str]
    security_group: str
    open_ports: List[int]
    public_facing: bool
    tags: dict
    risk_level: str
    recommendations: List[str] = field(default_factory=list)

@dataclass
class IAMFinding:
    user_name: str
    policy_name: str
    policy_arn: str
    is_overly_permissive: bool
    dangerous_permissions: List[str]
    risk_level: str
    recommendations: List[str] = field(default_factory=list)

@dataclass
class CloudScanResult:
    cloud_provider: str = 'AWS'
    s3_buckets: List[S3Bucket] = field(default_factory=list)
    ec2_instances: List[EC2Instance] = field(default_factory=list)
    iam_findings: List[IAMFinding] = field(default_factory=list)
    overall_risk_score: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0

class AWSEnumerator:
    def __init__(self, access_key: str, secret_key: str, region: str = 'us-east-1'):
        if not access_key or not secret_key:
            raise ValueError("AWS credentials are required")
            
        self.s3_client = boto3.client(
            's3', 
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        self.ec2_client = boto3.client(
            'ec2', 
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        self.iam_client = boto3.client(
            'iam', 
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

    def enumerate_s3_buckets(self) -> List[S3Bucket]:
        logger.info("Enumerating S3 buckets...")
        buckets = []
        try:
            response = self.s3_client.list_buckets()
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                is_public = False
                encryption = False
                versioning = False
                
                try:
                    acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
                    is_public = any(g.get('Grantee', {}).get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' for g in acl.get('Grants', []))
                except Exception:
                    pass
                
                try:
                    self.s3_client.get_bucket_encryption(Bucket=bucket_name)
                    encryption = True
                except Exception:
                    pass
                
                try:
                    vers = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
                    if vers.get('Status') == 'Enabled':
                        versioning = True
                except Exception:
                    pass
                
                risk_level = 'LOW'
                recs = []
                if is_public:
                    risk_level = 'CRITICAL'
                    recs.append("Disable public access to S3 bucket.")
                elif not encryption:
                    risk_level = 'HIGH'
                    recs.append("Enable default bucket encryption.")
                elif not versioning:
                    if risk_level != 'HIGH': risk_level = 'MEDIUM'
                    recs.append("Enable bucket versioning to prevent accidental deletions.")
                    
                buckets.append(S3Bucket(
                    name=bucket_name,
                    public_accessible=is_public,
                    encryption_enabled=encryption,
                    versioning_enabled=versioning,
                    objects_count=0, # Simplified
                    size_bytes=0.0, # Simplified
                    risk_level=risk_level,
                    recommendations=recs
                ))
        except Exception as e:
            logger.error(f"S3 enumeration failed: {e}")
        return buckets

    def enumerate_ec2_instances(self) -> List[EC2Instance]:
        logger.info("Enumerating EC2 instances...")
        instances = []
        try:
            response = self.ec2_client.describe_instances()
            for reservation in response.get('Reservations', []):
                for inst in reservation.get('Instances', []):
                    pub_ip = inst.get('PublicIpAddress')
                    priv_ip = inst.get('PrivateIpAddress', 'Unknown')
                    sgs = inst.get('SecurityGroups', [])
                    sg_name = sgs[0]['GroupName'] if sgs else 'Unknown'
                    
                    is_public = pub_ip is not None
                    risk_level = 'MEDIUM' if is_public else 'LOW'
                    recs = []
                    
                    if is_public:
                        recs.append("Ensure public IP is strictly necessary. Restrict SG inbound rules.")
                    
                    instances.append(EC2Instance(
                        instance_id=inst['InstanceId'],
                        instance_name=inst.get('KeyName', inst['InstanceId']),
                        ip_private=priv_ip,
                        ip_public=pub_ip,
                        security_group=sg_name,
                        open_ports=[], # Simplified
                        public_facing=is_public,
                        tags={},
                        risk_level=risk_level,
                        recommendations=recs
                    ))
        except Exception as e:
            logger.error(f"EC2 enumeration failed: {e}")
        return instances

    def check_iam_policies(self) -> List[IAMFinding]:
        logger.info("Enumerating IAM policies...")
        findings = []
        # Simplified IAM finding mock
        try:
            response = self.iam_client.list_users()
            for user in response.get('Users', [])[:5]: # limit for demo
                findings.append(IAMFinding(
                    user_name=user['UserName'],
                    policy_name="InlinePolicyCheck",
                    policy_arn="",
                    is_overly_permissive=False,
                    dangerous_permissions=[],
                    risk_level="LOW",
                    recommendations=["Regularly audit IAM permissions."]
                ))
        except Exception as e:
            logger.error(f"IAM enumeration failed: {e}")
        return findings

    def scan_all(self) -> CloudScanResult:
        s3 = self.enumerate_s3_buckets()
        ec2 = self.enumerate_ec2_instances()
        iam = self.check_iam_policies()
        
        crit = sum(1 for x in s3 + ec2 + iam if getattr(x, 'risk_level', '') == 'CRITICAL')
        high = sum(1 for x in s3 + ec2 + iam if getattr(x, 'risk_level', '') == 'HIGH')
        med = sum(1 for x in s3 + ec2 + iam if getattr(x, 'risk_level', '') == 'MEDIUM')
        
        score = min(100, crit * 25 + high * 15 + med * 5)
        
        return CloudScanResult(
            s3_buckets=s3,
            ec2_instances=ec2,
            iam_findings=iam,
            overall_risk_score=score,
            critical_count=crit,
            high_count=high,
            medium_count=med
        )
