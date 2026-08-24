"""AWS Data Models

Defines immutable data models for representing AWS cloud enumeration results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

@dataclass
class S3BucketData:
    """Immutable S3 bucket enumeration result."""
    name: str
    region: str
    creation_date: datetime
    public: bool
    encrypted: bool
    versioning: bool
    logging: bool
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'name': self.name,
            'region': self.region,
            'creation_date': self.creation_date.isoformat() if self.creation_date else None,
            'public': self.public,
            'encrypted': self.encrypted,
            'versioning': self.versioning,
            'logging': self.logging,
            'risk_level': self.risk_level,
            'findings': self.findings,
            'recommendations': self.recommendations,
        }

@dataclass
class EC2InstanceData:
    """EC2 instance enumeration result."""
    instance_id: str
    instance_type: str
    state: str
    public_ip: Optional[str]
    private_ip: str
    security_groups: List[str] = field(default_factory=list)
    iam_role: Optional[str] = None
    ami_id: str = ""
    root_volume_encrypted: bool = False
    risk_level: str = "MEDIUM"
    findings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'instance_id': self.instance_id,
            'instance_type': self.instance_type,
            'state': self.state,
            'public_ip': self.public_ip,
            'private_ip': self.private_ip,
            'security_groups': self.security_groups,
            'iam_role': self.iam_role,
            'ami_id': self.ami_id,
            'root_volume_encrypted': self.root_volume_encrypted,
            'risk_level': self.risk_level,
            'findings': self.findings,
        }

@dataclass
class IAMUserData:
    """IAM user audit result."""
    username: str
    user_id: str
    arn: str
    create_date: datetime
    access_keys_count: int
    mfa_enabled: bool
    policies: List[str] = field(default_factory=list)
    risk_level: str = "MEDIUM"
    findings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'username': self.username,
            'user_id': self.user_id,
            'arn': self.arn,
            'create_date': self.create_date.isoformat() if self.create_date else None,
            'access_keys_count': self.access_keys_count,
            'mfa_enabled': self.mfa_enabled,
            'policies': self.policies,
            'risk_level': self.risk_level,
            'findings': self.findings,
        }

@dataclass
class S3EnumerationResult:
    """Complete S3 enumeration result set."""
    timestamp: datetime
    account_id: str
    region: str
    total_buckets: int
    public_buckets: int
    encrypted_buckets: int
    buckets: List[S3BucketData] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'account_id': self.account_id,
            'region': self.region,
            'total_buckets': self.total_buckets,
            'public_buckets': self.public_buckets,
            'encrypted_buckets': self.encrypted_buckets,
            'buckets': [b.to_dict() for b in self.buckets],
        }
