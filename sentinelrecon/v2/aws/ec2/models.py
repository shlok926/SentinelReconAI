"""EC2 Data Models

Defines immutable data models for representing AWS EC2 enumeration results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

@dataclass
class SecurityGroupRule:
    protocol: str
    from_port: int
    to_port: int
    cidr: str
    is_public: bool

@dataclass
class EC2InstanceData:
    instance_id: str
    instance_type: str
    state: str
    public_ip: Optional[str]
    private_ip: str
    security_groups: List[str] = field(default_factory=list)
    iam_role: Optional[str] = None
    ami_id: str = ""
    root_volume_encrypted: bool = False
    security_group_rules: List[SecurityGroupRule] = field(default_factory=list)
    risk_level: str = "MEDIUM"
    findings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
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
