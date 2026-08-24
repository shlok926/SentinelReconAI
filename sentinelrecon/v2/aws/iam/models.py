"""IAM Data Models

Defines immutable data models for representing AWS IAM enumeration results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

@dataclass
class AccessKey:
    access_key_id: str
    status: str  # Active or Inactive
    created_date: datetime
    last_used: Optional[datetime] = None
    days_old: int = 0

@dataclass
class IAMUserData:
    username: str
    user_id: str
    arn: str
    create_date: datetime
    access_keys: List[AccessKey] = field(default_factory=list)
    mfa_enabled: bool = False
    attached_policies: List[str] = field(default_factory=list)
    risk_level: str = "MEDIUM"
    findings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'username': self.username,
            'user_id': self.user_id,
            'arn': self.arn,
            'create_date': self.create_date.isoformat() if self.create_date else None,
            'access_keys': [
                {
                    'id': k.access_key_id,
                    'status': k.status,
                    'days_old': k.days_old
                } for k in self.access_keys
            ],
            'mfa_enabled': self.mfa_enabled,
            'policies': self.attached_policies,
            'risk_level': self.risk_level,
            'findings': self.findings,
        }

@dataclass
class IAMRoleData:
    role_name: str
    role_id: str
    arn: str
    create_date: datetime
    trust_services: List[str] = field(default_factory=list)
    attached_policies: List[str] = field(default_factory=list)
    risk_level: str = "MEDIUM"
    findings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'role_name': self.role_name,
            'role_id': self.role_id,
            'arn': self.arn,
            'create_date': self.create_date.isoformat() if self.create_date else None,
            'trust_services': self.trust_services,
            'policies': self.attached_policies,
            'risk_level': self.risk_level,
            'findings': self.findings,
        }
