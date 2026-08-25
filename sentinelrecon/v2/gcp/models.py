from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

@dataclass
class GCPInstanceData:
    instance_name: str
    instance_id: str
    zone: str
    machine_type: str
    status: str
    public_ip: Optional[str] = None
    private_ip: str = ""
    disk_encrypted: bool = False
    tags: List[str] = field(default_factory=list)
    risk_level: str = "MEDIUM"
    findings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'instance_name': self.instance_name,
            'instance_id': self.instance_id,
            'zone': self.zone,
            'status': self.status,
            'public_ip': self.public_ip,
            'disk_encrypted': self.disk_encrypted,
            'risk_level': self.risk_level,
            'findings': self.findings,
        }

@dataclass
class GCPStorageBucketData:
    bucket_name: str
    bucket_id: str
    location: str
    uniform_access: bool
    versioning_enabled: bool
    public_access: bool
    risk_level: str = "MEDIUM"
    findings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'bucket_name': self.bucket_name,
            'bucket_id': self.bucket_id,
            'location': self.location,
            'uniform_access': self.uniform_access,
            'versioning_enabled': self.versioning_enabled,
            'public_access': self.public_access,
            'risk_level': self.risk_level,
            'findings': self.findings,
        }
