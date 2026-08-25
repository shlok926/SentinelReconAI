from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

@dataclass
class AzureVMData:
    vm_name: str
    vm_id: str
    resource_group: str
    subscription_id: str
    os_type: str
    state: str
    public_ip: Optional[str] = None
    private_ip: str = ""
    os_disk_encrypted: bool = False
    security_group_rules: List[str] = field(default_factory=list)
    risk_level: str = "MEDIUM"
    findings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'vm_name': self.vm_name,
            'vm_id': self.vm_id,
            'resource_group': self.resource_group,
            'state': self.state,
            'public_ip': self.public_ip,
            'os_disk_encrypted': self.os_disk_encrypted,
            'risk_level': self.risk_level,
            'findings': self.findings,
        }

@dataclass
class AzureStorageAccountData:
    name: str
    account_id: str
    resource_group: str
    subscription_id: str
    https_only: bool
    encryption_enabled: bool
    public_access: bool
    risk_level: str = "MEDIUM"
    findings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'account_id': self.account_id,
            'https_only': self.https_only,
            'encryption_enabled': self.encryption_enabled,
            'public_access': self.public_access,
            'risk_level': self.risk_level,
            'findings': self.findings,
        }
