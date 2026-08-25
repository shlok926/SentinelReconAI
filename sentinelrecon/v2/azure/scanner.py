import logging
from typing import List, Dict
from datetime import datetime
from azure.core.exceptions import AzureError
from .models import AzureVMData, AzureStorageAccountData

class AzureScanner:
    """Azure VMs and storage enumeration scanner."""
    
    def __init__(self, azure_client, config, logger: logging.Logger):
        self.azure_client = azure_client
        self.config = config
        self.logger = logger
    
    def scan(self) -> Dict:
        """Scan Azure VMs and storage accounts.
        
        Returns:
            Dict: VMs and storage accounts by subscription
        """
        self.logger.info("Starting Azure enumeration...")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'subscriptions': {},
        }
        
        try:
            # Get subscriptions
            subscriptions = self.azure_client.get_subscriptions()
            self.logger.info(f"Found {len(subscriptions)} subscriptions")
            
            # Scan each subscription
            for sub_id in subscriptions:
                self.logger.info(f"Scanning subscription: {sub_id}")
                
                vms = self._scan_vms(sub_id)
                storage = self._scan_storage(sub_id)
                
                results['subscriptions'][sub_id] = {
                    'vms': [vm.to_dict() for vm in vms],
                    'storage_accounts': [sa.to_dict() for sa in storage],
                }
            
            self.logger.info("Azure enumeration complete")
            return results
        
        except Exception as e:
            self.logger.error(f"Azure scan failed: {e}")
            raise
    
    def _scan_vms(self, subscription_id: str) -> List[AzureVMData]:
        """Scan VMs in subscription.
        
        Returns:
            List[AzureVMData]: VMs found
        """
        vms = []
        
        try:
            compute_client = self.azure_client.get_compute_client(subscription_id)
            
            # List all VMs
            for vm in compute_client.virtual_machines.list_all():
                findings = []
                
                # Check encryption
                encrypted = False
                try:
                    disk_encryption = compute_client.virtual_machine_extensions.get(
                        vm.id.split('/')[4],  # resource group
                        vm.name,
                        'AzureDiskEncryption'
                    )
                    encrypted = True
                except:
                    findings.append("OS disk encryption not detected")
                
                # Risk calculation
                risk = "HIGH" if not encrypted else "MEDIUM"
                
                vm_data = AzureVMData(
                    vm_name=vm.name,
                    vm_id=vm.id,
                    resource_group=vm.id.split('/')[4],
                    subscription_id=subscription_id,
                    os_type=vm.os_profile.os_type if vm.os_profile else "Unknown",
                    state="Running",  # Would need instance view for actual state
                    os_disk_encrypted=encrypted,
                    risk_level=risk,
                    findings=findings
                )
                vms.append(vm_data)
        
        except AzureError as e:
            self.logger.warning(f"Error scanning VMs: {e}")
        
        return vms
    
    def _scan_storage(self, subscription_id: str) -> List[AzureStorageAccountData]:
        """Scan storage accounts in subscription.
        
        Returns:
            List[AzureStorageAccountData]: Storage accounts found
        """
        accounts = []
        
        try:
            storage_client = self.azure_client.get_storage_client(subscription_id)
            
            # List all storage accounts
            for account in storage_client.storage_accounts.list():
                findings = []
                
                # Check HTTPS only
                https_only = account.https_traffic_only if hasattr(account, 'https_traffic_only') else False
                if not https_only:
                    findings.append("HTTPS-only traffic not enforced")
                
                # Check encryption
                encrypted = account.encryption is not None
                if not encrypted:
                    findings.append("Encryption not enabled")
                
                # Risk calculation
                risk = "HIGH" if not encrypted else "MEDIUM"
                
                sa_data = AzureStorageAccountData(
                    name=account.name,
                    account_id=account.id,
                    resource_group=account.id.split('/')[4],
                    subscription_id=subscription_id,
                    https_only=https_only,
                    encryption_enabled=encrypted,
                    public_access=False,  # Would need to check blob access
                    risk_level=risk,
                    findings=findings
                )
                accounts.append(sa_data)
        
        except AzureError as e:
            self.logger.warning(f"Error scanning storage: {e}")
        
        return accounts
