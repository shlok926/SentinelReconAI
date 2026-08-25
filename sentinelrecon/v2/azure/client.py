import logging
from typing import List, Optional
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.subscription import SubscriptionClient

class AzureClient:
    """Azure SDK client with security hardening."""
    
    def __init__(self, config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.credentials = None
        self.subscriptions = []
    
    def authenticate(self) -> bool:
        """Authenticate to Azure using DefaultAzureCredential.
        
        Returns:
            bool: True if authentication successful
        """
        try:
            self.logger.info("Authenticating to Azure...")
            self.credentials = DefaultAzureCredential()
            
            # Verify credentials work
            subscription_client = SubscriptionClient(self.credentials)
            subscriptions = list(subscription_client.subscriptions.list())
            
            self.subscriptions = subscriptions
            self.logger.info(f"Azure authentication successful. Found {len(subscriptions)} subscriptions")
            
            return True
        
        except Exception as e:
            self.logger.error(f"Azure authentication failed: {e}")
            raise
    
    def get_subscriptions(self) -> List[str]:
        """Get list of Azure subscription IDs.
        
        Returns:
            List[str]: Subscription IDs
        """
        if not self.subscriptions:
            self.logger.warning("No subscriptions authenticated")
            return []
        
        return [sub.subscription_id for sub in self.subscriptions]
    
    def get_compute_client(self, subscription_id: str):
        """Create compute management client for subscription.
        
        Args:
            subscription_id: Azure subscription ID
            
        Returns:
            ComputeManagementClient
        """
        self.logger.info(f"Creating compute client for subscription {subscription_id}")
        return ComputeManagementClient(self.credentials, subscription_id)
    
    def get_storage_client(self, subscription_id: str):
        """Create storage management client for subscription.
        
        Args:
            subscription_id: Azure subscription ID
            
        Returns:
            StorageManagementClient
        """
        self.logger.info(f"Creating storage client for subscription {subscription_id}")
        return StorageManagementClient(self.credentials, subscription_id)
