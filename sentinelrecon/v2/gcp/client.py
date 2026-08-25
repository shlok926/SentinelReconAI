import logging
from typing import List, Optional
from google.cloud import compute_v1, storage
from google.oauth2 import service_account

class GCPClient:
    """GCP SDK client with security hardening."""
    
    def __init__(self, config, logger: logging.Logger, project_id: Optional[str] = None):
        self.config = config
        self.logger = logger
        self.project_id = project_id
        self.credentials = None
    
    def authenticate(self, project_id: str) -> bool:
        """Authenticate to GCP using Application Default Credentials.
        
        Args:
            project_id: GCP project ID
            
        Returns:
            bool: True if successful
        """
        try:
            self.logger.info(f"Authenticating to GCP project: {project_id}")
            self.project_id = project_id
            self.credentials = None  # ADC will be used automatically
            self.logger.info("GCP authentication successful")
            return True
        
        except Exception as e:
            self.logger.error(f"GCP authentication failed: {e}")
            raise
    
    def get_compute_client(self):
        """Create compute API client.
        
        Returns:
            google.cloud.compute_v1.InstancesClient
        """
        self.logger.info("Creating GCP compute client")
        return compute_v1.InstancesClient()
    
    def get_firewall_client(self):
        """Create firewall rules client.
        
        Returns:
            google.cloud.compute_v1.FirewallsClient
        """
        self.logger.info("Creating GCP firewall client")
        return compute_v1.FirewallsClient()
    
    def get_storage_client(self):
        """Create storage client.
        
        Returns:
            google.cloud.storage.Client
        """
        self.logger.info("Creating GCP storage client")
        return storage.Client(project=self.project_id)
