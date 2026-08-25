import logging
from typing import List, Dict
from datetime import datetime
from google.cloud import compute_v1, storage
from google.api_core.exceptions import GoogleAPIError
from .models import GCPInstanceData, GCPStorageBucketData

class GCPScanner:
    """GCP compute and storage enumeration scanner."""
    
    def __init__(self, gcp_client, config, logger: logging.Logger):
        self.gcp_client = gcp_client
        self.config = config
        self.logger = logger
    
    def scan(self) -> Dict:
        """Scan GCP instances and storage buckets.
        
        Returns:
            Dict: Instances and buckets found
        """
        self.logger.info("Starting GCP enumeration...")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'project_id': self.gcp_client.project_id,
            'instances': [],
            'storage_buckets': [],
        }
        
        try:
            # Scan instances
            instances = self._scan_instances()
            results['instances'] = [i.to_dict() for i in instances]
            self.logger.info(f"Found {len(instances)} GCP instances")
            
            # Scan storage
            buckets = self._scan_storage()
            results['storage_buckets'] = [b.to_dict() for b in buckets]
            self.logger.info(f"Found {len(buckets)} GCP storage buckets")
            
            return results
        
        except Exception as e:
            self.logger.error(f"GCP scan failed: {e}")
            raise
    
    def _scan_instances(self) -> List[GCPInstanceData]:
        """Scan GCP Compute Engine instances.
        
        Returns:
            List[GCPInstanceData]: Instances found
        """
        instances = []
        
        try:
            compute_client = self.gcp_client.get_compute_client()
            request = compute_v1.AggregatedListInstancesRequest(
                project=self.gcp_client.project_id
            )
            
            agg_list = compute_client.aggregated_list(request=request)
            
            for zone, response in agg_list:
                if response.instances:
                    for instance in response.instances:
                        findings = []
                        
                        # Check if public IP
                        public_ip = None
                        if instance.network_interfaces:
                            for nic in instance.network_interfaces:
                                if nic.access_configs:
                                    public_ip = nic.access_configs[0].nat_i_p
                                    findings.append(f"Instance has public IP: {public_ip}")
                        
                        # Risk calculation
                        risk = "HIGH" if public_ip else "MEDIUM"
                        
                        inst_data = GCPInstanceData(
                            instance_name=instance.name,
                            instance_id=instance.id,
                            zone=zone.split('/')[-1],
                            machine_type=instance.machine_type.split('/')[-1],
                            status=instance.status,
                            public_ip=public_ip,
                            risk_level=risk,
                            findings=findings
                        )
                        instances.append(inst_data)
        
        except GoogleAPIError as e:
            self.logger.warning(f"Error scanning instances: {e}")
        
        return instances
    
    def _scan_storage(self) -> List[GCPStorageBucketData]:
        """Scan GCP Storage buckets.
        
        Returns:
            List[GCPStorageBucketData]: Buckets found
        """
        buckets = []
        
        try:
            storage_client = self.gcp_client.get_storage_client()
            
            for bucket in storage_client.list_buckets():
                findings = []
                
                # Check uniform bucket-level access
                uniform = bucket.uniform_bucket_level_access_enabled
                if not uniform:
                    findings.append("Uniform bucket-level access not enabled")
                
                # Check versioning
                versioning = bucket.versioning_enabled
                if not versioning:
                    findings.append("Versioning not enabled")
                
                # Risk calculation
                risk = "MEDIUM" if not uniform else "LOW"
                
                bucket_data = GCPStorageBucketData(
                    bucket_name=bucket.name,
                    bucket_id=bucket.id,
                    location=bucket.location,
                    uniform_access=uniform,
                    versioning_enabled=versioning,
                    public_access=False,  # Would need to check IAM
                    risk_level=risk,
                    findings=findings
                )
                buckets.append(bucket_data)
        
        except GoogleAPIError as e:
            self.logger.warning(f"Error scanning storage: {e}")
        
        return buckets
