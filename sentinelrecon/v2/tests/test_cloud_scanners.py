import pytest
import logging
from unittest.mock import MagicMock

from sentinelrecon.v2.config import Config
from sentinelrecon.v2.azure.scanner import AzureScanner
from sentinelrecon.v2.gcp.scanner import GCPScanner

@pytest.fixture
def logger():
    return logging.getLogger("test_cloud")

@pytest.fixture
def config():
    return Config()

@pytest.fixture
def mock_azure_client():
    client = MagicMock()
    # Mock subscriptions
    client.get_subscriptions.return_value = ["sub-123"]
    
    # Mock compute client and VMs
    mock_compute = MagicMock()
    mock_vm = MagicMock()
    mock_vm.name = "test-vm"
    mock_vm.id = "/subscriptions/sub-123/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/test-vm"
    mock_vm.os_profile.os_type = "Linux"
    mock_compute.virtual_machines.list_all.return_value = [mock_vm]
    
    # Simulate unencrypted disk by raising an exception when checking extensions
    mock_compute.virtual_machine_extensions.get.side_effect = Exception("Not found")
    client.get_compute_client.return_value = mock_compute
    
    # Mock storage client and accounts
    mock_storage = MagicMock()
    mock_sa = MagicMock()
    mock_sa.name = "teststorage"
    mock_sa.id = "/subscriptions/sub-123/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/teststorage"
    mock_sa.https_traffic_only = False
    mock_sa.encryption = None
    mock_storage.storage_accounts.list.return_value = [mock_sa]
    client.get_storage_client.return_value = mock_storage
    
    return client

@pytest.fixture
def mock_gcp_client():
    client = MagicMock()
    client.project_id = "test-project"
    
    # Mock compute client and instances
    mock_compute = MagicMock()
    
    # Mock response structure for aggregated_list
    mock_instance = MagicMock()
    mock_instance.name = "test-instance"
    mock_instance.id = 123456
    mock_instance.machine_type = "zones/us-central1-a/machineTypes/e2-micro"
    mock_instance.status = "RUNNING"
    
    mock_nic = MagicMock()
    mock_access_config = MagicMock()
    mock_access_config.nat_i_p = "8.8.8.8"  # Public IP
    mock_nic.access_configs = [mock_access_config]
    mock_instance.network_interfaces = [mock_nic]
    
    mock_response = MagicMock()
    mock_response.instances = [mock_instance]
    
    # aggregated_list returns an iterator of (zone, response)
    mock_compute.aggregated_list.return_value = [("zones/us-central1-a", mock_response)]
    client.get_compute_client.return_value = mock_compute
    
    # Mock storage client and buckets
    mock_storage = MagicMock()
    mock_bucket = MagicMock()
    mock_bucket.name = "test-bucket"
    mock_bucket.id = "test-bucket-id"
    mock_bucket.location = "US"
    mock_bucket.uniform_bucket_level_access_enabled = False
    mock_bucket.versioning_enabled = False
    
    mock_storage.list_buckets.return_value = [mock_bucket]
    client.get_storage_client.return_value = mock_storage
    
    return client

def test_azure_scanner(mock_azure_client, config, logger):
    """Test Azure scanner with mocked SDK client."""
    scanner = AzureScanner(mock_azure_client, config, logger)
    results = scanner.scan()
    
    assert 'subscriptions' in results
    assert 'sub-123' in results['subscriptions']
    
    sub_data = results['subscriptions']['sub-123']
    
    # Check VM
    vms = sub_data['vms']
    assert len(vms) == 1
    assert vms[0]['vm_name'] == "test-vm"
    assert vms[0]['os_disk_encrypted'] is False
    assert vms[0]['risk_level'] == "HIGH"
    
    # Check Storage
    storage_accounts = sub_data['storage_accounts']
    assert len(storage_accounts) == 1
    assert storage_accounts[0]['name'] == "teststorage"
    assert storage_accounts[0]['https_only'] is False
    assert storage_accounts[0]['encryption_enabled'] is False
    assert storage_accounts[0]['risk_level'] == "HIGH"

def test_gcp_scanner(mock_gcp_client, config, logger):
    """Test GCP scanner with mocked SDK client."""
    scanner = GCPScanner(mock_gcp_client, config, logger)
    results = scanner.scan()
    
    assert results['project_id'] == "test-project"
    
    # Check Instances
    instances = results['instances']
    assert len(instances) == 1
    assert instances[0]['instance_name'] == "test-instance"
    assert instances[0]['public_ip'] == "8.8.8.8"
    assert instances[0]['risk_level'] == "HIGH"
    
    # Check Storage Buckets
    buckets = results['storage_buckets']
    assert len(buckets) == 1
    assert buckets[0]['bucket_name'] == "test-bucket"
    assert buckets[0]['uniform_access'] is False
    assert buckets[0]['versioning_enabled'] is False
    assert buckets[0]['risk_level'] == "MEDIUM"
