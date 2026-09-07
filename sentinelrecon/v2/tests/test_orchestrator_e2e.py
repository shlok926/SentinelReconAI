import pytest
import logging
from unittest.mock import MagicMock, patch

from sentinelrecon.v2.config import Config
from sentinelrecon.v2.container import ServiceContainer
from sentinelrecon.v2.orchestrator import Orchestrator

@pytest.fixture
def logger():
    return logging.getLogger("test_orchestrator")

@pytest.fixture
def config():
    return Config()

@pytest.fixture
def mock_container(config, logger):
    container = MagicMock(spec=ServiceContainer)
    container.config = config
    container.logger = logger
    
    # Mock AWS client
    mock_aws_client = MagicMock()
    mock_aws_client.validate_credentials.return_value = {'Arn': 'arn:aws:iam::123456789012:user/test'}
    container.get_aws_client.return_value = mock_aws_client
    
    return container

@patch('sentinelrecon.v2.aws.s3.scanner.S3Scanner')
@patch('sentinelrecon.v2.aws.ec2.scanner.EC2Scanner')
@patch('sentinelrecon.v2.aws.iam.auditor.IAMAuditor')
def test_orchestrator_aws_scan(MockIAMAuditor, MockEC2Scanner, MockS3Scanner, mock_container, logger):
    """Test Orchestrator runs AWS scans successfully."""
    
    # Setup mocks
    mock_s3_instance = MockS3Scanner.return_value
    mock_s3_instance.scan.return_value = []
    mock_s3_instance.get_summary.return_value = {'total_buckets': 0}
    
    mock_ec2_instance = MockEC2Scanner.return_value
    mock_ec2_instance.scan.return_value = {'us-east-1': []}
    
    mock_iam_instance = MockIAMAuditor.return_value
    mock_iam_instance.audit.return_value = {
        'timestamp': '2023-01-01T00:00:00',
        'user_count': 0,
        'role_count': 0,
        'users': [],
        'roles': []
    }
    
    orchestrator = Orchestrator(mock_container, logger)
    
    # Execute scan
    results = orchestrator.execute_scan(
        account_id="123456789012",
        region="us-east-1",
        scan_types=['all'],
        cloud_provider="aws"
    )
    
    # Verify results structure
    assert results['cloud_provider'] == 'aws'
    assert 's3' in results
    assert 'ec2' in results
    assert 'iam' in results
    assert results['s3']['summary']['total_buckets'] == 0
    assert 'us-east-1' in results['ec2']
    assert results['iam']['user_count'] == 0

@patch('sentinelrecon.v2.azure.scanner.AzureScanner')
@patch('sentinelrecon.v2.azure.client.AzureClient')
def test_orchestrator_azure_scan(MockAzureClient, MockAzureScanner, mock_container, logger):
    """Test Orchestrator runs Azure scans successfully."""
    
    mock_azure_scanner = MockAzureScanner.return_value
    mock_azure_scanner.scan.return_value = {
        'timestamp': '2023-01-01T00:00:00',
        'subscriptions': {}
    }
    
    orchestrator = Orchestrator(mock_container, logger)
    
    # Execute scan
    results = orchestrator.execute_scan(
        scan_types=['all'],
        cloud_provider="azure",
        azure_subscription_id="sub-123"
    )
    
    assert results['cloud_provider'] == 'azure'
    assert 'azure' in results
    assert 'subscriptions' in results['azure']

@patch('sentinelrecon.v2.gcp.scanner.GCPScanner')
@patch('sentinelrecon.v2.gcp.client.GCPClient')
def test_orchestrator_gcp_scan(MockGCPClient, MockGCPScanner, mock_container, logger):
    """Test Orchestrator runs GCP scans successfully."""
    
    mock_gcp_scanner = MockGCPScanner.return_value
    mock_gcp_scanner.scan.return_value = {
        'project_id': 'test-project',
        'instances': [],
        'storage_buckets': []
    }
    
    orchestrator = Orchestrator(mock_container, logger)
    
    # Execute scan
    results = orchestrator.execute_scan(
        scan_types=['all'],
        cloud_provider="gcp",
        gcp_project_id="test-project"
    )
    
    assert results['cloud_provider'] == 'gcp'
    assert 'gcp' in results
    assert results['gcp']['project_id'] == 'test-project'
