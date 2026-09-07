import pytest
import boto3
import os
import logging
from moto import mock_aws

from sentinelrecon.v2.config import Config
from sentinelrecon.v2.aws.client import AWSClient
from sentinelrecon.v2.aws.s3.scanner import S3Scanner
from sentinelrecon.v2.aws.ec2.scanner import EC2Scanner

@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'

@pytest.fixture
def logger():
    return logging.getLogger("test_aws")

@pytest.fixture
def config():
    return Config()

@pytest.fixture
def aws_client(aws_credentials, config, logger):
    with mock_aws():
        client = AWSClient(config, logger)
        yield client

@mock_aws
def test_s3_scanner_public_unencrypted(aws_client, config, logger):
    """Test S3 scanner correctly identifies a public, unencrypted bucket."""
    s3 = boto3.client('s3', region_name='us-east-1')
    
    # Create bucket
    bucket_name = 'test-public-bucket'
    s3.create_bucket(Bucket=bucket_name)
    
    # We leave it unencrypted, unversioned, and public (no block public access)
    
    scanner = S3Scanner(aws_client, config, logger)
    results = scanner.scan()
    
    assert len(results) == 1
    bucket = results[0]
    assert bucket.name == bucket_name
    assert bucket.public is True
    assert bucket.encrypted is False
    assert bucket.versioning is False
    assert bucket.logging is False
    assert bucket.risk_level == "CRITICAL"

@mock_aws
def test_s3_scanner_secure_bucket(aws_client, config, logger):
    """Test S3 scanner correctly identifies a secure bucket."""
    s3 = boto3.client('s3', region_name='us-east-1')
    bucket_name = 'test-secure-bucket'
    s3.create_bucket(Bucket=bucket_name)
    
    # Enable versioning
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={'Status': 'Enabled'}
    )
    
    # Enable encryption
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
        }
    )
    
    # Block public access
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    
    scanner = S3Scanner(aws_client, config, logger)
    results = scanner.scan()
    
    assert len(results) == 1
    bucket = results[0]
    assert bucket.name == bucket_name
    assert bucket.public is False
    assert bucket.encrypted is True
    assert bucket.versioning is True
    assert bucket.risk_level in ["LOW", "MEDIUM"]  # Medium if no logging

@mock_aws
def test_ec2_scanner(aws_client, config, logger):
    """Test EC2 scanner correctly identifies instance risks."""
    ec2 = boto3.client('ec2', region_name='us-east-1')
    
    # Create a mock instance
    # moto requires an AMI, usually ami-12c6146b works
    reservation = ec2.run_instances(
        ImageId='ami-12c6146b',
        MinCount=1,
        MaxCount=1,
        InstanceType='t2.micro'
    )
    instance_id = reservation['Instances'][0]['InstanceId']
    
    # EC2 scanner scans all regions by default, let's just scan us-east-1 for speed
    scanner = EC2Scanner(aws_client, config, logger)
    results = scanner.scan(regions=['us-east-1'])
    
    instances = results.get('us-east-1', [])
    assert len(instances) == 1
    
    instance = instances[0]
    assert instance.instance_id == instance_id
    assert instance.instance_type == 't2.micro'
    # Without specific setup, root volume might not be encrypted in moto by default
    # So risk level should be HIGH
    assert instance.risk_level in ["HIGH", "CRITICAL"]
