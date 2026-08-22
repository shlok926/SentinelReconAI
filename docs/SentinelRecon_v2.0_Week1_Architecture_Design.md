# SentinelRecon v2.0 Week 1: Architecture & Implementation Plan
## AWS Cloud Enumeration Module (S3, EC2, IAM)

**Status:** ARCHITECTURE DESIGN PHASE  
**Week:** 1 of 8  
**Target Duration:** 22-24 hours  
**Scope:** AWS S3, EC2, IAM enumeration with security audit  

---

## 📐 SECTION 1: HIGH-LEVEL ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────┐
│                    SentinelRecon v2.0                       │
│              AWS Cloud Enumeration Module                    │
└─────────────────────────────────────────────────────────────┘
                              │
                ┌─────────────┼─────────────┐
                │             │             │
                ▼             ▼             ▼
          ┌─────────┐   ┌─────────┐   ┌──────────┐
          │   S3    │   │   EC2   │   │   IAM    │
          │ Scanner │   │ Scanner │   │ Auditor  │
          └────┬────┘   └────┬────┘   └────┬─────┘
               │             │             │
               └─────────────┼─────────────┘
                             │
                    ┌────────▼────────┐
                    │  Report Engine  │
                    │  (HTML, JSON)   │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Output Storage │
                    │  (~/Reports)    │
                    └─────────────────┘
```

---

## 🏗️ SECTION 2: DETAILED ARCHITECTURE

### 2.1 Module Structure

```
sentinelrecon/
├── v2/
│   ├── __init__.py
│   ├── main.py                      # Entry point
│   ├── config.py                    # Configuration, constants
│   ├── output/                      # Output management
│   │   ├── __init__.py
│   │   ├── manager.py               # Directory/file management
│   │   ├── reporter.py              # Report generation
│   │   └── storage.py               # File I/O with security
│   ├── validators/                  # Input validation
│   │   ├── __init__.py
│   │   └── aws_validator.py         # AWS-specific validation
│   ├── aws/                         # AWS enumeration
│   │   ├── __init__.py
│   │   ├── client.py                # AWS client setup (with security)
│   │   ├── s3/
│   │   │   ├── __init__.py
│   │   │   ├── scanner.py           # S3 enumeration logic
│   │   │   └── models.py            # Data models (Bucket, Object, etc)
│   │   ├── ec2/
│   │   │   ├── __init__.py
│   │   │   ├── scanner.py           # EC2 enumeration logic
│   │   │   └── models.py            # Data models (Instance, VPC, etc)
│   │   └── iam/
│   │       ├── __init__.py
│   │       ├── auditor.py           # IAM audit logic
│   │       └── models.py            # Data models (User, Role, Policy)
│   └── security/                    # Security utilities
│       ├── __init__.py
│       ├── credentials.py           # AWS credential handling
│       └── checklist.py             # Security hardening checks
```

---

## 🔐 SECTION 3: SECURITY ARCHITECTURE

### 3.1 Credential Handling

```
┌──────────────────────────────────┐
│   AWS Credential Sources         │
├──────────────────────────────────┤
│ 1. IAM Role (EC2/Lambda/ECS)    │ ← Preferred
│ 2. ~/.aws/credentials            │ ← Fallback
│ 3. ~/.aws/config                 │ ← Region config
│ 4. Environment variables (avoid) │ ← Last resort
└──────────────────────────────────┘
            │
            ▼
┌──────────────────────────────────┐
│  Credential Validator            │
├──────────────────────────────────┤
│ - Check format                   │
│ - Validate not hardcoded         │
│ - Check file permissions (0o600) │
│ - Verify not in logs             │
└──────────────────────────────────┘
            │
            ▼
┌──────────────────────────────────┐
│  AWS Client (boto3)              │
├──────────────────────────────────┤
│ - Use temporary credentials      │
│ - Set region explicitly          │
│ - Add request signing            │
│ - Set timeout (30-60s)           │
└──────────────────────────────────┘
```

### 3.2 Output Security

```
Output File Structure:
├── ~/SentinelRecon-Reports/        (mode: 0o755)
│   └── aws_enum_2024-08-22/        (mode: 0o755)
│       ├── s3_results.json         (mode: 0o600) ← SENSITIVE
│       ├── ec2_results.json        (mode: 0o600) ← SENSITIVE
│       ├── iam_results.json        (mode: 0o600) ← SENSITIVE
│       ├── summary_report.html     (mode: 0o600) ← SENSITIVE
│       └── findings.json           (mode: 0o600) ← SENSITIVE

Sensitive Data:
- S3 bucket names + encryption status
- EC2 instances + security groups
- IAM users/roles/policies
- Access patterns + exposure analysis
```

---

## 📊 SECTION 4: DATA FLOW ARCHITECTURE

### 4.1 S3 Enumeration Flow

```
START
  │
  ├─ Authenticate AWS
  │   └─ boto3.session.Session()
  │
  ├─ List All S3 Buckets
  │   ├─ s3_client.list_buckets()
  │   └─ Store: Bucket name, creation date, region
  │
  ├─ For Each Bucket:
  │   ├─ Check Permissions
  │   │   ├─ Public access block settings
  │   │   ├─ Bucket ACL
  │   │   ├─ Bucket policy
  │   │   └─ Access point policies
  │   │
  │   ├─ Check Encryption
  │   │   ├─ Default encryption enabled?
  │   │   └─ Encryption algorithm (AES256, KMS)
  │   │
  │   ├─ Check Versioning
  │   │   └─ Version control enabled?
  │   │
  │   ├─ Check Logging
  │   │   └─ Access logging enabled?
  │   │
  │   ├─ List Objects (sampling)
  │   │   ├─ First 100 objects
  │   │   ├─ Check for sensitive patterns
  │   │   └─ Estimate total size
  │   │
  │   └─ Store Results:
  │       {
  │         "bucket_name": "example-bucket",
  │         "region": "us-east-1",
  │         "public_access_block": {...},
  │         "encryption": "AES256",
  │         "versioning": "Enabled",
  │         "object_count": 1000,
  │         "total_size_gb": 50,
  │         "risk_level": "MEDIUM"
  │       }
  │
  ├─ Generate S3 Report
  │   ├─ Count: Public, encrypted, unversioned
  │   ├─ Findings: Risks identified
  │   └─ Remediation: Fix recommendations
  │
  └─ END (Save to JSON)
```

### 4.2 EC2 Enumeration Flow

```
START
  │
  ├─ For Each AWS Region:
  │   ├─ Authenticate (regional endpoint)
  │   │
  │   ├─ List Instances
  │   │   ├─ ec2_client.describe_instances()
  │   │   └─ Filter: All states (running, stopped, etc)
  │   │
  │   ├─ For Each Instance:
  │   │   ├─ Instance Details
  │   │   │   ├─ ID, type, state, launch time
  │   │   │   ├─ Public IP, private IP
  │   │   │   └─ AMI ID, OS, tags
  │   │   │
  │   │   ├─ Security Groups
  │   │   │   ├─ Inbound rules
  │   │   │   ├─ Outbound rules
  │   │   │   └─ Check: Overly permissive (0.0.0.0/0)
  │   │   │
  │   │   ├─ IAM Role
  │   │   │   ├─ Attached role
  │   │   │   └─ Check: Instance profile permissions
  │   │   │
  │   │   ├─ Network Interfaces
  │   │   │   ├─ VPC, subnet
  │   │   │   └─ Network ACLs
  │   │   │
  │   │   ├─ Storage
  │   │   │   ├─ Root volume encryption
  │   │   │   ├─ EBS volumes
  │   │   │   └─ Volume encryption status
  │   │   │
  │   │   ├─ Monitoring
  │   │   │   ├─ CloudWatch enabled?
  │   │   │   └─ Detailed monitoring?
  │   │   │
  │   │   └─ Store Results:
  │   │       {
  │   │         "instance_id": "i-1234567890abcdef0",
  │   │         "public_ip": "1.2.3.4",
  │   │         "private_ip": "10.0.0.1",
  │   │         "security_groups": [...],
  │   │         "iam_role": "EC2-Full-Access",
  │   │         "encrypted": false,
  │   │         "risk_level": "HIGH"
  │   │       }
  │   │
  │   ├─ List VPCs
  │   │   ├─ VPC ID, CIDR, tags
  │   │   ├─ Flow logs enabled?
  │   │   └─ VPC endpoints (private access)
  │   │
  │   └─ List Security Groups
  │       ├─ Rules (inbound/outbound)
  │       ├─ Check: Unrestricted access (0.0.0.0/0)
  │       └─ Risk assessment
  │
  ├─ Generate EC2 Report
  │   ├─ Count: Running, stopped, encrypted
  │   ├─ Findings: Exposure, misconfiguration
  │   └─ Remediation: Security improvements
  │
  └─ END (Save to JSON)
```

### 4.3 IAM Enumeration Flow

```
START
  │
  ├─ List IAM Users
  │   ├─ iam_client.list_users()
  │   │
  │   └─ For Each User:
  │       ├─ Access Keys
  │       │   ├─ Count active keys
  │       │   ├─ Last rotated date
  │       │   ├─ Check: Keys > 90 days old
  │       │   └─ Check: Unused access keys
  │       │
  │       ├─ Policies (Inline + Attached)
  │       │   ├─ List all policies
  │       │   ├─ Parse policy document
  │       │   ├─ Check: Admin access
  │       │   └─ Check: Overly permissive (*)
  │       │
  │       ├─ Groups
  │       │   └─ Group membership
  │       │
  │       ├─ MFA
  │       │   ├─ MFA enabled?
  │       │   └─ MFA device type
  │       │
  │       └─ Store Results:
  │           {
  │             "username": "admin-user",
  │             "access_keys": 2,
  │             "mfa_enabled": false,
  │             "policies": ["AdministratorAccess"],
  │             "risk_level": "CRITICAL"
  │           }
  │
  ├─ List IAM Roles
  │   ├─ iam_client.list_roles()
  │   │
  │   └─ For Each Role:
  │       ├─ Trust Relationships
  │       │   ├─ Service principals
  │       │   ├─ Cross-account access
  │       │   └─ Check: Overly trusting
  │       │
  │       ├─ Attached Policies
  │       │   ├─ Managed policies
  │       │   ├─ Inline policies
  │       │   └─ Permission analysis
  │       │
  │       ├─ Used By
  │       │   ├─ Attached to users/groups
  │       │   ├─ Attached to resources
  │       │   └─ Last used information
  │       │
  │       └─ Store Results:
  │           {
  │             "role_name": "EC2-Instance-Role",
  │             "trust_services": ["ec2.amazonaws.com"],
  │             "policies": ["S3FullAccess"],
  │             "risk_level": "MEDIUM"
  │           }
  │
  ├─ List Policies
  │   ├─ iam_client.list_policies()
  │   └─ For each policy:
  │       ├─ Get policy document
  │       ├─ Parse JSON
  │       ├─ Check: Overly permissive statements
  │       └─ Check: Wildcard permissions (*)
  │
  ├─ Cross-Account Analysis
  │   ├─ Find roles with cross-account access
  │   ├─ Check: Trust relationship validation
  │   └─ Identify external account dependencies
  │
  ├─ Generate IAM Report
  │   ├─ Count: Users, roles, policies
  │   ├─ Findings: Excessive permissions, old keys
  │   └─ Remediation: Recommendations
  │
  └─ END (Save to JSON)
```

---

## 📋 SECTION 5: DATA MODELS

### 5.1 S3 Models

```python
# Data structures returned by S3 scanner

@dataclass
class S3Bucket:
    name: str
    region: str
    creation_date: datetime
    public_access_block: Dict
    encryption: Optional[str]  # 'AES256', 'aws:kms', None
    versioning: bool
    logging_enabled: bool
    object_count: int
    total_size_bytes: int
    risk_level: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    findings: List[str]
    recommendations: List[str]

@dataclass
class S3EnumerationResult:
    timestamp: datetime
    account_id: str
    total_buckets: int
    buckets: List[S3Bucket]
    summary: Dict  # Statistics, counts
```

### 5.2 EC2 Models

```python
@dataclass
class SecurityGroup:
    id: str
    name: str
    vpc_id: str
    inbound_rules: List[Dict]
    outbound_rules: List[Dict]
    risk_level: str

@dataclass
class EC2Instance:
    instance_id: str
    instance_type: str
    state: str  # 'running', 'stopped', etc
    public_ip: Optional[str]
    private_ip: str
    security_groups: List[SecurityGroup]
    iam_role: Optional[str]
    ami_id: str
    root_volume_encrypted: bool
    ebs_volumes: List[Dict]
    monitoring_enabled: bool
    risk_level: str
    findings: List[str]

@dataclass
class EC2EnumerationResult:
    timestamp: datetime
    account_id: str
    regions: Dict[str, Dict]  # region -> instances/vpcs/sgs
    total_instances: int
    summary: Dict
```

### 5.3 IAM Models

```python
@dataclass
class IAMPolicy:
    name: str
    type: str  # 'Managed', 'Inline'
    arn: str
    policy_document: Dict
    is_overly_permissive: bool
    wildcard_actions: List[str]

@dataclass
class IAMUser:
    username: str
    user_id: str
    arn: str
    create_date: datetime
    access_keys: List[Dict]
    mfa_enabled: bool
    policies: List[IAMPolicy]
    groups: List[str]
    last_activity: Optional[datetime]
    risk_level: str
    findings: List[str]

@dataclass
class IAMRole:
    role_name: str
    role_id: str
    arn: str
    trust_services: List[str]
    trust_accounts: List[str]
    policies: List[IAMPolicy]
    risk_level: str
    findings: List[str]

@dataclass
class IAMAuditResult:
    timestamp: datetime
    account_id: str
    users: List[IAMUser]
    roles: List[IAMRole]
    policies: List[IAMPolicy]
    summary: Dict
```

---

## 🎯 SECTION 6: IMPLEMENTATION ROADMAP (Week 1)

### Phase 1: Foundation Setup (Hours 1-4)

**Task 1.1: Project Structure & Configuration** (1 hour)
```
✓ Create directory structure
✓ Set up __init__.py files
✓ Create config.py with constants
✓ Create .env template (for AWS credentials)
✓ Set up logging configuration
```

**Task 1.2: Security Infrastructure** (1.5 hours)
```
✓ Implement output/manager.py (directory creation with 0o755/0o600)
✓ Implement security/credentials.py (AWS credential loading)
✓ Implement security/checklist.py (security hardening checks)
✓ Add symlink detection
✓ Add permission verification
```

**Task 1.3: AWS Client Setup** (1.5 hours)
```
✓ Implement aws/client.py
  - boto3 session creation
  - Region support (US, EU, AP)
  - Error handling
  - Timeout configuration
  - SSL verification (ALWAYS verify=True)
```

---

### Phase 2: S3 Enumeration (Hours 5-10)

**Task 2.1: S3 Scanner Core** (2 hours)
```
✓ Implement aws/s3/scanner.py
  - list_buckets()
  - check_permissions() per bucket
  - check_encryption() per bucket
  - check_versioning() per bucket
  - check_logging() per bucket
  - sample_objects() first 100
```

**Task 2.2: S3 Risk Analysis** (1.5 hours)
```
✓ Analyze findings
✓ Calculate risk_level (LOW/MEDIUM/HIGH/CRITICAL)
✓ Generate recommendations
✓ Parse public access block
```

**Task 2.3: S3 Report Generation** (1.5 hours)
```
✓ Implement output/reporter.py for S3
✓ Generate JSON output
✓ Generate HTML summary
✓ Create findings list
```

---

### Phase 3: EC2 Enumeration (Hours 11-17)

**Task 3.1: EC2 Scanner Core** (2 hours)
```
✓ Implement aws/ec2/scanner.py
  - describe_instances() per region
  - describe_security_groups() per region
  - describe_vpcs() per region
  - describe_network_acls() per region
```

**Task 3.2: EC2 Security Analysis** (2 hours)
```
✓ Check security groups (0.0.0.0/0 rules)
✓ Check IAM roles attached
✓ Check encryption status
✓ Check monitoring enabled
✓ Analyze risk levels
```

**Task 3.3: EC2 Multi-Region Support** (1.5 hours)
```
✓ Support all AWS regions
✓ Parallel region scanning
✓ Consolidate results
✓ Handle regional differences
```

**Task 3.4: EC2 Report Generation** (1.5 hours)
```
✓ Generate JSON output
✓ Generate HTML summary
✓ Regional breakdown
✓ Risk consolidation
```

---

### Phase 4: IAM Enumeration (Hours 18-21)

**Task 4.1: IAM Auditor Core** (1.5 hours)
```
✓ Implement aws/iam/auditor.py
  - list_users()
  - list_roles()
  - list_policies()
  - get_policy_document() (inline + managed)
```

**Task 4.2: IAM Security Analysis** (1.5 hours)
```
✓ Check overly permissive policies (wildcard *)
✓ Check access key age
✓ Check MFA enabled
✓ Check cross-account access
✓ Analyze risk levels
```

**Task 4.3: IAM Report Generation** (1 hour)
```
✓ Generate JSON output
✓ Generate HTML summary
✓ Policy analysis
✓ Risk consolidation
```

---

### Phase 5: Integration & Testing (Hours 22-24)

**Task 5.1: Main Entry Point** (1 hour)
```
✓ Implement main.py
✓ Orchestrate S3 → EC2 → IAM
✓ Argument parsing (--account-id, --region, etc)
✓ Progress reporting
```

**Task 5.2: Testing** (1 hour)
```
✓ Test with real AWS account
✓ Verify output formats
✓ Check file permissions
✓ Validate JSON structure
✓ Test error handling
```

---

## 📝 SECTION 7: IMPLEMENTATION CHECKLIST

### Code Quality Checklist

- [ ] All imports at top
- [ ] Type hints on all functions
- [ ] Docstrings on all classes/functions
- [ ] Error handling (try/except)
- [ ] Logging statements (info, warning, error)
- [ ] No hardcoded credentials
- [ ] No print() statements (use logging)
- [ ] Follow PEP 8 (autopep8 clean)

### Security Checklist (from ThreatMap audit)

- [ ] No verify=False on HTTPS
- [ ] No subprocess shell=True
- [ ] No hardcoded paths (use /usr/bin/aws)
- [ ] Output dirs: mode 0o755
- [ ] Sensitive files: mode 0o600
- [ ] Reject inputs starting with "-"
- [ ] Symlink detection
- [ ] Timeout on all AWS calls

### AWS Best Practices Checklist

- [ ] Use IAM roles (not access keys)
- [ ] Verify credentials before use
- [ ] Handle throttling (exponential backoff)
- [ ] Pagination support (list operations)
- [ ] Regional filtering
- [ ] Error messages don't expose sensitive data
- [ ] Rate limiting (respect AWS API limits)

---

## 🔧 SECTION 8: CONFIGURATION TEMPLATE

```python
# v2/config.py

import os
from pathlib import Path

# Directories
HOME_DIR = Path.home()
REPORTS_DIR = HOME_DIR / "SentinelRecon-Reports"
CURRENT_SCAN_DIR = None  # Set at runtime

# AWS Configuration
AWS_TIMEOUT = 30  # seconds
AWS_REGIONS = [
    "us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"
    # Add more as needed
]

# Security
OUTPUT_DIR_PERMISSIONS = 0o755
SENSITIVE_FILE_PERMISSIONS = 0o600
MAX_REDIRECTS = 5
VERIFY_SSL = True  # ALWAYS True

# Logging
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Limits
MAX_S3_OBJECTS_SAMPLE = 100
MAX_EC2_PER_REGION = 1000
MAX_IAM_ITEMS = 500
REQUEST_TIMEOUT = 30

# Feature flags
ENABLE_S3_SCAN = True
ENABLE_EC2_SCAN = True
ENABLE_IAM_AUDIT = True
```

---

## 📊 SECTION 9: ERROR HANDLING STRATEGY

### Handled Exceptions

```python
# AWS Errors
- botocore.exceptions.ClientError
  - NoCredentialsError
  - PartialCredentialsError
  - InvalidConfigError
  - AccessDenied
  - Throttling
  - ServiceUnavailable

# Network Errors
- requests.exceptions.Timeout
- requests.exceptions.ConnectionError
- requests.exceptions.SSLError

# File I/O Errors
- FileExistsError
- PermissionError
- OSError

# Input Validation Errors
- ValueError (invalid input)
- TypeError (wrong type)
```

### Error Handling Pattern

```python
try:
    # AWS operation
    result = s3_client.list_buckets()
except botocore.exceptions.ClientError as e:
    error_code = e.response['Error']['Code']
    if error_code == 'AccessDenied':
        logger.error("Access denied to S3. Check IAM permissions.")
    elif error_code == 'ThrottlingException':
        logger.warning("AWS throttling. Retrying after backoff...")
        # Implement exponential backoff
    else:
        logger.error(f"AWS error: {error_code}")
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    raise
```

---

## 🚀 SECTION 10: LAUNCH SEQUENCE

### Week 1 Implementation Order

1. **Day 1-2:** Foundation (hours 1-4)
   - Project structure
   - Security infrastructure
   - AWS client setup

2. **Day 2-3:** S3 Enumeration (hours 5-10)
   - S3 scanner implementation
   - Risk analysis
   - Report generation

3. **Day 3-4:** EC2 Enumeration (hours 11-17)
   - EC2 scanner core
   - Security analysis
   - Multi-region support
   - Report generation

4. **Day 4-5:** IAM Enumeration (hours 18-21)
   - IAM auditor core
   - Policy analysis
   - Report generation

5. **Day 5:** Integration & Testing (hours 22-24)
   - Main entry point
   - End-to-end testing
   - Documentation

---

## 📦 SECTION 11: DELIVERABLES (Week 1)

### Code Deliverables
- ✅ `v2/` package (complete module)
- ✅ `requirements.txt` (boto3, etc)
- ✅ `.env.example` (credential template)
- ✅ `README_AWS.md` (usage guide)

### Output Deliverables
- ✅ S3 enumeration results (JSON)
- ✅ EC2 enumeration results (JSON)
- ✅ IAM audit results (JSON)
- ✅ Combined HTML report
- ✅ Findings/recommendations

### Documentation
- ✅ Architecture documentation
- ✅ API documentation (docstrings)
- ✅ Setup guide (how to run)
- ✅ Security assumptions

---

## ✅ READY FOR IMPLEMENTATION

This architecture is designed to be implemented **prompt-by-prompt** using Claude Code/Cowork.

**Next Step:** Break each task into prompts and implement iteratively.

Each prompt will:
1. Create files (or edit existing)
2. Follow security checklist
3. Include tests/validation
4. Output to `/tmp/sentinelrecon`

---

**Architecture Complete ✅**

**Ready for Prompt-Wise Implementation 🚀**

