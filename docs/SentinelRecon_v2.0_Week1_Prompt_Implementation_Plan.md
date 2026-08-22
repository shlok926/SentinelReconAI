# SentinelRecon v2.0 Week 1: Prompt-Based Implementation Plan
## Task-by-Task Breakdown for Claude Code Implementation

**Status:** IMPLEMENTATION ROADMAP  
**Total Prompts:** 25-30  
**Estimated Duration:** 22-24 hours  
**Methodology:** One prompt = one complete task (file/module)  

---

## 🎯 IMPLEMENTATION PHASES

### PHASE 1: FOUNDATION (4 hours, 5 prompts)

---

## PROMPT 1: Project Structure & __init__.py Files

**Duration:** 30 minutes  
**Difficulty:** Easy  
**Prerequisites:** None

### What to Build
```
Create complete directory structure:
sentinelrecon/
├── v2/
│   ├── __init__.py
│   ├── main.py (stub)
│   ├── config.py (stub)
│   ├── output/
│   │   ├── __init__.py
│   │   ├── manager.py (stub)
│   │   ├── reporter.py (stub)
│   │   └── storage.py (stub)
│   ├── validators/
│   │   ├── __init__.py
│   │   └── aws_validator.py (stub)
│   ├── aws/
│   │   ├── __init__.py
│   │   ├── client.py (stub)
│   │   ├── s3/
│   │   ├── ec2/
│   │   └── iam/
│   └── security/
│       ├── __init__.py
│       ├── credentials.py (stub)
│       └── checklist.py (stub)
```

### Prompt to Use

```
Create the complete SentinelRecon v2.0 project structure for AWS cloud 
enumeration. This is the foundation for all AWS S3, EC2, and IAM scanning.

Requirements:
1. Create directory structure in /tmp/sentinelrecon/
2. Create all __init__.py files with module docstrings
3. Each module gets a placeholder with TODO comments
4. Add type hints and docstrings to all __init__.py files
5. Follow Python packaging best practices

Output to /tmp/sentinelrecon/ directly (not artifacts)

Include:
- sentinelrecon/v2/ main package
- output/ subpackage (for reporting)
- validators/ subpackage (for input validation)
- aws/ subpackage with aws/s3/, aws/ec2/, aws/iam/
- security/ subpackage (for security utilities)

Verify with: `find /tmp/sentinelrecon -type f -name "*.py" | head -20`
```

---

## PROMPT 2: Configuration Module (config.py)

**Duration:** 30 minutes  
**Difficulty:** Easy  
**Prerequisites:** Project structure (Prompt 1)

### What to Build
- Constants and configuration values
- Directory setup
- AWS region definitions
- Security settings
- Logging configuration

### Prompt to Use

```
Create sentinelrecon/v2/config.py - the central configuration module.

This module defines:
1. Directory paths (REPORTS_DIR, etc)
2. AWS settings (regions, timeout, API limits)
3. Security settings (file permissions, SSL verification)
4. Logging configuration
5. Feature flags
6. Constants (max items, sample sizes, etc)

Requirements:
- All values as constants (uppercase)
- AWS_REGIONS should include: us-east-1, us-west-2, eu-west-1, ap-southeast-1
- VERIFY_SSL must always be True (no exceptions)
- OUTPUT_DIR_PERMISSIONS = 0o755
- SENSITIVE_FILE_PERMISSIONS = 0o600
- Use Path() for directory paths
- Add helper functions (get_timestamp(), etc) if needed
- Include docstrings on all definitions

Security Requirements:
- No hardcoded credentials
- No plaintext secrets
- All paths use Path() not strings
- Document every setting

Output to: /tmp/sentinelrecon/sentinelrecon/v2/config.py
```

---

## PROMPT 3: Output Storage Manager (output/storage.py)

**Duration:** 45 minutes  
**Difficulty:** Medium  
**Prerequisites:** config.py

### What to Build
- Safe file I/O with permission control
- Directory creation with 0o755/0o600
- Symlink detection
- Permission verification
- Path safety checks

### Prompt to Use

```
Create sentinelrecon/v2/output/storage.py - handles all file I/O 
with security hardening from ThreatMap audit.

Class: SecureStorage

Methods:
1. safe_mkdir(path, mode=0o755)
   - Create directory with explicit permissions
   - Verify no symlinks in path
   - Log creation
   - Handle exists-already case

2. safe_write(filepath, content, mode=0o600)
   - Write content to file
   - Detect symlinks before write
   - Apply permissions after write
   - Verify write succeeded
   - Log sensitive data warning

3. create_report_directory(scan_timestamp)
   - Create ~/SentinelRecon-Reports/{timestamp}/
   - Return directory path
   - Set correct permissions

4. verify_permissions(path, expected_mode)
   - Check actual permissions match expected
   - Return True/False

Requirements:
- All functions have type hints + docstrings
- Raise ValueError on symlinks
- Raise PermissionError on permission issues
- Log warnings for security issues
- Never write through symlinks
- Test with actual file operations

Security Checklist:
- [x] Check path.is_symlink()
- [x] Check parent is not symlink
- [x] Verify effective permissions (stat)
- [x] Reject if parent is world-writable (except /tmp)
- [x] Chmod after write to ensure 0o600

Output to: /tmp/sentinelrecon/sentinelrecon/v2/output/storage.py
```

---

## PROMPT 4: AWS Client Setup (aws/client.py)

**Duration:** 1 hour  
**Difficulty:** Medium  
**Prerequisites:** config.py

### What to Build
- Boto3 session creation
- Credential loading (with security)
- Regional client creation
- Error handling
- Timeout/SSL configuration

### Prompt to Use

```
Create sentinelrecon/v2/aws/client.py - handles secure AWS client setup.

Class: AWSClientManager

Methods:
1. __init__(account_id: str, region: str = "us-east-1")
   - Initialize boto3 session
   - Load credentials safely
   - Validate authentication
   - Set region

2. get_s3_client()
   - Return configured S3 client
   - Verify SSL (always True)
   - Set timeout from config
   - Add request logging

3. get_ec2_client(region: str)
   - Return regional EC2 client
   - Verify SSL (always True)
   - Set timeout

4. get_iam_client()
   - Return IAM client
   - NOTE: IAM is global, no region param
   - Verify SSL (always True)

5. validate_credentials()
   - Call sts.get_caller_identity()
   - Return account ID, ARN, user ID
   - Raise exception on invalid creds

Requirements:
- Always verify=True for SSL (no exceptions!)
- Set timeout on all calls (30s default)
- Handle botocore exceptions (NoCredentialsError, etc)
- Log all authentication attempts
- No print() statements (use logging)
- Type hints + docstrings on everything

Error Handling:
- NoCredentialsError -> "AWS credentials not found"
- PartialCredentialsError -> "Incomplete credentials"
- InvalidConfigError -> "Invalid AWS configuration"
- General Exception -> Log and re-raise

Output to: /tmp/sentinelrecon/sentinelrecon/v2/aws/client.py
```

---

## PROMPT 5: Security Credentials Handler (security/credentials.py)

**Duration:** 45 minutes  
**Difficulty:** Medium  
**Prerequisites:** aws/client.py

### What to Build
- Safe credential loading
- Validation (not hardcoded)
- MFA support
- Session token handling
- Documentation

### Prompt to Use

```
Create sentinelrecon/v2/security/credentials.py - manages AWS credentials 
securely without ever logging them.

Class: CredentialManager

Methods:
1. load_credentials(source: str = "auto")
   - Auto-detect: IAM role > ~/.aws/credentials > env vars
   - Load from specified source
   - Validate format
   - Return validated credential dict (NO VALUES IN LOGS)

2. validate_not_hardcoded(creds: Dict)
   - Check credentials NOT in code/config
   - Check file permissions are 0o600
   - Warn if ~/.aws/credentials has wrong permissions
   - Return True/False

3. setup_mfa(device_arn: str)
   - Prompt for MFA token
   - Validate 6-digit code
   - Return session token

4. get_account_id()
   - From STS caller identity
   - Cache result
   - Return as string

Requirements:
- NEVER log actual credential values
- Always log "credentials loaded from [source]" (no values)
- Validate ~/.aws/credentials permissions are 0o600
- Warn if permissions are 0o644 or higher
- Support ~/.aws/config for regions
- Check for credentials in environment:
  - AWS_ACCESS_KEY_ID
  - AWS_SECRET_ACCESS_KEY
  - AWS_SESSION_TOKEN
- Warn if environment variables contain hardcoded keys

Format Validation:
- AWS Access Key: AKIA... (20 chars)
- Secret Key: 40 alphanumeric chars
- Session Token: Optional, variable length

Output to: /tmp/sentinelrecon/sentinelrecon/v2/security/credentials.py
```

---

### PHASE 2: S3 ENUMERATION (6 hours, 6 prompts)

---

## PROMPT 6: S3 Data Models (aws/s3/models.py)

**Duration:** 30 minutes  
**Difficulty:** Easy  
**Prerequisites:** config.py

### Prompt to Use

```
Create sentinelrecon/v2/aws/s3/models.py - data models for S3 enumeration.

Use dataclasses for clean data structure:

1. PublicAccessBlockConfiguration
   - block_public_acls: bool
   - ignore_public_acls: bool
   - block_public_policy: bool
   - restrict_public_buckets: bool

2. S3BucketEncryption
   - algorithm: str  # 'AES256' or 'aws:kms'
   - kms_key_id: Optional[str]
   - enabled: bool

3. S3Bucket
   - name: str
   - region: str
   - creation_date: datetime
   - public_access_block: Optional[PublicAccessBlockConfiguration]
   - encryption: Optional[S3BucketEncryption]
   - versioning_enabled: bool
   - logging_enabled: bool
   - object_count: int
   - total_size_bytes: int
   - is_public: bool
   - risk_level: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
   - findings: List[str]
   - recommendations: List[str]

4. S3EnumerationResult
   - timestamp: datetime
   - account_id: str
   - region: str
   - total_buckets: int
   - public_buckets: int
   - encrypted_buckets: int
   - versioned_buckets: int
   - buckets: List[S3Bucket]
   - summary: Dict

Requirements:
- Use @dataclass decorator
- Add __post_init__() if validation needed
- All fields have type hints
- Add helper methods (to_dict(), to_json())
- Document risk_level calculation

Output to: /tmp/sentinelrecon/sentinelrecon/v2/aws/s3/models.py
```

---

## PROMPT 7: S3 Scanner Core (aws/s3/scanner.py)

**Duration:** 2 hours  
**Difficulty:** High  
**Prerequisites:** aws/client.py, aws/s3/models.py

### Prompt to Use

```
Create sentinelrecon/v2/aws/s3/scanner.py - S3 enumeration logic.

Class: S3Scanner

Methods:
1. scan(regions: List[str])
   - Scan S3 in specified regions
   - Call scan_buckets() for each region
   - Consolidate results
   - Return S3EnumerationResult

2. scan_buckets()
   - List all S3 buckets (global operation)
   - For each bucket:
     - get_bucket_details()
     - check_permissions()
     - check_encryption()
     - check_versioning()
     - check_logging()
     - calculate_risk_level()
   - Return List[S3Bucket]

3. get_bucket_details(bucket_name: str)
   - Get creation date, region
   - Estimate object count + size
   - Sample first 100 objects
   - Return bucket metadata

4. check_permissions(bucket_name: str)
   - Get public access block config
   - Get bucket ACL (if public)
   - Get bucket policy (if any)
   - Analyze: Is bucket public?
   - Return PublicAccessBlockConfiguration

5. check_encryption(bucket_name: str)
   - Get default encryption config
   - Return S3BucketEncryption

6. check_versioning(bucket_name: str)
   - Get versioning status
   - Return bool

7. check_logging(bucket_name: str)
   - Get logging configuration
   - Return bool (enabled/disabled)

8. calculate_risk_level(bucket: S3Bucket)
   - LOW: Encrypted + private + versioned + logging
   - MEDIUM: Missing 1-2 features
   - HIGH: Missing 3+ features
   - CRITICAL: Public + unencrypted

9. generate_findings(bucket: S3Bucket)
   - Identify security issues
   - Return List[str] with findings

10. generate_recommendations(bucket: S3Bucket)
    - Security improvement suggestions
    - Return List[str]

Error Handling:
- BotoClientError: Log and skip bucket
- NoSuchBucket: Log warning
- AccessDenied: Log and continue
- Throttling: Exponential backoff (5 retries)

Security Requirements:
- [x] All AWS calls use SSL (verify=True)
- [x] All calls have timeout (30s)
- [x] Handle throttling gracefully
- [x] Log at info/warning level
- [x] Never log bucket contents
- [x] Handle large bucket counts

Testing:
- Test with 0, 1, 5, 100+ buckets
- Test with encrypted and unencrypted
- Test public and private buckets
- Test timeout scenarios

Output to: /tmp/sentinelrecon/sentinelrecon/v2/aws/s3/scanner.py
```

---

## PROMPT 8: S3 Risk Analysis & Findings (aws/s3/scanner.py - part 2)

**Duration:** 1 hour  
**Difficulty:** Medium  
**Prerequisites:** S3 Scanner (Prompt 7)

### Prompt to Use

```
Add to sentinelrecon/v2/aws/s3/scanner.py (same file as Prompt 7):

Implement detailed risk analysis methods:

1. analyze_public_access(bucket: S3Bucket)
   - PUBLIC: public access block disabled
   - PARTIALLY PUBLIC: inconsistent settings
   - PRIVATE: fully blocked
   - Return finding strings

2. analyze_encryption(bucket: S3Bucket)
   - NO ENCRYPTION: finding + HIGH risk
   - AES256: finding + recommendation (use KMS)
   - KMS: finding + OK
   - Return finding strings

3. analyze_versioning(bucket: S3Bucket)
   - If versioning disabled: finding + recommendation
   - If versioning enabled: OK
   - Impact: Data recovery, accidental deletion

4. analyze_logging(bucket: S3Bucket)
   - If logging disabled: finding + recommendation
   - If logging enabled: OK
   - Impact: Audit trail, compliance

5. analyze_object_patterns(bucket: S3Bucket)
   - Sample 100 objects
   - Check for sensitive patterns:
     - Unencrypted PII (ssn, credit card patterns)
     - Credential files (.env, config.json)
     - Backups (*.bak, *.backup)
     - Logs (*.log)
   - Return findings + risk elevation

6. security_recommendations(bucket: S3Bucket)
   - Enable encryption (if disabled)
   - Enable versioning (if disabled)
   - Enable logging (if disabled)
   - Restrict public access (if public)
   - Use KMS encryption (if AES256)
   - Return List[str]

Requirements:
- Findings: Clear, specific, actionable
- Recommendations: Prioritized by impact
- Risk calculation: Based on finding count + severity
- No hardcoded risk multipliers (use config)

Risk Calculation:
- Start: LOW
- +1 factor: MEDIUM (encryption, versioning, logging)
- +2 factors: HIGH
- +3+ factors or PUBLIC: CRITICAL

Output: Append to /tmp/sentinelrecon/sentinelrecon/v2/aws/s3/scanner.py
```

---

## PROMPT 9: S3 Report Generation (output/reporter.py - S3 section)

**Duration:** 1 hour  
**Difficulty:** Medium  
**Prerequisites:** output/storage.py, aws/s3/models.py

### Prompt to Use

```
Create/Update sentinelrecon/v2/output/reporter.py - add S3 reporting:

Class: S3ReportGenerator

Methods:
1. generate_json_report(result: S3EnumerationResult, output_dir: Path)
   - Convert S3EnumerationResult to JSON
   - Pretty format (indent=2)
   - Write to output_dir/s3_results.json
   - chmod 0o600 (sensitive)
   - Return file path

2. generate_html_summary(results: List[S3EnumerationResult], output_dir: Path)
   - Create HTML report
   - Include:
     - Total buckets count
     - Public buckets count
     - Encrypted buckets %
     - Risk distribution (pie chart)
     - Top findings table
     - Recommendations
   - Style: Dark theme (professional)
   - Write to output_dir/s3_summary.html

3. generate_findings_report(result: S3EnumerationResult, output_dir: Path)
   - List all findings by severity
   - HIGH: Public + unencrypted
   - MEDIUM: Missing versioning/logging
   - LOW: Best practice improvements
   - Write to output_dir/s3_findings.txt

4. generate_remediation_guide(result: S3EnumerationResult, output_dir: Path)
   - List all recommendations
   - Grouped by bucket
   - Prioritized by impact
   - Include AWS CLI commands to fix
   - Write to output_dir/s3_remediation.md

Requirements:
- All output files: mode 0o600 (sensitive)
- JSON: machine readable
- HTML: human readable
- Use templates (inline HTML if small)
- Include timestamp
- Include account ID
- Include region(s) scanned

Output to: /tmp/sentinelrecon/sentinelrecon/v2/output/reporter.py
```

---

### PHASE 3: EC2 ENUMERATION (7 hours, 8 prompts)

## PROMPT 10-17: EC2 Enumeration (Similar to S3, but more complex)

**Each EC2 prompt follows same pattern as S3:**
- Models (Prompt 10)
- Scanner core (Prompt 11-12)
- Risk analysis (Prompt 13)
- Report generation (Prompt 14)
- Multi-region support (Prompt 15-16)
- VPC/Network analysis (Prompt 17)

---

### PHASE 4: IAM ENUMERATION (4 hours, 5 prompts)

## PROMPT 18-22: IAM Auditing (Similar structure)

---

### PHASE 5: INTEGRATION (2 hours, 3 prompts)

## PROMPT 23: Main Entry Point (main.py)

**Duration:** 1 hour  
**Difficulty:** Medium

### Prompt to Use

```
Create sentinelrecon/v2/main.py - orchestrates all enumeration.

Function: main()
- ArgumentParser setup
- Load configuration
- Initialize AWS client
- Call S3 scanner
- Call EC2 scanner
- Call IAM auditor
- Consolidate reports
- Generate summary
- Save all results

Arguments:
- --account-id (required)
- --region (optional, default: all)
- --scan-type (s3, ec2, iam, all)
- --output-dir (optional, default: ~/SentinelRecon-Reports)
- --debug (verbose logging)

Output:
- All reports to output_dir
- Console progress messages
- Final summary stats

Requirements:
- Argument validation
- Error handling (show usage on error)
- Progress indication
- Log to file + console
```

---

## PROMPT 24: Testing & Validation

**Duration:** 1 hour  
**Difficulty:** Medium

### What to Test

```
1. End-to-end test with real AWS account
2. Verify all output files created with correct permissions
3. Validate JSON structure of all results
4. Check HTML reports render correctly
5. Verify no sensitive data in logs
6. Test error handling (invalid account, throttling, etc)
7. Verify timestamps and metadata
```

---

## PROMPT 25: Documentation & README

**Duration:** 1 hour  
**Difficulty:** Easy

### What to Document

```
1. README.md
   - Installation
   - Usage examples
   - Output formats
   - Security notes

2. AWS_SETUP.md
   - How to configure AWS credentials
   - IAM permissions needed
   - Regional setup

3. SECURITY.md
   - Security assumptions
   - Credential handling
   - Data protection
   - ThreatMap lessons applied
```

---

## 📋 PROMPT SUMMARY TABLE

| # | Task | Duration | Difficulty | Prereq |
|---|------|----------|-----------|--------|
| 1 | Project Structure | 30m | Easy | None |
| 2 | config.py | 30m | Easy | #1 |
| 3 | storage.py | 45m | Medium | #2 |
| 4 | aws/client.py | 1h | Medium | #2 |
| 5 | security/credentials.py | 45m | Medium | #4 |
| 6 | s3/models.py | 30m | Easy | #2 |
| 7 | s3/scanner.py (core) | 2h | High | #4,#6 |
| 8 | s3/scanner.py (analysis) | 1h | Medium | #7 |
| 9 | reporter.py (S3) | 1h | Medium | #3,#6 |
| 10-17 | EC2 (models, scanner, reporter) | 7h | High | #2-5 |
| 18-22 | IAM (models, auditor, reporter) | 4h | High | #2-5 |
| 23 | main.py | 1h | Medium | #1-22 |
| 24 | Testing | 1h | Medium | #23 |
| 25 | Documentation | 1h | Easy | #23 |

---

## 🚀 DAILY BREAKDOWN

### Day 1 (6 hours)
- Prompts 1-5 (Foundation)
- All 4 hours complete
- Architecture in place

### Day 2 (8 hours)
- Prompts 6-9 (S3 complete)
- All 6 hours complete
- S3 fully functional

### Day 3 (10 hours)
- Prompts 10-17 (EC2 complete)
- All 7 hours complete
- EC2 fully functional

### Day 4 (4 hours)
- Prompts 18-22 (IAM complete)
- All 4 hours complete
- IAM fully functional

### Day 5 (3 hours)
- Prompts 23-25 (Integration, testing, docs)
- All 3 hours complete
- Ready for v2.0 release

---

## ✅ IMPLEMENTATION RULES

### Before Each Prompt

1. Read the prompt carefully
2. Understand prerequisites
3. Check security checklist
4. Review architecture section

### During Implementation

1. Follow ALL type hints
2. Add docstrings to everything
3. Use logging (never print)
4. Handle exceptions explicitly
5. Apply security hardening
6. No hardcoded credentials
7. Verify SSL always True
8. Set timeouts on all calls

### After Each Prompt

1. Verify files created
2. Run syntax check (python -m py_compile)
3. Check imports work
4. Review security checklist
5. Note any blockers

---

## 🎯 FINAL DELIVERABLES

**After all 25 prompts:**

1. ✅ Complete sentinelrecon/v2 package
2. ✅ S3 enumeration module (working)
3. ✅ EC2 enumeration module (working)
4. ✅ IAM audit module (working)
5. ✅ Report generation (HTML, JSON)
6. ✅ Security hardening (ThreatMap lessons)
7. ✅ Full documentation
8. ✅ Test coverage
9. ✅ Ready for v2.0 release

**Total Implementation Time:** 22-24 hours ✅

---

**Ready to Execute Prompts!** 🚀

Use this document for **prompt-by-prompt implementation**.

Each prompt is self-contained and can be executed with Claude Code.

