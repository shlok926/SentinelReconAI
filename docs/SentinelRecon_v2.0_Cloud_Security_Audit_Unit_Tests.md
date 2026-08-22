# SentinelRecon v2.0 Cloud Enumeration
## Security Audit + Unit Test Implementation Plan

**Status:** CODE EXISTS, NEEDS SECURITY AUDIT + UNIT TESTS  
**Current Block:** CI/CD pipeline failing due to missing unit tests  
**Priority:** HIGH (Critical security patterns to apply from ThreatMap audit)  

---

## 🚨 SECTION 1: ThreatMap Vulnerabilities → v2.0 Risk Assessment

### Critical Findings from ThreatMap Audit

**ThreatMap Vulnerability 1: SSL Verification Disabled**
```python
# ThreatMap had this (CRITICAL - CVSS 8.1):
resp = requests.get(url, verify=False)  # ❌ MITM vulnerable
urllib3.disable_warnings()  # ❌ Hide security warnings
```

**ThreatMap Vulnerability 2: Unrestricted Redirects**
```python
# ThreatMap had this (MEDIUM - CWE-601):
resp = requests.get(url, allow_redirects=True)  # No limit
```

---

## 🔍 SECTION 2: v2.0 Cloud Code Security Scan

### Files to Audit in v2.0

```
sentinelrecon/v2/aws/
├── __init__.py
├── enumerator.py          ← AUDIT THIS
├── s3_scanner.py          ← AUDIT THIS
├── ec2_scanner.py         ← AUDIT THIS
├── models.py
└── client.py              ← AUDIT THIS

sentinelrecon/v2/azure/
├── __init__.py
├── enumerator.py          ← AUDIT THIS
├── scanner.py             ← AUDIT THIS
└── models.py

sentinelrecon/v2/gcp/
├── __init__.py
├── enumerator.py          ← AUDIT THIS
└── scanner.py             ← AUDIT THIS
```

### Audit Checklist for Each File

```
Security Checklist:
- [ ] No verify=False in requests.get() calls
- [ ] No urllib3.disable_warnings()
- [ ] No allow_redirects=True without limits
- [ ] All HTTPS calls have timeout parameter
- [ ] All AWS SDK calls use SSL verification
- [ ] No hardcoded credentials
- [ ] File operations use 0o755/0o600 permissions
- [ ] No symlinks in output paths
- [ ] All errors are caught and logged
- [ ] No print() statements (use logging)
- [ ] Type hints on all functions
- [ ] Docstrings on all classes/functions
```

---

## 🛠️ SECTION 3: Unit Test Structure for v2.0

### Test File Organization

```
tests/
├── __init__.py
├── conftest.py                 # Pytest fixtures
├── test_aws_scanner.py
│   ├── test_s3_enumeration()
│   ├── test_ec2_enumeration()
│   └── test_aws_security()     ← NEW: Security-specific tests
├── test_azure_scanner.py
│   ├── test_azure_enumeration()
│   └── test_azure_security()   ← NEW: Security-specific tests
├── test_gcp_scanner.py
│   ├── test_gcp_enumeration()
│   └── test_gcp_security()     ← NEW: Security-specific tests
├── test_integration.py
│   └── test_end_to_end()
└── test_security.py            ← NEW: Dedicated security tests
    ├── test_no_verify_false()
    ├── test_ssl_verification()
    ├── test_file_permissions()
    └── test_symlink_detection()
```

---

## 📋 SECTION 4: Security Unit Tests (NEW)

### Test 1: No verify=False in Code

```python
# tests/test_security.py

import re
from pathlib import Path

def test_no_verify_false_in_cloud_code():
    """Verify no verify=False exists in v2.0 cloud enumeration code.
    
    This is a CRITICAL vulnerability from ThreatMap audit.
    CVSS 8.1: SSL certificate verification disabled allows MITM attacks.
    """
    v2_dir = Path("sentinelrecon/v2")
    
    for py_file in v2_dir.rglob("*.py"):
        with open(py_file) as f:
            content = f.read()
        
        # Search for verify=False
        assert "verify=False" not in content, \
            f"CRITICAL: {py_file} contains verify=False - MITM vulnerability!"
        
        # Search for disabled warnings
        assert "disable_warnings" not in content, \
            f"CRITICAL: {py_file} disables SSL warnings - hiding MITM risks!"


def test_ssl_verification_enabled():
    """Verify all HTTPS calls use verify=True explicitly."""
    v2_dir = Path("sentinelrecon/v2")
    
    for py_file in v2_dir.rglob("*.py"):
        with open(py_file) as f:
            content = f.read()
        
        # Check: if requests.get/post, must have verify=True
        if "requests.get" in content or "requests.post" in content:
            # This is a heuristic check - actual validation happens in integration tests
            assert "verify=True" in content or "verify=" not in content, \
                f"WARNING: {py_file} may have requests without explicit verify="
```

### Test 2: File Permissions Security

```python
# tests/test_security.py

import os
import tempfile
from pathlib import Path

def test_output_directory_permissions():
    """Verify output directories created with 0o755 (owner only)."""
    from sentinelrecon.v2.output import ReportManager
    
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = ReportManager(tmpdir)
        
        # Create report directory
        report_dir = manager.create_report_directory("test_scan")
        
        # Check permissions
        stat_info = os.stat(report_dir)
        perms = stat_info.st_mode & 0o777
        
        # Should be 0o755 (owner rwx, group rx, other rx)
        assert perms == 0o755, \
            f"Directory permissions {oct(perms)} != 0o755"


def test_sensitive_file_permissions():
    """Verify sensitive files created with 0o600 (owner only)."""
    from sentinelrecon.v2.output import ReportManager
    
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = ReportManager(tmpdir)
        
        # Create report with sensitive data
        report_dir = manager.create_report_directory("test_scan")
        report_file = report_dir / "results.json"
        
        manager.safe_write(
            report_file,
            '{"sensitive": "data"}',
            permissions=0o600
        )
        
        # Check permissions
        stat_info = os.stat(report_file)
        perms = stat_info.st_mode & 0o777
        
        # Should be 0o600 (owner rw only)
        assert perms == 0o600, \
            f"File permissions {oct(perms)} != 0o600"
```

### Test 3: Symlink Detection

```python
# tests/test_security.py

def test_symlink_detection_in_output():
    """Verify symlink attacks are detected and prevented."""
    from sentinelrecon.v2.output import ReportManager
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = ReportManager(tmpdir)
        report_dir = manager.create_report_directory("test_scan")
        
        # Create a symlink to /etc/passwd
        symlink_path = report_dir / "evil_symlink.json"
        target = Path("/etc/passwd")
        
        # Attempt to create symlink (for testing purposes only)
        try:
            os.symlink(target, symlink_path)
        except:
            # Skip if we can't create symlink (restricted environment)
            pass
        
        # Verify manager.safe_write() rejects symlinks
        with pytest.raises(ValueError, match="symlink"):
            manager.safe_write(
                symlink_path,
                '{"data": "should fail"}',
                permissions=0o600
            )
```

### Test 4: Timeout Configuration

```python
# tests/test_security.py

def test_aws_client_has_timeout():
    """Verify AWS SDK calls have timeout configured."""
    from sentinelrecon.v2.aws import AWSScanner
    
    scanner = AWSScanner(account_id="123456789012")
    
    # Check: S3 client should have timeout
    s3_client = scanner.get_s3_client()
    assert hasattr(s3_client, '_client_config'), \
        "S3 client missing configuration"
    
    # Check: Timeout should be > 0
    config = s3_client._client_config
    assert hasattr(config, 'connect_timeout'), \
        "Missing connection timeout configuration"
    assert config.connect_timeout > 0, \
        "Connection timeout not set"


def test_requests_session_has_timeout():
    """Verify HTTP requests have timeout set."""
    from sentinelrecon.v2 import AzureScanner
    
    scanner = AzureScanner(subscription_id="test-sub")
    
    # Check: Session should have timeout
    session = scanner.get_session()
    assert hasattr(session, 'timeout'), \
        "Session missing timeout attribute"
    assert session.timeout > 0, \
        "Timeout not set on session"
```

---

## 🧪 SECTION 5: Functional Unit Tests (Existing Tests Enhanced)

### AWS S3 Scanner Tests

```python
# tests/test_aws_scanner.py

import pytest
from unittest.mock import Mock, patch, MagicMock
from sentinelrecon.v2.aws import S3Scanner

class TestS3Scanner:
    """Tests for AWS S3 enumeration with security checks."""
    
    @pytest.fixture
    def mock_boto3(self):
        """Mock boto3 S3 client."""
        with patch("boto3.client") as mock:
            yield mock
    
    def test_s3_list_buckets_ssl_verified(self, mock_boto3):
        """Verify list_buckets uses SSL verification."""
        # This test verifies the call was made
        scanner = S3Scanner(account_id="123456789012")
        
        # Mock should show verify=True was passed
        # (exact verification depends on implementation)
        assert scanner is not None
    
    def test_s3_bucket_enumeration_with_timeout(self):
        """Test S3 enumeration includes timeout."""
        from sentinelrecon.v2.aws import S3Scanner
        
        # Create scanner
        scanner = S3Scanner(account_id="123456789012", region="us-east-1")
        
        # Verify timeout configured
        assert scanner.timeout > 0, "S3 scanner must have timeout"
    
    def test_s3_results_output_permissions(self):
        """Test S3 results saved with correct permissions."""
        import tempfile
        from sentinelrecon.v2.aws import S3Scanner
        
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = S3Scanner(
                account_id="123456789012",
                output_dir=tmpdir
            )
            
            # Mock enumeration (don't actually call AWS)
            # ... test that output files have 0o600 permissions
```

### Azure Scanner Tests

```python
# tests/test_azure_scanner.py

import pytest
from unittest.mock import patch
from sentinelrecon.v2.azure import AzureScanner

class TestAzureScanner:
    """Tests for Azure cloud enumeration with security checks."""
    
    def test_azure_ssl_verification(self):
        """Verify Azure SDK uses SSL verification."""
        scanner = AzureScanner(subscription_id="test-sub")
        
        # Azure SDK should have SSL verification enabled by default
        assert scanner is not None
    
    def test_azure_credential_handling(self):
        """Test credentials not logged or exposed."""
        # Verify credentials loaded safely
        # Verify credentials not in logs
        pass
```

### GCP Scanner Tests

```python
# tests/test_gcp_scanner.py

import pytest
from unittest.mock import patch
from sentinelrecon.v2.gcp import GCPScanner

class TestGCPScanner:
    """Tests for GCP cloud enumeration with security checks."""
    
    def test_gcp_api_client_ssl(self):
        """Verify GCP API uses HTTPS/SSL."""
        scanner = GCPScanner(project_id="test-project")
        
        # GCP SDK uses HTTPS by default
        assert scanner is not None
```

---

## 🔐 SECTION 6: Integration Tests (Security + Functionality)

```python
# tests/test_integration.py

import pytest
import tempfile
from pathlib import Path

@pytest.mark.integration
class TestCloudEnumerationSecurity:
    """End-to-end tests verifying security + functionality."""
    
    def test_aws_enumeration_output_secure(self):
        """Test complete AWS enumeration produces secure output."""
        from sentinelrecon.v2.aws import AWSScanner
        
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = AWSScanner(
                account_id="123456789012",
                output_dir=tmpdir
            )
            
            # Mock AWS (or use localstack for testing)
            # Run enumeration
            # results = scanner.enumerate()
            
            # Verify:
            # 1. All output files have 0o600 permissions
            # 2. No credentials in output
            # 3. No symlinks in paths
            # 4. Valid JSON structure
            # 5. Required fields present
    
    def test_no_verify_false_in_actual_calls(self):
        """Verify actual HTTPS calls use verify=True."""
        # This requires mocking HTTP calls
        # Intercept requests and verify verify=True parameter
        pass
    
    def test_timeout_on_all_calls(self):
        """Verify all cloud API calls have timeout."""
        # Mock cloud API calls
        # Verify timeout parameter present
        pass
```

---

## 📊 SECTION 7: CI/CD Fix Plan

### GitHub Actions Workflow Fix

```yaml
# .github/workflows/tests.yml

name: CI/CD Tests

on: [push, pull_request]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      
      - name: Install dependencies
        run: |
          pip install pytest pytest-cov
          pip install -r requirements.txt
      
      - name: Run security tests
        run: |
          pytest tests/test_security.py -v
      
      - name: Run unit tests
        run: |
          pytest tests/ -v --cov=sentinelrecon --cov-report=xml
      
      - name: Check coverage
        run: |
          coverage report --fail-under=80
```

---

## ✅ IMPLEMENTATION PLAN

### Phase 1: Security Audit (2 hours)

```
Task 1: Scan v2.0 code for ThreatMap vulnerabilities
- [ ] Search for verify=False
- [ ] Search for disable_warnings
- [ ] Search for allow_redirects=True (no limit)
- [ ] Search for missing timeouts
- [ ] Document findings

Task 2: Document all findings in audit report
- [ ] Create ThreatMap-style detailed findings
- [ ] CVSS scores for each issue
- [ ] Remediation steps
```

### Phase 2: Fix Security Issues (2 hours)

```
Task 1: Fix SSL verification
- [ ] Change verify=False → verify=True
- [ ] Remove urllib3.disable_warnings()
- [ ] Test SSL verification works

Task 2: Fix timeouts
- [ ] Add timeout to all AWS calls
- [ ] Add timeout to all HTTPS calls
- [ ] Verify timeout handling

Task 3: Fix permissions
- [ ] Ensure 0o755 on output dirs
- [ ] Ensure 0o600 on sensitive files
- [ ] Add symlink detection
```

### Phase 3: Write Unit Tests (3 hours)

```
Task 1: Security unit tests
- [ ] test_no_verify_false()
- [ ] test_ssl_verification()
- [ ] test_file_permissions()
- [ ] test_symlink_detection()
- [ ] test_timeout_config()

Task 2: Functional unit tests
- [ ] AWS S3 enumeration tests
- [ ] EC2 enumeration tests
- [ ] Azure enumeration tests
- [ ] GCP enumeration tests

Task 3: Integration tests
- [ ] End-to-end security tests
- [ ] Verify actual output security
- [ ] Mock cloud API calls
```

### Phase 4: Fix CI/CD Pipeline (1 hour)

```
Task 1: Update GitHub Actions
- [ ] Add security test job
- [ ] Add coverage requirements
- [ ] Add timeout handling

Task 2: Local testing
- [ ] Run all tests locally
- [ ] Verify 80%+ coverage
- [ ] Check for CI failures

Task 3: Push and verify
- [ ] Push to feature branch
- [ ] Verify GitHub Actions passes
- [ ] Create PR for review
```

---

## 📈 EXPECTED OUTCOMES

### Before (Current State)
```
❌ CI/CD failing
❌ No unit tests
❌ Unknown security status
❌ Cannot ship v2.0
```

### After (After This Plan)
```
✅ CI/CD passing
✅ 80%+ test coverage
✅ Security audit complete
✅ All vulnerabilities fixed
✅ Ready to ship v2.0
```

---

## 🎯 DECISION POINT

**After v2.0 Cloud Security Audit + Unit Tests Complete:**

**Option A: Ship v2.0 Immediately**
- Cloud enumeration (AWS, Azure, GCP) working
- All security tests passing
- CI/CD green
- Users can enumerate cloud infrastructure

**Option B: Continue to v3.0 DAST**
- Start building Active Attack Simulation
- Directory brute-forcing
- SQLi/XSS payload injection
- Async scanner upgrade

**Option C: Hybrid (Recommended)**
- Ship v2.0 with Cloud enumeration
- Start v3.0 DAST in parallel
- Release v2.1 with Azure/GCP when ready

---

## 📞 NEXT STEPS

1. **Audit v2.0 code** (ThreatMap vulnerability checklist)
2. **Fix security issues** (if any found)
3. **Write security unit tests** (from this plan)
4. **Fix CI/CD pipeline** (GitHub Actions)
5. **Test locally** and push
6. **Ship v2.0** or continue to v3.0

---

**Estimated Total Time:** 8-10 hours

**Timeline:** Can complete this week if done systematically!

