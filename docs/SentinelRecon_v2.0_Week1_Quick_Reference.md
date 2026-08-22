# SentinelRecon v2.0 Week 1: Quick Reference Guide
## Security Checklist + Implementation Tips

**Quick Links:**
- 📐 Architecture: `SentinelRecon_v2.0_Week1_Architecture_Design.md`
- 📋 Prompts: `SentinelRecon_v2.0_Week1_Prompt_Implementation_Plan.md`
- ✅ Security: `SentinelRecon_v2.0_Security_Checklist.md`

---

## 🚀 HOW TO EXECUTE

### Step 1: Read Architecture (30 min)
```
1. Open SentinelRecon_v2.0_Week1_Architecture_Design.md
2. Understand the data flows
3. Review the 5 implementation phases
4. Check the data models
```

### Step 2: Review Security Checklist (30 min)
```
1. Open SentinelRecon_v2.0_Security_Checklist.md
2. Understand each section
3. Copy code snippets for reference
4. Note the security patterns
```

### Step 3: Execute Prompts Sequentially (22-24 hours)
```
1. Start with Prompt 1 (Project Structure)
2. Each prompt builds on previous
3. Follow the daily breakdown
4. Test after each prompt
```

### Step 4: Integrate & Release
```
1. Run end-to-end testing
2. Generate documentation
3. Test with real AWS account
4. Ready for v2.0 release!
```

---

## ✅ SECURITY CHECKLIST - Copy This!

### Code Security Checklist

#### Every File Should Have:
- [ ] Type hints on all functions
- [ ] Docstrings on all classes/functions
- [ ] Error handling (try/except blocks)
- [ ] Logging statements (logger.info/warning/error)
- [ ] No print() statements
- [ ] No hardcoded credentials
- [ ] No hardcoded paths (use Path() from config)
- [ ] PEP 8 compliant

#### AWS Calls Must Have:
- [ ] verify=True (ALWAYS, no exceptions)
- [ ] timeout parameter (30-60 seconds)
- [ ] Error handling (specific exceptions first)
- [ ] Logging before and after
- [ ] No sensitive data in logs

#### File I/O Must Have:
- [ ] symlink detection
- [ ] Permission verification (0o755/0o600)
- [ ] Error handling
- [ ] Secure storage.py usage
- [ ] No world-writable permissions

#### Input Validation Must Have:
- [ ] Reject "-" prefixes
- [ ] Validate AWS account format
- [ ] Validate region format
- [ ] Clear error messages
- [ ] Logging on validation failures

---

## 🎯 PROMPT EXECUTION CHECKLIST

### Before Starting Prompt

```bash
# Terminal 1: Start Claude Code (for implementation)
cd /tmp && claude-code

# Terminal 2: Monitor file creation
watch "find /tmp/sentinelrecon -type f -name '*.py' | wc -l"

# Terminal 3: Check syntax as files are created
cd /tmp/sentinelrecon && python -m py_compile sentinelrecon/**/*.py
```

### Per Prompt Checklist

- [ ] Read prompt description completely
- [ ] Understand prerequisites
- [ ] Check data flow diagram (if applicable)
- [ ] Review security requirements
- [ ] Execute prompt in Claude Code
- [ ] Verify files created
- [ ] Check for syntax errors
- [ ] Run pylint if available
- [ ] Note any blockers
- [ ] Move to next prompt

### After Each Prompt

```bash
# Verify files exist
ls -la /tmp/sentinelrecon/sentinelrecon/v2/aws/

# Check syntax
python -m py_compile /tmp/sentinelrecon/sentinelrecon/v2/aws/*.py

# Count lines of code
find /tmp/sentinelrecon -name "*.py" -exec wc -l {} + | tail -1

# List all modules
find /tmp/sentinelrecon -name "*.py" | sort
```

---

## 🔒 SECURITY HARDENING RULES

### RULE 1: SSL Verification
```python
# ❌ NEVER DO THIS:
requests.get(url, verify=False)  # CRITICAL VULNERABILITY

# ✅ ALWAYS DO THIS:
requests.get(url, verify=True, timeout=30)
```

### RULE 2: Subprocess Security
```python
# ❌ NEVER DO THIS:
subprocess.run(f"aws {cmd}", shell=True)  # INJECTION RISK

# ✅ ALWAYS DO THIS:
subprocess.run(["aws", "--", arg], timeout=300)
```

### RULE 3: File Permissions
```python
# ❌ NEVER DO THIS:
Path(file).write_text(data)  # Default 644 - readable by others

# ✅ ALWAYS DO THIS:
Path(file).write_text(data)
Path(file).chmod(0o600)  # Owner only: rw-------
```

### RULE 4: Symlink Detection
```python
# ❌ NEVER DO THIS:
open(filepath, "w")  # Could be symlink attack

# ✅ ALWAYS DO THIS:
if filepath.is_symlink():
    raise ValueError("Won't write through symlink")
open(filepath, "w")
```

### RULE 5: Credentials
```python
# ❌ NEVER DO THIS:
logger.info(f"Using key: {access_key}")  # LOG LEAK!

# ✅ ALWAYS DO THIS:
logger.info("AWS credentials loaded from ~/.aws/credentials")  # No values
```

### RULE 6: Timeouts
```python
# ❌ NEVER DO THIS:
s3.list_buckets()  # No timeout - could hang forever

# ✅ ALWAYS DO THIS:
s3.list_buckets(timeout=30)  # Always set timeout
```

---

## 🏗️ ARCHITECTURE AT A GLANCE

```
Week 1 Deliverables:
├── sentinelrecon/v2/
│   ├── config.py           (constants + settings)
│   ├── main.py             (orchestration)
│   ├── output/
│   │   ├── storage.py      (secure file I/O)
│   │   └── reporter.py     (report generation)
│   ├── validators/
│   │   └── aws_validator.py (input validation)
│   ├── aws/
│   │   ├── client.py       (boto3 setup)
│   │   ├── s3/
│   │   │   ├── scanner.py  (S3 enumeration)
│   │   │   └── models.py   (data structures)
│   │   ├── ec2/
│   │   │   ├── scanner.py  (EC2 enumeration)
│   │   │   └── models.py   (data structures)
│   │   └── iam/
│   │       ├── auditor.py  (IAM audit)
│   │       └── models.py   (data structures)
│   └── security/
│       ├── credentials.py  (cred handling)
│       └── checklist.py    (security checks)

Output Files:
├── ~/SentinelRecon-Reports/          (0o755)
│   └── aws_enum_2024-08-22/
│       ├── s3_results.json           (0o600)
│       ├── ec2_results.json          (0o600)
│       ├── iam_results.json          (0o600)
│       ├── summary_report.html       (0o600)
│       └── findings.json             (0o600)
```

---

## 📊 METRICS & MILESTONES

### Code Metrics After Week 1

```
Expected Lines of Code: 3,000-4,000
Expected Modules: 12
Expected Classes: 15+
Expected Functions: 50+
Expected Type Hints: 100%
Expected Documentation: 100%
Expected Test Coverage: 80%+
```

### Daily Progress Tracking

| Day | Phase | Prompts | Hours | Expected LOC |
|-----|-------|---------|-------|------------|
| 1 | Foundation | 1-5 | 4 | 600 |
| 2 | S3 | 6-9 | 6 | 1,200 |
| 3 | EC2 | 10-17 | 8 | 1,600 |
| 4 | IAM | 18-22 | 4 | 800 |
| 5 | Integration | 23-25 | 2 | 400 |
| **Total** | | **25** | **24** | **4,600** |

---

## 🐛 DEBUGGING TIPS

### Common Issues & Solutions

#### Issue 1: Import Errors
```python
# Problem: ModuleNotFoundError: No module named 'sentinelrecon'

# Solution:
# 1. Check PYTHONPATH includes /tmp/sentinelrecon
export PYTHONPATH=/tmp/sentinelrecon:$PYTHONPATH

# 2. Verify __init__.py exists in all directories
find /tmp/sentinelrecon -type d -exec touch {}/__init__.py \;

# 3. Check for circular imports
```

#### Issue 2: AWS Authentication
```python
# Problem: NoCredentialsError

# Solution:
# 1. Check ~/.aws/credentials exists
cat ~/.aws/credentials

# 2. Check AWS region in ~/.aws/config
cat ~/.aws/config

# 3. Test with AWS CLI
aws sts get-caller-identity

# 4. Check for typos in account ID
```

#### Issue 3: Permission Denied on Files
```python
# Problem: PermissionError when writing to ~/SentinelRecon-Reports

# Solution:
# 1. Check directory permissions
ls -la ~/SentinelRecon-Reports

# 2. Check parent directory writable
ls -ld ~

# 3. Create directory if missing
mkdir -p ~/SentinelRecon-Reports
chmod 755 ~/SentinelRecon-Reports
```

#### Issue 4: Timeout Errors
```python
# Problem: TimeoutError from boto3 calls

# Solution:
# 1. Increase timeout in config.py
AWS_TIMEOUT = 60  # from 30

# 2. Check internet connection
ping 8.8.8.8

# 3. Check AWS service status
# Visit https://health.aws.amazon.com/
```

---

## 🧪 TESTING COMMANDS

### Syntax Validation
```bash
# Check all Python files for syntax errors
cd /tmp/sentinelrecon
python -m py_compile sentinelrecon/**/*.py

# Or use pylint (if installed)
pylint sentinelrecon/v2/config.py
```

### Import Testing
```bash
# Test imports work
cd /tmp/sentinelrecon
python -c "from sentinelrecon.v2 import config; print(config.AWS_TIMEOUT)"

# Test all submodules
python -c "import sentinelrecon.v2.aws.client"
python -c "import sentinelrecon.v2.aws.s3.scanner"
python -c "import sentinelrecon.v2.aws.ec2.scanner"
python -c "import sentinelrecon.v2.aws.iam.auditor"
```

### Runtime Testing (After Main.py)
```bash
# Test help message
python -m sentinelrecon.v2.main --help

# Test with test account (if available)
python -m sentinelrecon.v2.main --account-id 123456789012 --region us-east-1 --scan-type s3

# Check output
ls -la ~/SentinelRecon-Reports/aws_enum_*/
```

---

## 📞 SUPPORT RESOURCES

### If You Get Stuck

1. **Check Architecture First**
   - Review data flow diagram
   - Check data model structure
   - Verify prerequisites

2. **Re-read Prompt**
   - Especially requirements section
   - Check security checklist
   - Review error handling requirements

3. **Check ThreatMap Lessons**
   - No verify=False (CRITICAL)
   - No shell=True (CRITICAL)
   - Always set timeouts
   - File permissions 0o755/0o600

4. **Debug With Print + Logging**
   - Never use print() - use logging instead
   - Add logger.debug() statements
   - Enable DEBUG level logging

5. **Test Incrementally**
   - Test after each prompt
   - Don't wait for everything to complete
   - Fix issues immediately

---

## ⏱️ TIME MANAGEMENT

### If Behind Schedule

**Cut List (in priority order):**
1. Reduce test coverage (keep core tests)
2. Simplify HTML reports (focus on JSON)
3. Skip advanced EC2 features (focus on instances)
4. Defer comprehensive IAM policy analysis

**Keep Essential:**
- ✅ Security hardening (never cut)
- ✅ Error handling
- ✅ S3 + EC2 core functionality
- ✅ Basic IAM audit

### If Ahead of Schedule

**Bonus Tasks:**
1. Add caching for API calls (boto3 response caching)
2. Add CSV export format
3. Add email reporting
4. Add webhook notifications
5. Add compliance checking (CIS benchmarks)

---

## 🎉 COMPLETION CRITERIA

### Week 1 Complete When:

- [x] All 25 prompts executed
- [x] 4,000+ lines of code written
- [x] All security checks passing
- [x] All tests passing
- [x] End-to-end test with real AWS account successful
- [x] All output files generated correctly
- [x] All file permissions correct (0o755/0o600)
- [x] No hardcoded credentials
- [x] No verify=False in code
- [x] No shell=True in code
- [x] Documentation complete
- [x] Ready for v2.0 release

### After Week 1 Completion:

- Commit code to GitHub (tag v2.0-week1)
- Document lessons learned
- Prepare Week 2 architecture (Azure)
- Update roadmap

---

## 🚀 READY TO START!

**Use this Quick Reference to:**
1. Keep implementation on track
2. Verify security at each step
3. Debug issues quickly
4. Manage time effectively

**Next Action:**
→ Start with Prompt 1: Project Structure
→ Follow daily breakdown
→ Complete in 5 days (22-24 hours)

---

**Let's Build SentinelRecon v2.0! 💪**

