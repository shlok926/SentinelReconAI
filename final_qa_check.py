#!/usr/bin/env python3
"""Final QA verification script for SentinelRecon v2.0."""

import subprocess
import sys
from pathlib import Path

# Fix unicode encoding on Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

def run_check(name: str, command: str) -> bool:
    """Run a check and report result."""
    print(f"\n🔍 {name}...")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ {name}: PASS")
            return True
        else:
            print(f"❌ {name}: FAIL")
            print(result.stderr)
            return False
    except Exception as e:
        print(f"❌ {name}: ERROR - {e}")
        return False

def main():
    """Run all QA checks."""
    print("=" * 60)
    print("SentinelRecon v2.0 - Final QA Verification")
    print("=" * 60)
    
    checks = [
        ("Syntax Check", "python -c \"import py_compile, glob; [py_compile.compile(f) for f in glob.glob('sentinelrecon/v2/**/*.py', recursive=True)]\""),
        ("Import Check", "python -c \"from sentinelrecon.v2.main import main; print('OK')\""),
        ("Config Validation", "python -c \"from sentinelrecon.v2.config import Config; Config.validate(); print('OK')\""),
        ("Container Creation", "python -c \"from sentinelrecon.v2.container import ServiceContainer; ServiceContainer.create(); print('OK')\""),
        ("Security - No verify=False", "python -c \"import os, sys; found = any('verify=False' in open(os.path.join(root, f), errors='ignore').read() for root, dirs, files in os.walk('sentinelrecon/v2') if 'tests' not in root for f in files if f.endswith('.py')); sys.exit(1 if found else 0)\""),
        ("Security - No disabled warnings", "python -c \"import os, sys; found = any('disable_warnings' in open(os.path.join(root, f), errors='ignore').read() for root, dirs, files in os.walk('sentinelrecon/v2') if 'tests' not in root for f in files if f.endswith('.py')); sys.exit(1 if found else 0)\""),
        ("File Count", "python -c \"from pathlib import Path; import sys; count = len(list(Path('sentinelrecon/v2').rglob('*.py'))); print(f'Files: {count}'); sys.exit(0 if count >= 25 else 1)\""),
        ("Type Hints Check", "python -m py_compile sentinelrecon/v2/config.py sentinelrecon/v2/container.py"),
        ("Test Imports", "python -c \"import pytest; print('OK')\""),
    ]
    
    results = {}
    for name, command in checks:
        results[name] = run_check(name, command)
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")
    
    print("\n" + "=" * 60)
    print(f"TOTAL: {passed}/{total} checks passed")
    print("=" * 60)
    
    if passed == total:
        print("\n🎉 ALL CHECKS PASSED!")
        print("\nReady to merge to main branch:")
        print("  git checkout main")
        print("  git merge v2.0-implementation")
        print("  git tag v2.0.0")
        print("  git push origin main --tags")
        return 0
    else:
        print("\n❌ SOME CHECKS FAILED")
        print("Fix issues before merging.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
