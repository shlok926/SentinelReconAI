#!/usr/bin/env python
"""
SentinelRecon Database Initialization Script

This script sets up the database and directory structure for SentinelRecon.
It should be run once before using SentinelRecon.

Usage:
    python scripts/setup_db.py
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sentinelrecon.data.database import Database


def setup_database():
    """Initialize database and directory structure"""
    
    print("=" * 60)
    print("SentinelRecon Database Setup")
    print("=" * 60)
    
    # Get home directory
    home_dir = Path.home()
    sentinel_dir = home_dir / ".sentinelrecon"
    
    print(f"\n[*] Creating directory structure...")
    print(f"    Directory: {sentinel_dir}")
    
    # Create main directory
    sentinel_dir.mkdir(parents=True, exist_ok=True)
    
    # Create subdirectories
    subdirs = [
        "logs",
        "reports",
        "backups",
        "profiles",
    ]
    
    for subdir in subdirs:
        subdir_path = sentinel_dir / subdir
        subdir_path.mkdir(exist_ok=True)
        print(f"    ✓ Created {subdir_path}")
    
    # Initialize database
    print(f"\n[*] Initializing database...")
    db_path = str(sentinel_dir / "sentinel.db")
    db = Database(db_path=db_path)
    print(f"    ✓ Database created at {db_path}")
    
    # Create default scan profiles
    print(f"\n[*] Creating default scan profiles...")
    
    default_profiles = [
        {
            "name": "quick",
            "scan_type": "connect",
            "port_range_start": 1,
            "port_range_end": 100,
            "timeout": 3.0,
            "threads": 20,
            "banner_grab": True,
            "ai_analysis": False,
            "cve_lookup": False,
            "is_default": False,
        },
        {
            "name": "standard",
            "scan_type": "connect",
            "port_range_start": 1,
            "port_range_end": 1024,
            "timeout": 5.0,
            "threads": 10,
            "banner_grab": True,
            "ai_analysis": True,
            "cve_lookup": True,
            "is_default": True,
        },
        {
            "name": "full",
            "scan_type": "connect",
            "port_range_start": 1,
            "port_range_end": 65535,
            "timeout": 10.0,
            "threads": 5,
            "banner_grab": True,
            "ai_analysis": True,
            "cve_lookup": True,
            "is_default": False,
        },
        {
            "name": "stealth",
            "scan_type": "syn",
            "port_range_start": 1,
            "port_range_end": 1024,
            "timeout": 7.0,
            "threads": 5,
            "banner_grab": False,
            "ai_analysis": False,
            "cve_lookup": False,
            "is_default": False,
        },
    ]
    
    for profile in default_profiles:
        try:
            db.save_scan_profile(profile)
            print(f"    ✓ Created profile: {profile['name']}")
        except Exception as e:
            print(f"    ! Profile {profile['name']} already exists or error: {e}")
    
    # Create configuration file template
    print(f"\n[*] Creating configuration template...")
    config_file = sentinel_dir / "config.json"
    if not config_file.exists():
        config_template = """{
  "api_provider": "claude",
  "claude_api_key": "",
  "openai_api_key": "",
  "nvd_api_key": "",
  "default_scan_timeout": 5,
  "default_thread_count": 10,
  "default_ports": "1-1024",
  "beginner_mode": true,
  "theme": "dark",
  "auto_ai_analysis": true,
  "auto_cve_lookup": true
}
"""
        with open(config_file, 'w') as f:
            f.write(config_template)
        print(f"    ✓ Created config template at {config_file}")
    else:
        print(f"    ! Config file already exists")
    
    # Create .env file template
    print(f"\n[*] Creating .env template...")
    env_file = sentinel_dir / ".env"
    if not env_file.exists():
        env_template = """# SentinelRecon Environment Variables
# Copy this file to the sentinelrecon directory and fill in your API keys

CLAUDE_API_KEY=your_claude_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
NVD_API_KEY=your_nvd_api_key_here

DATABASE_PATH=~/.sentinelrecon/sentinel.db
LOG_PATH=~/.sentinelrecon/logs/sentinel.log

APP_ENV=production
DEBUG=False
LOG_LEVEL=INFO
"""
        with open(env_file, 'w') as f:
            f.write(env_template)
        print(f"    ✓ Created .env template at {env_file}")
    else:
        print(f"    ! .env file already exists")
    
    # Summary
    print("\n" + "=" * 60)
    print("✓ Database initialization complete!")
    print("=" * 60)
    print("\nNext steps:")
    print(f"1. Edit configuration: {sentinel_dir}/config.json")
    print(f"2. Or set environment variables in: {sentinel_dir}/.env")
    print("3. Add your API keys (Claude, NVD)")
    print("4. Run: sentinelrecon scan --target <target>")
    print("\nFor more help:")
    print("  sentinelrecon --help")
    print("  sentinelrecon scan --help")
    print("=" * 60)


if __name__ == "__main__":
    try:
        setup_database()
    except Exception as e:
        print(f"\n✗ Error during setup: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
