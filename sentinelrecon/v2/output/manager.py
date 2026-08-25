"""Secure Report Output Manager

Manages the secure creation and output of reports with strict file permissions
and symlink vulnerability detection.
"""

from pathlib import Path
import json
import logging
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from sentinelrecon.v2.config import Config
class ReportManager:
    """Manages secure report generation and output."""
    
    def __init__(self, config: 'Config', logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.report_dir: Optional[Path] = None
    
    def initialize_report_directory(self, scan_name: str) -> Path:
        """Initialize report directory with proper permissions."""
        self.report_dir = self.config.get_report_dir(scan_name)
        self.logger.info(f"Report directory: {self.report_dir}")
        return self.report_dir
    
    def save_json_report(self, data: dict, filename: str) -> Path:
        """Save JSON report with security."""
        if self.report_dir is None:
            raise ValueError("Call initialize_report_directory() first")
        
        filepath = self.report_dir / filename
        
        # Check for symlinks (security)
        if filepath.exists() and filepath.is_symlink():
            raise ValueError(f"Won't overwrite symlink: {filepath}")
        
        # Write JSON
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        # Set permissions to 0o600 (owner rw only)
        filepath.chmod(self.config.SENSITIVE_FILE_PERMISSIONS)
        
        self.logger.info(f"Saved report: {filepath}")
        return filepath
    
    def save_html_report(self, html_content: str, filename: str) -> Path:
        """Save HTML report with security."""
        if self.report_dir is None:
            raise ValueError("Call initialize_report_directory() first")
        
        filepath = self.report_dir / filename
        
        # Check for symlinks (security)
        if filepath.exists() and filepath.is_symlink():
            raise ValueError(f"Won't overwrite symlink: {filepath}")
            
        # Write HTML
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        # Set permissions
        filepath.chmod(self.config.SENSITIVE_FILE_PERMISSIONS)
        
        self.logger.info(f"Saved HTML report: {filepath}")
        return filepath

    def save_markdown_report(self, markdown_content: str, filename: str) -> Path:
        """Save Markdown report with security."""
        if self.report_dir is None:
            raise ValueError("Call initialize_report_directory() first")
        
        filepath = self.report_dir / filename
        
        # Check for symlinks (security)
        if filepath.exists() and filepath.is_symlink():
            raise ValueError(f"Won't overwrite symlink: {filepath}")
            
        with open(filepath, 'w') as f:
            f.write(markdown_content)
            
        filepath.chmod(self.config.SENSITIVE_FILE_PERMISSIONS)
        self.logger.info(f"Saved Markdown report: {filepath}")
        return filepath

    def get_report_index(self) -> dict:
        """Get all report files in current report directory."""
        if self.report_dir is None:
            raise ValueError("No report directory initialized")
        
        files = list(self.report_dir.glob('*'))
        return {
            'directory': str(self.report_dir),
            'file_count': len(files),
            'files': [f.name for f in files]
        }
