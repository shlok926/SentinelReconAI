"""
SQLAlchemy ORM Models for SentinelRecon
Defines database schema for scans, results, CVEs, AI analyses, etc.
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, Float, DateTime, Boolean,
    ForeignKey, Enum as SQLEnum, create_engine
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum

Base = declarative_base()


class RiskLevel(str, enum.Enum):
    """Risk level enumeration"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanType(str, enum.Enum):
    """Scan type enumeration"""
    SYN = "syn"
    CONNECT = "connect"
    UDP = "udp"


class ScanStatus(str, enum.Enum):
    """Scan status enumeration"""
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class Scan(Base):
    """
    Main scan record - represents a complete reconnaissance scan
    """
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_uuid = Column(String(36), unique=True, nullable=False, index=True)
    target_input = Column(String(255), nullable=False)  # Original user input
    resolved_ip = Column(String(45))  # Resolved IP (after DNS lookup)
    scan_type = Column(SQLEnum(ScanType), default=ScanType.CONNECT, nullable=False)
    port_range_start = Column(Integer, nullable=False)
    port_range_end = Column(Integer, nullable=False)
    total_ports = Column(Integer)  # Total ports scanned
    open_ports_count = Column(Integer, default=0)  # Ports that are open
    risk_score = Column(Float, default=0.0)  # Overall risk score (0-100)
    risk_label = Column(SQLEnum(RiskLevel), default=RiskLevel.LOW)
    os_guess = Column(String(255))  # Guessed OS fingerprint
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.RUNNING, nullable=False)
    
    # Timestamps
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime)
    
    # Report paths
    report_path_html = Column(String(512))
    report_path_pdf = Column(String(512))
    report_path_json = Column(String(512))
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    port_results = relationship("PortResult", back_populates="scan", cascade="all, delete-orphan")
    ai_analysis = relationship("AIAnalysis", back_populates="scan", uselist=False, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan(id={self.id}, target={self.target_input}, status={self.status})>"


class PortResult(Base):
    """
    Individual port scan result
    """
    __tablename__ = "port_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")  # tcp or udp
    state = Column(String(20), nullable=False)  # open, closed, filtered
    service_name = Column(String(100))  # http, ssh, mysql, etc.
    service_version = Column(String(255))  # Apache 2.4.29, OpenSSH 7.4, etc.
    banner_raw = Column(Text)  # Raw banner text
    banner_parsed = Column(Text)  # Parsed/cleaned banner
    risk_level = Column(SQLEnum(RiskLevel), default=RiskLevel.INFO)
    risk_score = Column(Float, default=0.0)  # Risk score for this port (0-100)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="port_results")
    cve_results = relationship("CVEResult", back_populates="port_result", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<PortResult(port={self.port}, state={self.state}, service={self.service_name})>"


class CVEResult(Base):
    """
    CVE (Common Vulnerabilities and Exposures) record linked to port result
    """
    __tablename__ = "cve_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    port_result_id = Column(Integer, ForeignKey("port_results.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id = Column(String(50), nullable=False, index=True)  # CVE-2021-44228
    description = Column(Text)
    cvss_score = Column(Float)  # 0.0 to 10.0
    severity = Column(SQLEnum(RiskLevel), default=RiskLevel.LOW)
    published_date = Column(String(20))  # ISO date string
    reference_url = Column(String(512))  # Link to CVE details
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    port_result = relationship("PortResult", back_populates="cve_results")

    def __repr__(self):
        return f"<CVEResult(cve_id={self.cve_id}, cvss={self.cvss_score})>"


class AIAnalysis(Base):
    """
    AI-generated analysis for a scan (one-to-one with Scan)
    """
    __tablename__ = "ai_analyses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    prompt_sent = Column(Text)  # The prompt we sent to Claude
    response_raw = Column(Text)  # Raw response from Claude
    summary = Column(Text)  # Executive summary
    attack_surface = Column(Text)  # Description of attack surface
    remediation_steps = Column(Text)  # Recommended remediation steps
    risk_narrative = Column(Text)  # Natural language risk narrative
    model_used = Column(String(100), default="claude-sonnet-4-6")
    tokens_used = Column(Integer)  # Number of tokens used
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    scan = relationship("Scan", back_populates="ai_analysis")

    def __repr__(self):
        return f"<AIAnalysis(scan_id={self.scan_id}, model={self.model_used})>"


class CVECache(Base):
    """
    Cache for CVE lookups (to avoid repeated NVD API calls)
    """
    __tablename__ = "cve_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cache_key = Column(String(255), unique=True, nullable=False, index=True)  # Hash of service+version
    data_json = Column(Text, nullable=False)  # JSON-serialized CVE data
    cached_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)  # When this cache entry expires (24h TTL)

    def __repr__(self):
        return f"<CVECache(key={self.cache_key}, expires={self.expires_at})>"


class ScanProfile(Base):
    """
    Saved scan configuration profiles for quick scanning
    """
    __tablename__ = "scan_profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    scan_type = Column(SQLEnum(ScanType), default=ScanType.CONNECT)
    port_range_start = Column(Integer, default=1)
    port_range_end = Column(Integer, default=1024)
    timeout = Column(Float, default=5.0)
    threads = Column(Integer, default=10)
    banner_grab = Column(Boolean, default=True)
    ai_analysis = Column(Boolean, default=True)
    cve_lookup = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<ScanProfile(name={self.name})>"
