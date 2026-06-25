"""
Database class for SentinelRecon
Handles SQLAlchemy session management and CRUD operations
"""

import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional
import json
import uuid

from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from sentinelrecon.data.models import (
    Base, Scan, PortResult, CVEResult, AIAnalysis,
    CVECache, ScanProfile, ScanStatus, RiskLevel, ScanType
)


class Database:
    """
    Database manager for SentinelRecon
    Handles all database operations using SQLAlchemy ORM
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize database connection
        
        Args:
            db_path: Path to SQLite database file
                    If None, uses ~/.sentinelrecon/sentinel.db
        """
        if db_path is None:
            # Default path in user home directory
            home_dir = Path.home()
            sentinel_dir = home_dir / ".sentinelrecon"
            sentinel_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(sentinel_dir / "sentinel.db")
        
        self.db_path = db_path
        self.engine = None
        self.SessionLocal = None
        self._initialize_db()

    def _initialize_db(self):
        """Initialize database engine and create tables"""
        # Create SQLite engine
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        
        # Create session factory
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
        
        # Create all tables
        Base.metadata.create_all(bind=self.engine)

    def get_session(self) -> Session:
        """Get a database session"""
        return self.SessionLocal()

    # ==================== SCAN OPERATIONS ====================

    def save_scan(self, scan_data: dict) -> Scan:
        """
        Save a new scan to database
        
        Args:
            scan_data: Dictionary containing scan information
                      Must include: target_input, port_range_start, port_range_end, scan_type
        
        Returns:
            Scan object with database ID
        """
        session = self.get_session()
        try:
            scan = Scan(
                scan_uuid=str(uuid.uuid4()),
                target_input=scan_data.get("target_input"),
                resolved_ip=scan_data.get("resolved_ip"),
                scan_type=scan_data.get("scan_type", ScanType.CONNECT),
                port_range_start=scan_data.get("port_range_start", 1),
                port_range_end=scan_data.get("port_range_end", 1024),
                total_ports=scan_data.get("total_ports"),
                open_ports_count=scan_data.get("open_ports_count", 0),
                risk_score=scan_data.get("risk_score", 0.0),
                risk_label=scan_data.get("risk_label", RiskLevel.LOW),
                os_guess=scan_data.get("os_guess"),
                status=scan_data.get("status", ScanStatus.RUNNING),
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            return scan
        finally:
            session.close()

    def load_scan(self, scan_id: int) -> Optional[Scan]:
        """
        Load a scan by ID
        
        Args:
            scan_id: Scan ID
            
        Returns:
            Scan object or None if not found
        """
        session = self.get_session()
        try:
            return session.query(Scan).filter(Scan.id == scan_id).first()
        finally:
            session.close()

    def load_scan_by_uuid(self, scan_uuid: str) -> Optional[Scan]:
        """Load a scan by UUID"""
        session = self.get_session()
        try:
            return session.query(Scan).filter(Scan.scan_uuid == scan_uuid).first()
        finally:
            session.close()

    def list_scans(self, limit: int = 100, offset: int = 0) -> List[Scan]:
        """
        List all scans with pagination
        
        Args:
            limit: Maximum number of scans to return
            offset: Number of scans to skip
            
        Returns:
            List of Scan objects
        """
        session = self.get_session()
        try:
            return session.query(Scan).order_by(
                Scan.created_at.desc()
            ).limit(limit).offset(offset).all()
        finally:
            session.close()

    def list_scans_by_target(self, target: str, limit: int = 50) -> List[Scan]:
        """List all scans for a specific target"""
        session = self.get_session()
        try:
            return session.query(Scan).filter(
                Scan.target_input == target
            ).order_by(Scan.created_at.desc()).limit(limit).all()
        finally:
            session.close()

    def update_scan(self, scan_id: int, updates: dict) -> Optional[Scan]:
        """
        Update scan record
        
        Args:
            scan_id: Scan ID to update
            updates: Dictionary of fields to update
            
        Returns:
            Updated Scan object
        """
        session = self.get_session()
        try:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return None
            
            for key, value in updates.items():
                if hasattr(scan, key):
                    setattr(scan, key, value)
            
            session.commit()
            session.refresh(scan)
            return scan
        finally:
            session.close()

    def delete_scan(self, scan_id: int) -> bool:
        """
        Delete a scan (cascade deletes port results, CVEs, etc.)
        
        Args:
            scan_id: Scan ID to delete
            
        Returns:
            True if successful, False if not found
        """
        session = self.get_session()
        try:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return False
            session.delete(scan)
            session.commit()
            return True
        finally:
            session.close()

    # ==================== PORT RESULT OPERATIONS ====================

    def save_port_result(self, scan_id: int, port_data: dict) -> PortResult:
        """Save a port scan result"""
        session = self.get_session()
        try:
            port_result = PortResult(
                scan_id=scan_id,
                port=port_data.get("port"),
                protocol=port_data.get("protocol", "tcp"),
                state=port_data.get("state"),
                service_name=port_data.get("service_name"),
                service_version=port_data.get("service_version"),
                banner_raw=port_data.get("banner_raw"),
                banner_parsed=port_data.get("banner_parsed"),
                risk_level=port_data.get("risk_level", RiskLevel.INFO),
                risk_score=port_data.get("risk_score", 0.0),
            )
            session.add(port_result)
            session.commit()
            session.refresh(port_result)
            return port_result
        finally:
            session.close()

    def get_port_results(self, scan_id: int) -> List[PortResult]:
        """Get all port results for a scan"""
        session = self.get_session()
        try:
            return session.query(PortResult).filter(
                PortResult.scan_id == scan_id
            ).order_by(PortResult.port).all()
        finally:
            session.close()

    # ==================== CVE OPERATIONS ====================

    def save_cve_result(self, port_result_id: int, cve_data: dict) -> CVEResult:
        """Save a CVE result for a port"""
        session = self.get_session()
        try:
            cve_result = CVEResult(
                port_result_id=port_result_id,
                cve_id=cve_data.get("cve_id"),
                description=cve_data.get("description"),
                cvss_score=cve_data.get("cvss_score"),
                severity=cve_data.get("severity", RiskLevel.LOW),
                published_date=cve_data.get("published_date"),
                reference_url=cve_data.get("reference_url"),
            )
            session.add(cve_result)
            session.commit()
            session.refresh(cve_result)
            return cve_result
        finally:
            session.close()

    def get_cves_for_port(self, port_result_id: int) -> List[CVEResult]:
        """Get all CVEs for a port result"""
        session = self.get_session()
        try:
            return session.query(CVEResult).filter(
                CVEResult.port_result_id == port_result_id
            ).order_by(CVEResult.cvss_score.desc()).all()
        finally:
            session.close()

    # ==================== AI ANALYSIS OPERATIONS ====================

    def save_ai_analysis(self, scan_id: int, analysis_data: dict) -> AIAnalysis:
        """Save AI analysis for a scan"""
        session = self.get_session()
        try:
            ai_analysis = AIAnalysis(
                scan_id=scan_id,
                prompt_sent=analysis_data.get("prompt_sent"),
                response_raw=analysis_data.get("response_raw"),
                summary=analysis_data.get("summary"),
                attack_surface=analysis_data.get("attack_surface"),
                remediation_steps=analysis_data.get("remediation_steps"),
                risk_narrative=analysis_data.get("risk_narrative"),
                model_used=analysis_data.get("model_used", "claude-sonnet-4-6"),
                tokens_used=analysis_data.get("tokens_used"),
            )
            session.add(ai_analysis)
            session.commit()
            session.refresh(ai_analysis)
            return ai_analysis
        finally:
            session.close()

    def get_ai_analysis(self, scan_id: int) -> Optional[AIAnalysis]:
        """Get AI analysis for a scan"""
        session = self.get_session()
        try:
            return session.query(AIAnalysis).filter(
                AIAnalysis.scan_id == scan_id
            ).first()
        finally:
            session.close()

    # ==================== CVE CACHE OPERATIONS ====================

    def get_cve_cache(self, cache_key: str) -> Optional[dict]:
        """
        Get cached CVE data
        
        Args:
            cache_key: Cache key (usually service+version hash)
            
        Returns:
            Cached data as dict or None if not found/expired
        """
        session = self.get_session()
        try:
            cache_entry = session.query(CVECache).filter(
                CVECache.cache_key == cache_key
            ).first()
            
            if not cache_entry:
                return None
            
            # Check if expired
            if datetime.utcnow() > cache_entry.expires_at:
                session.delete(cache_entry)
                session.commit()
                return None
            
            # Return parsed JSON data
            return json.loads(cache_entry.data_json)
        finally:
            session.close()

    def save_cve_cache(self, cache_key: str, data: dict, ttl_hours: int = 24):
        """
        Save CVE data to cache
        
        Args:
            cache_key: Cache key
            data: Data to cache (will be JSON serialized)
            ttl_hours: Time-to-live in hours
        """
        session = self.get_session()
        try:
            # Delete existing entry if present
            existing = session.query(CVECache).filter(
                CVECache.cache_key == cache_key
            ).first()
            if existing:
                session.delete(existing)
            
            # Create new cache entry
            cache_entry = CVECache(
                cache_key=cache_key,
                data_json=json.dumps(data),
                expires_at=datetime.utcnow() + timedelta(hours=ttl_hours),
            )
            session.add(cache_entry)
            session.commit()
        finally:
            session.close()

    # ==================== SCAN PROFILE OPERATIONS ====================

    def save_scan_profile(self, profile_data: dict) -> ScanProfile:
        """Save a scan profile"""
        session = self.get_session()
        try:
            profile = ScanProfile(
                name=profile_data.get("name"),
                scan_type=profile_data.get("scan_type", ScanType.CONNECT),
                port_range_start=profile_data.get("port_range_start", 1),
                port_range_end=profile_data.get("port_range_end", 1024),
                timeout=profile_data.get("timeout", 5.0),
                threads=profile_data.get("threads", 10),
                banner_grab=profile_data.get("banner_grab", True),
                ai_analysis=profile_data.get("ai_analysis", True),
                cve_lookup=profile_data.get("cve_lookup", True),
                is_default=profile_data.get("is_default", False),
            )
            session.add(profile)
            session.commit()
            session.refresh(profile)
            return profile
        finally:
            session.close()

    def get_scan_profile(self, name: str) -> Optional[ScanProfile]:
        """Get a scan profile by name"""
        session = self.get_session()
        try:
            return session.query(ScanProfile).filter(
                ScanProfile.name == name
            ).first()
        finally:
            session.close()

    def list_scan_profiles(self) -> List[ScanProfile]:
        """List all scan profiles"""
        session = self.get_session()
        try:
            return session.query(ScanProfile).order_by(
                ScanProfile.created_at.desc()
            ).all()
        finally:
            session.close()

    def delete_scan_profile(self, name: str) -> bool:
        """Delete a scan profile"""
        session = self.get_session()
        try:
            profile = session.query(ScanProfile).filter(
                ScanProfile.name == name
            ).first()
            if not profile:
                return False
            session.delete(profile)
            session.commit()
            return True
        finally:
            session.close()

    # ==================== STATISTICS ====================

    def get_scan_statistics(self) -> dict:
        """Get overall scan statistics"""
        session = self.get_session()
        try:
            total_scans = session.query(func.count(Scan.id)).scalar()
            completed_scans = session.query(func.count(Scan.id)).filter(
                Scan.status == ScanStatus.COMPLETED
            ).scalar()
            critical_findings = session.query(func.count(PortResult.id)).filter(
                PortResult.risk_level == RiskLevel.CRITICAL
            ).scalar()
            
            return {
                "total_scans": total_scans,
                "completed_scans": completed_scans,
                "critical_findings": critical_findings,
            }
        finally:
            session.close()
