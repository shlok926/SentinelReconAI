"""
CVE lookup module for vulnerability identification.
Integrates with NVD API and caches results.
"""
import json
import hashlib
import time
from typing import Optional, Dict, List
from datetime import datetime, timedelta
import requests
from functools import lru_cache

from sentinelrecon.utils.logger import LoggerSetup
from sentinelrecon.utils.exceptions import (
    APIException,
    RateLimitException,
    TimeoutException,
)


class CVELookup:
    """CVE database lookup and caching"""

    # NVD API endpoints
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    SHODAN_API_URL = "https://api.shodan.io/shodan/host/search"

    # Rate limiting
    REQUEST_TIMEOUT = 10
    CACHE_TTL_HOURS = 24
    RATE_LIMIT_DELAY = 0.6  # NVD API requires 6 requests per 60 seconds

    def __init__(self, nvd_api_key: Optional[str] = None, cache_enabled: bool = True):
        """
        Initialize CVE lookup engine.

        Args:
            nvd_api_key: NVD API key for higher rate limits
            cache_enabled: Enable local caching
        """
        self.logger = LoggerSetup.setup_logger(__name__)
        self.nvd_api_key = nvd_api_key
        self.cache_enabled = cache_enabled
        self.last_request_time = 0
        self._cache = {}  # In-memory cache

    def lookup_by_service(
        self,
        service_name: str,
        version: Optional[str] = None,
    ) -> List[Dict]:
        """
        Look up CVEs for a specific service/version.

        Args:
            service_name: Service name (e.g., 'openssl', 'apache')
            version: Service version (optional)

        Returns:
            List of CVE dictionaries

        Raises:
            APIException: If API call fails
            RateLimitException: If rate limited
        """
        # Check cache first
        cache_key = self._make_cache_key(service_name, version)
        if self.cache_enabled and cache_key in self._cache:
            cached_data, expiry = self._cache[cache_key]
            if time.time() < expiry:
                self.logger.debug(f"Cache hit for {service_name} {version}")
                return cached_data

        try:
            # Build query
            if version:
                query = f"{service_name} {version}"
            else:
                query = service_name

            # Query NVD API
            cves = self._query_nvd_api(query)

            # Cache results
            if self.cache_enabled and cves:
                expiry = time.time() + (self.CACHE_TTL_HOURS * 3600)
                self._cache[cache_key] = (cves, expiry)

            return cves

        except Exception as e:
            self.logger.error(f"CVE lookup failed for {service_name}: {e}")
            raise APIException(f"CVE lookup failed: {str(e)}")

    def lookup_by_cpe(self, cpe: str) -> List[Dict]:
        """
        Look up CVEs by CPE (Common Platform Enumeration).

        Args:
            cpe: CPE string (e.g., 'cpe:2.3:a:vendor:product:version')

        Returns:
            List of CVE dictionaries

        Raises:
            APIException: If API call fails
        """
        cache_key = f"cpe:{cpe}"
        if self.cache_enabled and cache_key in self._cache:
            cached_data, expiry = self._cache[cache_key]
            if time.time() < expiry:
                self.logger.debug(f"Cache hit for CPE {cpe}")
                return cached_data

        try:
            cves = self._query_nvd_by_cpe(cpe)

            if self.cache_enabled and cves:
                expiry = time.time() + (self.CACHE_TTL_HOURS * 3600)
                self._cache[cache_key] = (cves, expiry)

            return cves

        except Exception as e:
            self.logger.error(f"CPE lookup failed for {cpe}: {e}")
            raise APIException(f"CPE lookup failed: {str(e)}")

    def lookup_by_cve_id(self, cve_id: str) -> Optional[Dict]:
        """
        Look up specific CVE by ID.

        Args:
            cve_id: CVE ID (e.g., 'CVE-2021-1234')

        Returns:
            CVE dictionary or None

        Raises:
            APIException: If API call fails
        """
        cache_key = f"cve:{cve_id}"
        if self.cache_enabled and cache_key in self._cache:
            cached_data, expiry = self._cache[cache_key]
            if time.time() < expiry:
                self.logger.debug(f"Cache hit for {cve_id}")
                return cached_data

        try:
            cve = self._query_nvd_by_cve_id(cve_id)

            if self.cache_enabled and cve:
                expiry = time.time() + (self.CACHE_TTL_HOURS * 3600)
                self._cache[cache_key] = (cve, expiry)

            return cve

        except Exception as e:
            self.logger.error(f"CVE ID lookup failed for {cve_id}: {e}")
            raise APIException(f"CVE lookup failed: {str(e)}")

    def _query_nvd_api(self, query: str) -> List[Dict]:
        """
        Query NVD API for CVEs.

        Args:
            query: Search query

        Returns:
            List of CVE dictionaries

        Raises:
            RateLimitException: If rate limited
            TimeoutException: If request times out
        """
        self._rate_limit()

        try:
            params = {
                "keyword": query,
                "resultsPerPage": 20,
            }

            if self.nvd_api_key:
                params["apiKey"] = self.nvd_api_key

            response = requests.get(
                self.NVD_API_URL,
                params=params,
                timeout=self.REQUEST_TIMEOUT,
            )

            # Check rate limiting
            if response.status_code == 429:
                raise RateLimitException(
                    "NVD API rate limit exceeded. Please try again later."
                )

            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            # Parse and normalize results
            cves = []
            for vuln in vulnerabilities:
                cve_data = self._parse_nvd_response(vuln)
                if cve_data:
                    cves.append(cve_data)

            self.logger.info(f"Found {len(cves)} CVEs for query: {query}")
            return cves

        except requests.Timeout:
            raise TimeoutException(f"NVD API request timed out for: {query}")
        except requests.RequestException as e:
            raise APIException(f"NVD API request failed: {str(e)}")

    def _query_nvd_by_cpe(self, cpe: str) -> List[Dict]:
        """
        Query NVD API using CPE.

        Args:
            cpe: CPE string

        Returns:
            List of CVE dictionaries
        """
        self._rate_limit()

        try:
            params = {
                "cpeName": cpe,
                "resultsPerPage": 20,
            }

            if self.nvd_api_key:
                params["apiKey"] = self.nvd_api_key

            response = requests.get(
                self.NVD_API_URL,
                params=params,
                timeout=self.REQUEST_TIMEOUT,
            )

            if response.status_code == 429:
                raise RateLimitException("NVD API rate limit exceeded")

            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            cves = []
            for vuln in vulnerabilities:
                cve_data = self._parse_nvd_response(vuln)
                if cve_data:
                    cves.append(cve_data)

            self.logger.info(f"Found {len(cves)} CVEs for CPE: {cpe}")
            return cves

        except requests.Timeout:
            raise TimeoutException(f"NVD API request timed out")
        except requests.RequestException as e:
            raise APIException(f"NVD API request failed: {str(e)}")

    def _query_nvd_by_cve_id(self, cve_id: str) -> Optional[Dict]:
        """
        Query NVD API for specific CVE ID.

        Args:
            cve_id: CVE ID

        Returns:
            CVE dictionary or None
        """
        self._rate_limit()

        try:
            params = {
                "cveId": cve_id,
            }

            if self.nvd_api_key:
                params["apiKey"] = self.nvd_api_key

            response = requests.get(
                self.NVD_API_URL,
                params=params,
                timeout=self.REQUEST_TIMEOUT,
            )

            if response.status_code == 429:
                raise RateLimitException("NVD API rate limit exceeded")

            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            if vulnerabilities:
                cve_data = self._parse_nvd_response(vulnerabilities[0])
                self.logger.info(f"Found CVE: {cve_id}")
                return cve_data

            return None

        except requests.Timeout:
            raise TimeoutException(f"NVD API request timed out")
        except requests.RequestException as e:
            raise APIException(f"NVD API request failed: {str(e)}")

    def _parse_nvd_response(self, vuln: Dict) -> Optional[Dict]:
        """
        Parse NVD API response into standard format.

        Args:
            vuln: Vulnerability entry from NVD

        Returns:
            Normalized CVE dictionary
        """
        try:
            cve_id = vuln.get("cve", {}).get("id")
            if not cve_id:
                return None

            # Extract CVSS scores (prefer v3.1 > v3.0 > v2.0)
            cvss_v3_1 = None
            cvss_v3_0 = None
            cvss_v2_0 = None

            metrics = vuln.get("cve", {}).get("metrics", {})

            if "cvssMetricV31" in metrics:
                cvss_v3_1 = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore")

            if "cvssMetricV30" in metrics:
                cvss_v3_0 = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore")

            if "cvssMetricV2" in metrics:
                cvss_v2_0 = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")

            # Use highest CVSS score available
            cvss_score = cvss_v3_1 or cvss_v3_0 or cvss_v2_0 or 0.0

            # Get severity
            severity = self._cvss_to_severity(cvss_score)

            # Extract description
            descriptions = vuln.get("cve", {}).get("descriptions", [])
            description = ""
            if descriptions:
                description = descriptions[0].get("value", "")

            # Get published date
            published = vuln.get("cve", {}).get("published", "")

            # Get references
            references = []
            refs = vuln.get("cve", {}).get("references", [])
            for ref in refs[:5]:  # Limit to 5 references
                url = ref.get("url")
                if url:
                    references.append(url)

            # Get affected versions/CPEs
            affected_cppes = []
            configs = vuln.get("cve", {}).get("configurations", [])
            for config in configs:
                nodes = config.get("nodes", [])
                for node in nodes:
                    cpes = node.get("cpeMatch", [])
                    for cpe_match in cpes[:3]:  # Limit to 3
                        cpe = cpe_match.get("criteria")
                        if cpe:
                            affected_cppes.append(cpe)

            return {
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity,
                "description": description,
                "published_date": published,
                "references": references,
                "affected_cpes": list(set(affected_cppes)),  # Remove duplicates
                "source": "NVD",
            }

        except Exception as e:
            self.logger.warning(f"Failed to parse NVD response: {e}")
            return None

    def _cvss_to_severity(self, cvss_score: float) -> str:
        """
        Convert CVSS score to severity level.

        Args:
            cvss_score: CVSS score (0.0-10.0)

        Returns:
            Severity level string
        """
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        elif cvss_score > 0:
            return "LOW"
        else:
            return "NONE"

    def _make_cache_key(self, service: str, version: Optional[str]) -> str:
        """Create cache key for service lookup."""
        key = f"{service}:{version or 'any'}"
        return hashlib.md5(key.encode()).hexdigest()

    def _rate_limit(self) -> None:
        """Implement rate limiting for NVD API."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.RATE_LIMIT_DELAY:
            time.sleep(self.RATE_LIMIT_DELAY - elapsed)
        self.last_request_time = time.time()

    def clear_cache(self) -> None:
        """Clear cache."""
        self._cache.clear()
        self.logger.info("Cache cleared")

    def get_cache_stats(self) -> Dict:
        """Get cache statistics."""
        return {
            "cached_entries": len(self._cache),
            "cache_enabled": self.cache_enabled,
        }

    def batch_lookup(self, services: List[tuple]) -> Dict[str, List[Dict]]:
        """
        Perform batch CVE lookups.

        Args:
            services: List of (service_name, version) tuples

        Returns:
            Dictionary mapping service to CVE list
        """
        results = {}
        for service_name, version in services:
            try:
                cves = self.lookup_by_service(service_name, version)
                key = f"{service_name}:{version}" if version else service_name
                results[key] = cves
            except Exception as e:
                self.logger.warning(f"Batch lookup failed for {service_name}: {e}")
                results[f"{service_name}:{version}"] = []

        return results
