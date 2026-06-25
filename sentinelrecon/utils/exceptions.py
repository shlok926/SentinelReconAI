"""
Custom exception classes for SentinelRecon
"""


class SentinelReconException(Exception):
    """Base exception for all SentinelRecon errors"""
    pass


class ScanException(SentinelReconException):
    """Exception raised during scanning operations"""
    pass


class ValidationException(SentinelReconException):
    """Exception raised during input validation"""
    pass


class NetworkException(SentinelReconException):
    """Exception raised during network operations (DNS, connectivity)"""
    pass


class DatabaseException(SentinelReconException):
    """Exception raised during database operations"""
    pass


class APIException(SentinelReconException):
    """Exception raised during API calls (Claude, NVD)"""
    pass


class ConfigException(SentinelReconException):
    """Exception raised during configuration operations"""
    pass


class BannerGrabbingException(ScanException):
    """Exception raised during banner grabbing"""
    pass


class ServiceDetectionException(ScanException):
    """Exception raised during service detection"""
    pass


class CVELookupException(APIException):
    """Exception raised during CVE lookup"""
    pass


class AIAnalysisException(APIException):
    """Exception raised during AI analysis"""
    pass


class ReportGenerationException(SentinelReconException):
    """Exception raised during report generation"""
    pass


class AuthenticationException(APIException):
    """Exception raised when API authentication fails"""
    pass


class RateLimitException(APIException):
    """Exception raised when API rate limit is exceeded"""
    pass


class TimeoutException(NetworkException):
    """Exception raised when network operation times out"""
    pass
