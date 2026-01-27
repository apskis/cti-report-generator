"""
Type definitions for CTI Report Generator.

This module contains dataclasses and TypedDicts for structured data types
used throughout the application. Using structured types provides:
- Type safety and IDE autocompletion
- Self-documenting code
- Runtime validation (with optional validation)
- Clearer interfaces between components
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any
from datetime import datetime
from enum import Enum


class Severity(Enum):
    """Standardized severity levels across all sources."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Priority(Enum):
    """Threat priority levels."""
    P1 = "P1"  # Critical - immediate action required
    P2 = "P2"  # High - action required soon
    P3 = "P3"  # Medium - monitor and plan


class ConfidenceLevel(Enum):
    """Confidence levels for threat intelligence."""
    CONFIRMED = "Confirmed"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    VERY_LOW = "Very Low"
    UNKNOWN = "Unknown"


# =============================================================================
# Collector Data Types
# =============================================================================

@dataclass
class CVERecord:
    """Represents a CVE vulnerability record from NVD or other sources."""
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    published_date: str
    exploited: bool = False
    source: str = "NVD"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "published_date": self.published_date,
            "exploited": self.exploited,
            "source": self.source
        }


@dataclass
class ThreatReport:
    """Represents a threat intelligence report from Intel471 or similar."""
    source: str
    threat_actor: str
    threat_type: str
    confidence: str
    summary: str
    date: str
    tags: List[str] = field(default_factory=list)
    motivation: List[str] = field(default_factory=list)
    portal_url: str = ""
    uid: str = ""
    mitre_tactics: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "source": self.source,
            "threat_actor": self.threat_actor,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "summary": self.summary,
            "date": self.date,
            "tags": self.tags,
            "motivation": self.motivation,
            "portal_url": self.portal_url,
            "uid": self.uid,
            "mitre_tactics": self.mitre_tactics
        }


@dataclass
class APTActor:
    """Represents an APT actor from CrowdStrike or similar."""
    actor_name: str
    country: str
    motivations: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    target_industries: List[str] = field(default_factory=list)
    last_activity: str = ""
    indicator: str = ""
    source: str = "CrowdStrike"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "actor_name": self.actor_name,
            "country": self.country,
            "motivations": self.motivations,
            "ttps": self.ttps,
            "target_industries": self.target_industries,
            "last_activity": self.last_activity,
            "indicator": self.indicator,
            "source": self.source
        }


@dataclass
class ThreatIndicator:
    """Represents a threat indicator from ThreatQ or similar."""
    indicator_type: str
    value: str
    score: int
    status: str = "Unknown"
    last_seen: str = ""
    source: str = "ThreatQ"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "indicator_type": self.indicator_type,
            "value": self.value,
            "score": self.score,
            "status": self.status,
            "last_seen": self.last_seen,
            "source": self.source
        }


@dataclass
class VulnerabilitySummary:
    """Represents a vulnerability summary from Rapid7 or similar."""
    source: str
    total_vulnerabilities_scanned: int
    critical_severe_count: int
    unique_cve_count: int
    all_cve_ids: List[str] = field(default_factory=list)
    critical_count: int = 0
    severe_count: int = 0
    exploitable_count: int = 0
    top_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "source": self.source,
            "total_vulnerabilities_scanned": self.total_vulnerabilities_scanned,
            "critical_severe_count": self.critical_severe_count,
            "unique_cve_count": self.unique_cve_count,
            "all_cve_ids": self.all_cve_ids,
            "critical_count": self.critical_count,
            "severe_count": self.severe_count,
            "exploitable_count": self.exploitable_count,
            "top_vulnerabilities": self.top_vulnerabilities
        }


# =============================================================================
# Analysis Types
# =============================================================================

@dataclass
class ThreatAnalysisResult:
    """Structured result from threat analysis."""
    executive_summary: str
    top_threats: List[Dict[str, Any]]
    cve_analysis: List[Dict[str, Any]]
    apt_activity: List[Dict[str, Any]]
    recommendations: List[str]
    statistics: Dict[str, int]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "executive_summary": self.executive_summary,
            "top_threats": self.top_threats,
            "cve_analysis": self.cve_analysis,
            "apt_activity": self.apt_activity,
            "recommendations": self.recommendations,
            "statistics": self.statistics
        }


@dataclass
class ReportResult:
    """Result from report generation and upload."""
    success: bool
    filename: str | None = None
    url: str | None = None
    error: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {"success": self.success}
        if self.filename:
            result["filename"] = self.filename
        if self.url:
            result["url"] = self.url
        if self.error:
            result["error"] = self.error
        return result


# =============================================================================
# Collector Result Types
# =============================================================================

@dataclass
class CollectorResult:
    """Generic result from a collector."""
    source: str
    success: bool
    data: List[Dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    record_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "source": self.source,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "record_count": self.record_count
        }


# =============================================================================
# Credentials Types
# =============================================================================

@dataclass
class APICredentials:
    """Container for all API credentials stored in Key Vault."""
    # Threat Intelligence APIs
    nvd_key: str = ""
    threatq_key: str = ""
    threatq_url: str = ""
    intel471_email: str = ""
    intel471_key: str = ""
    crowdstrike_id: str = ""
    crowdstrike_secret: str = ""
    crowdstrike_base_url: str = ""
    rapid7_key: str = ""
    rapid7_region: str = ""
    # Azure OpenAI
    openai_key: str = ""
    openai_endpoint: str = ""
    # Azure Storage
    storage_account_name: str = ""
    storage_account_key: str = ""

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary (for backwards compatibility)."""
        return {
            "nvd_key": self.nvd_key,
            "threatq_key": self.threatq_key,
            "threatq_url": self.threatq_url,
            "intel471_email": self.intel471_email,
            "intel471_key": self.intel471_key,
            "crowdstrike_id": self.crowdstrike_id,
            "crowdstrike_secret": self.crowdstrike_secret,
            "crowdstrike_base_url": self.crowdstrike_base_url,
            "rapid7_key": self.rapid7_key,
            "rapid7_region": self.rapid7_region,
            "openai_key": self.openai_key,
            "openai_endpoint": self.openai_endpoint,
            "storage_account_name": self.storage_account_name,
            "storage_account_key": self.storage_account_key
        }
