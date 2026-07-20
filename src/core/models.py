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
from typing import Any

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
    affected_product: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "published_date": self.published_date,
            "exploited": self.exploited,
            "source": self.source,
            "affected_product": self.affected_product,
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
    tags: list[str] = field(default_factory=list)
    motivation: list[str] = field(default_factory=list)
    portal_url: str = ""
    uid: str = ""
    mitre_tactics: str = ""

    def to_dict(self) -> dict[str, Any]:
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
            "mitre_tactics": self.mitre_tactics,
        }


@dataclass
class APTActor:
    """Represents an APT actor from CrowdStrike or similar."""

    actor_name: str
    country: str
    motivations: list[str] = field(default_factory=list)
    ttps: list[str] = field(default_factory=list)
    target_industries: list[str] = field(default_factory=list)
    last_activity: str = ""
    indicator: str = ""
    source: str = "CrowdStrike"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "actor_name": self.actor_name,
            "country": self.country,
            "motivations": self.motivations,
            "ttps": self.ttps,
            "target_industries": self.target_industries,
            "last_activity": self.last_activity,
            "indicator": self.indicator,
            "source": self.source,
        }


# =============================================================================
# Analysis Types
# =============================================================================


@dataclass
class ThreatAnalysisResult:
    """Structured result from threat analysis (weekly)."""

    executive_summary: str
    top_threats: list[dict[str, Any]]
    cve_analysis: list[dict[str, Any]]
    apt_activity: list[dict[str, Any]]
    recommendations: list[str]
    statistics: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "executive_summary": self.executive_summary,
            "top_threats": self.top_threats,
            "cve_analysis": self.cve_analysis,
            "apt_activity": self.apt_activity,
            "recommendations": self.recommendations,
            "statistics": self.statistics,
        }


@dataclass
class ReportResult:
    """Result from report generation and upload."""

    success: bool
    filename: str | None = None
    url: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
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
    data: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    record_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "source": self.source,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "record_count": self.record_count,
        }
