"""
IOC Correlator.

Correlates threat indicators across multiple intelligence sources to provide
actor attribution and context. Transforms raw IOCs into actionable intelligence
by linking them to known threat actors, campaigns, and TTPs.

Correlation Strategy:
    1. ThreatQ Native: Pull adversaries with linked indicators
    2. CrowdStrike Enrichment: Cross-reference IOCs against CrowdStrike intel
    3. Value Matching: Match IOC values across sources for attribution
"""
import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class EnrichedIOC:
    """
    An IOC enriched with threat actor attribution and context.
    
    This represents the output of the correlation process, combining
    raw indicator data with actor intelligence from multiple sources.
    """
    value: str
    indicator_type: str
    score: int
    status: str
    sources: List[str] = field(default_factory=list)
    
    # Attribution fields
    attributed_actors: List[str] = field(default_factory=list)
    actor_countries: List[str] = field(default_factory=list)
    actor_motivations: List[str] = field(default_factory=list)
    target_industries: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    
    # Context
    first_seen: str = ""
    last_seen: str = ""
    confidence: str = "Medium"
    correlation_sources: List[str] = field(default_factory=list)
    
    # Relevance to organization
    relevance_score: int = 0
    relevance_reason: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "value": self.value,
            "indicator_type": self.indicator_type,
            "score": self.score,
            "status": self.status,
            "sources": self.sources,
            "attributed_actors": self.attributed_actors,
            "actor_countries": self.actor_countries,
            "actor_motivations": self.actor_motivations,
            "target_industries": self.target_industries,
            "ttps": self.ttps,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "confidence": self.confidence,
            "correlation_sources": self.correlation_sources,
            "relevance_score": self.relevance_score,
            "relevance_reason": self.relevance_reason
        }


@dataclass
class CorrelationResult:
    """Result of the IOC correlation process."""
    enriched_iocs: List[EnrichedIOC]
    attributed_count: int
    unattributed_count: int
    actors_identified: List[str]
    correlation_stats: Dict[str, int]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "enriched_iocs": [ioc.to_dict() for ioc in self.enriched_iocs],
            "attributed_count": self.attributed_count,
            "unattributed_count": self.unattributed_count,
            "actors_identified": self.actors_identified,
            "correlation_stats": self.correlation_stats
        }


class IOCCorrelator:
    """
    Correlates IOCs across multiple threat intelligence sources.
    
    Builds attribution by:
    1. Using native ThreatQ adversary-indicator relationships
    2. Matching IOC values against CrowdStrike attributed indicators
    3. Inferring attribution from shared infrastructure patterns
    
    Usage:
        correlator = IOCCorrelator(target_industries=["Healthcare", "Biotechnology"])
        result = correlator.correlate(
            threatq_data=threatq_collector_result,
            crowdstrike_data=crowdstrike_collector_result
        )
    """
    
    # Industry keywords for relevance scoring
    BIOTECH_KEYWORDS = (
        "biotech", "genomics", "healthcare", "hospital", "medical",
        "pharmaceutical", "life sciences", "research", "clinical",
        "patient", "health", "laboratory", "diagnostics", "bioinformatics",
        "genetic", "therapy", "drug", "vaccine", "clinical trial"
    )
    
    def __init__(self, target_industries: Optional[List[str]] = None):
        """
        Initialize the correlator.
        
        Args:
            target_industries: Industries to prioritize for relevance scoring
        """
        self.target_industries = target_industries or [
            "Healthcare", "Pharmaceutical", "Biotechnology",
            "Life Sciences", "Medical Devices", "Research"
        ]
        
        # Lookup tables built during correlation
        self._crowdstrike_ioc_index: Dict[str, Dict[str, Any]] = {}
        self._crowdstrike_actor_index: Dict[str, Dict[str, Any]] = {}
        self._threatq_adversary_index: Dict[str, Dict[str, Any]] = {}
    
    def correlate(
        self,
        threatq_indicators: List[Dict[str, Any]],
        threatq_adversaries: List[Dict[str, Any]],
        crowdstrike_actors: List[Dict[str, Any]],
        crowdstrike_indicators: List[Dict[str, Any]]
    ) -> CorrelationResult:
        """
        Correlate IOCs across all sources and enrich with attribution.
        
        Args:
            threatq_indicators: Indicators from ThreatQ collector
            threatq_adversaries: Adversaries with linked indicators from ThreatQ
            crowdstrike_actors: Actor profiles from CrowdStrike
            crowdstrike_indicators: Attributed indicators from CrowdStrike
            
        Returns:
            CorrelationResult with enriched IOCs and statistics
        """
        logger.info("Starting IOC correlation across sources")
        
        # Step 1: Build lookup indices
        self._build_crowdstrike_indices(crowdstrike_actors, crowdstrike_indicators)
        self._build_threatq_adversary_index(threatq_adversaries)
        
        # Step 2: Enrich each ThreatQ indicator
        enriched_iocs: List[EnrichedIOC] = []
        
        for indicator in threatq_indicators:
            enriched = self._enrich_indicator(indicator)
            enriched_iocs.append(enriched)
        
        # Step 3: Add CrowdStrike indicators not in ThreatQ
        threatq_values = {ioc.value for ioc in enriched_iocs}
        for cs_indicator in crowdstrike_indicators:
            indicator_value = cs_indicator.get("indicator", "")
            if indicator_value and indicator_value not in threatq_values:
                enriched = self._enrich_crowdstrike_indicator(cs_indicator)
                enriched_iocs.append(enriched)
        
        # Step 4: Sort by relevance and score
        enriched_iocs.sort(key=lambda x: (x.relevance_score, x.score), reverse=True)
        
        # Step 5: Calculate statistics
        attributed = [ioc for ioc in enriched_iocs if ioc.attributed_actors]
        unattributed = [ioc for ioc in enriched_iocs if not ioc.attributed_actors]
        
        all_actors: Set[str] = set()
        for ioc in enriched_iocs:
            all_actors.update(ioc.attributed_actors)
        
        stats = {
            "total_iocs": len(enriched_iocs),
            "threatq_source": len(threatq_indicators),
            "crowdstrike_source": len(crowdstrike_indicators),
            "threatq_adversary_matches": sum(
                1 for ioc in enriched_iocs if "ThreatQ Adversary" in ioc.correlation_sources
            ),
            "crowdstrike_matches": sum(
                1 for ioc in enriched_iocs if "CrowdStrike" in ioc.correlation_sources
            ),
            "high_relevance": sum(1 for ioc in enriched_iocs if ioc.relevance_score >= 80),
            "medium_relevance": sum(1 for ioc in enriched_iocs if 50 <= ioc.relevance_score < 80),
        }
        
        logger.info(
            f"Correlation complete: {len(attributed)} attributed, "
            f"{len(unattributed)} unattributed, {len(all_actors)} unique actors"
        )
        
        return CorrelationResult(
            enriched_iocs=enriched_iocs,
            attributed_count=len(attributed),
            unattributed_count=len(unattributed),
            actors_identified=sorted(all_actors),
            correlation_stats=stats
        )
    
    def _build_crowdstrike_indices(
        self,
        actors: List[Dict[str, Any]],
        indicators: List[Dict[str, Any]]
    ) -> None:
        """
        Build lookup indices from CrowdStrike data.
        
        Creates:
            _crowdstrike_ioc_index: IOC value -> indicator with actor info
            _crowdstrike_actor_index: actor name -> actor profile
        """
        # Index actors by name
        for actor in actors:
            actor_name = actor.get("actor_name", "")
            if actor_name:
                self._crowdstrike_actor_index[actor_name.lower()] = actor
        
        # Index indicators by value
        for indicator in indicators:
            value = indicator.get("indicator", "")
            if value:
                self._crowdstrike_ioc_index[value.lower()] = indicator
        
        logger.info(
            f"Built CrowdStrike indices: {len(self._crowdstrike_actor_index)} actors, "
            f"{len(self._crowdstrike_ioc_index)} indicators"
        )
    
    def _build_threatq_adversary_index(
        self,
        adversaries: List[Dict[str, Any]]
    ) -> None:
        """
        Build index mapping indicator IDs to their associated adversaries.
        
        ThreatQ adversaries come with linked indicator IDs when fetched
        with ?with=indicators parameter.
        """
        for adversary in adversaries:
            adversary_name = adversary.get("name", "")
            indicator_ids = adversary.get("indicator_ids", [])
            
            for ind_id in indicator_ids:
                if ind_id not in self._threatq_adversary_index:
                    self._threatq_adversary_index[ind_id] = adversary
                else:
                    # Multiple adversaries for same indicator - keep both
                    existing = self._threatq_adversary_index[ind_id]
                    if isinstance(existing, list):
                        existing.append(adversary)
                    else:
                        self._threatq_adversary_index[ind_id] = [existing, adversary]
        
        logger.info(
            f"Built ThreatQ adversary index: {len(adversaries)} adversaries, "
            f"{len(self._threatq_adversary_index)} indicator mappings"
        )
    
    def _enrich_indicator(self, indicator: Dict[str, Any]) -> EnrichedIOC:
        """
        Enrich a ThreatQ indicator with attribution from all sources.
        
        Correlation order:
            1. Check ThreatQ native adversary linkage
            2. Cross-reference against CrowdStrike IOC index
            3. Calculate relevance score
        """
        value = indicator.get("value", "")
        indicator_id = indicator.get("id")
        
        enriched = EnrichedIOC(
            value=value,
            indicator_type=indicator.get("indicator_type", "Unknown"),
            score=indicator.get("score", 0),
            status=indicator.get("status", "Unknown"),
            sources=["ThreatQ"] + indicator.get("threatq_sources", []),
            first_seen=indicator.get("created_at", ""),
            last_seen=indicator.get("last_seen", "")
        )
        
        # Method 1: ThreatQ native adversary linkage
        if indicator_id and indicator_id in self._threatq_adversary_index:
            adversary_data = self._threatq_adversary_index[indicator_id]
            adversaries = adversary_data if isinstance(adversary_data, list) else [adversary_data]
            
            for adv in adversaries:
                if adv.get("name"):
                    enriched.attributed_actors.append(adv["name"])
                enriched.actor_motivations.extend(adv.get("tags", []))
            
            enriched.correlation_sources.append("ThreatQ Adversary")
            enriched.confidence = "High"
        
        # Method 2: CrowdStrike IOC cross-reference
        cs_match = self._crowdstrike_ioc_index.get(value.lower())
        if cs_match:
            actor_name = cs_match.get("actor_name", "")
            if actor_name and actor_name != "Unknown":
                if actor_name not in enriched.attributed_actors:
                    enriched.attributed_actors.append(actor_name)
                
                # Get full actor profile
                actor_profile = self._crowdstrike_actor_index.get(actor_name.lower())
                if actor_profile:
                    enriched.actor_countries.extend(
                        [actor_profile.get("country", "")] if actor_profile.get("country") else []
                    )
                    enriched.actor_motivations.extend(actor_profile.get("motivations", []))
                    enriched.target_industries.extend(actor_profile.get("target_industries", []))
                    enriched.ttps.extend(actor_profile.get("ttps", []))
            
            enriched.correlation_sources.append("CrowdStrike")
            if enriched.confidence != "High":
                enriched.confidence = "High" if actor_name else "Medium"
        
        # Method 3: Actor name matching (check if IOC value appears in actor intel)
        if not enriched.attributed_actors:
            for actor_name, actor_profile in self._crowdstrike_actor_index.items():
                # Check if this actor targets relevant industries
                actor_industries = actor_profile.get("target_industries", [])
                if self._has_relevant_industry(actor_industries):
                    # This actor is relevant but we can't directly attribute
                    # Just note them as potentially relevant
                    pass
        
        # Calculate relevance score
        enriched.relevance_score, enriched.relevance_reason = self._calculate_relevance(enriched)
        
        # Deduplicate lists
        enriched.attributed_actors = list(dict.fromkeys(enriched.attributed_actors))
        enriched.actor_countries = list(dict.fromkeys(enriched.actor_countries))
        enriched.actor_motivations = list(dict.fromkeys(enriched.actor_motivations))
        enriched.target_industries = list(dict.fromkeys(enriched.target_industries))
        enriched.ttps = list(dict.fromkeys(enriched.ttps))
        
        return enriched
    
    def _enrich_crowdstrike_indicator(self, indicator: Dict[str, Any]) -> EnrichedIOC:
        """
        Convert a CrowdStrike indicator to EnrichedIOC format.
        
        CrowdStrike indicators already have actor attribution.
        """
        actor_name = indicator.get("actor_name", "Unknown")
        
        enriched = EnrichedIOC(
            value=indicator.get("indicator", ""),
            indicator_type=indicator.get("ttps", ["Unknown"])[0] if indicator.get("ttps") else "Unknown",
            score=8 if indicator.get("actor_name") else 5,  # Higher score if attributed
            status="Active",
            sources=["CrowdStrike"],
            last_seen=indicator.get("last_activity", ""),
            correlation_sources=["CrowdStrike"]
        )
        
        if actor_name and actor_name != "Unknown":
            enriched.attributed_actors.append(actor_name)
            enriched.confidence = "High"
            
            # Get full actor profile
            actor_profile = self._crowdstrike_actor_index.get(actor_name.lower())
            if actor_profile:
                enriched.actor_countries = [actor_profile.get("country", "")] if actor_profile.get("country") else []
                enriched.actor_motivations = actor_profile.get("motivations", [])
                enriched.target_industries = actor_profile.get("target_industries", [])
                enriched.ttps = actor_profile.get("ttps", [])
        
        enriched.relevance_score, enriched.relevance_reason = self._calculate_relevance(enriched)
        
        return enriched
    
    def _calculate_relevance(self, ioc: EnrichedIOC) -> tuple[int, str]:
        """
        Calculate relevance score (0-100) for an IOC based on:
            - Actor attribution (higher if attributed)
            - Target industry overlap (higher if targets our sectors)
            - IOC score/severity
            - Confidence level
            
        Returns:
            Tuple of (score, reason)
        """
        score = 0
        reasons = []
        
        # Attribution bonus (up to 30 points)
        if ioc.attributed_actors:
            score += 30
            reasons.append(f"Attributed to {', '.join(ioc.attributed_actors[:2])}")
        
        # Industry targeting bonus (up to 40 points)
        if self._has_relevant_industry(ioc.target_industries):
            score += 40
            matching = [i for i in ioc.target_industries if i in self.target_industries]
            reasons.append(f"Targets {', '.join(matching[:2])}")
        
        # IOC score bonus (up to 20 points)
        if ioc.score >= 9:
            score += 20
            reasons.append("Critical severity")
        elif ioc.score >= 7:
            score += 15
            reasons.append("High severity")
        elif ioc.score >= 5:
            score += 10
        
        # Confidence bonus (up to 10 points)
        if ioc.confidence == "High":
            score += 10
        elif ioc.confidence == "Medium":
            score += 5
        
        reason = "; ".join(reasons) if reasons else "Low relevance indicators"
        
        return min(score, 100), reason
    
    def _has_relevant_industry(self, industries: List[str]) -> bool:
        """Check if any industry matches our target industries."""
        if not industries:
            return False
        
        industries_lower = [i.lower() for i in industries]
        targets_lower = [t.lower() for t in self.target_industries]
        
        for industry in industries_lower:
            if industry in targets_lower:
                return True
            # Partial match for keywords
            for keyword in self.BIOTECH_KEYWORDS:
                if keyword in industry:
                    return True
        
        return False
    
    def get_high_priority_iocs(
        self,
        result: CorrelationResult,
        min_relevance: int = 50,
        max_count: int = 20
    ) -> List[EnrichedIOC]:
        """
        Get highest priority IOCs for reporting.
        
        Args:
            result: CorrelationResult from correlate()
            min_relevance: Minimum relevance score to include
            max_count: Maximum number of IOCs to return
            
        Returns:
            List of high priority EnrichedIOCs
        """
        filtered = [
            ioc for ioc in result.enriched_iocs
            if ioc.relevance_score >= min_relevance
        ]
        
        return filtered[:max_count]
    
    def get_actor_summary(self, result: CorrelationResult) -> List[Dict[str, Any]]:
        """
        Generate actor summary with their associated IOCs.
        
        Returns a list of actors with:
            - Actor name and profile
            - Count of associated IOCs
            - Sample IOC values
            - Relevance to organization
        """
        actor_iocs: Dict[str, List[EnrichedIOC]] = defaultdict(list)
        
        for ioc in result.enriched_iocs:
            for actor in ioc.attributed_actors:
                actor_iocs[actor].append(ioc)
        
        summaries = []
        for actor_name, iocs in actor_iocs.items():
            # Get actor profile from CrowdStrike if available
            profile = self._crowdstrike_actor_index.get(actor_name.lower(), {})
            
            # Determine if this actor is relevant to us
            target_industries = profile.get("target_industries", [])
            is_relevant = self._has_relevant_industry(target_industries)
            
            summaries.append({
                "actor_name": actor_name,
                "country": profile.get("country", "Unknown"),
                "motivations": profile.get("motivations", []),
                "target_industries": target_industries,
                "ttps": profile.get("ttps", [])[:5],
                "ioc_count": len(iocs),
                "sample_iocs": [ioc.value for ioc in iocs[:5]],
                "avg_score": sum(ioc.score for ioc in iocs) / len(iocs) if iocs else 0,
                "relevant_to_org": is_relevant,
                "relevance_note": "Targets healthcare/biotech sector" if is_relevant else ""
            })
        
        # Sort by relevance and IOC count
        summaries.sort(key=lambda x: (x["relevant_to_org"], x["ioc_count"]), reverse=True)
        
        return summaries
