"""
CVE Enrichment Module

Enriches CVE data with additional information from multiple sources:
- CPE (Common Platform Enumeration) data from NVD
- CISA Known Exploited Vulnerabilities (KEV) catalog
- Web search for missing product/vendor information (configurable)
"""
import logging
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class CVEEnricher:
    """
    Enriches CVE records with additional context from multiple sources.
    
    Configuration:
        Uses src.core.config.enrichment_config for settings:
        - enable_web_search: Toggle web search on/off
        - web_search_timeout_seconds: Timeout for each search
        - max_web_searches_per_run: Limit total searches per enrichment run
        - kev_cache_duration_hours: How long to cache CISA KEV data
    """
    
    # CISA KEV catalog URL
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def __init__(self):
        """Initialize the CVE enricher."""
        self._kev_cache: Optional[Dict[str, Any]] = None
        self._kev_cache_time: Optional[datetime] = None
        self._web_search_count = 0  # Track searches per run
        
        # Load config
        from src.core.config import enrichment_config
        self.config = enrichment_config
        self._cache_ttl = timedelta(hours=self.config.kev_cache_duration_hours)
    
    async def enrich_cves(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich a list of CVEs with additional information.
        
        Uses configuration from enrichment_config:
        - Checks CISA KEV catalog (always)
        - Uses pattern matching on descriptions (always)
        - Falls back to web search if enabled and needed
        
        Args:
            cves: List of CVE dictionaries
        
        Returns:
            Enriched CVE list with affected_product, exploited_by, and other fields
        """
        logger.info(f"Enriching {len(cves)} CVEs...")
        logger.info(f"Web search: {'ENABLED' if self.config.enable_web_search else 'DISABLED'}")
        
        # Reset search counter for this run
        self._web_search_count = 0
        
        # Load CISA KEV catalog
        kev_data = await self._load_kev_catalog()
        
        enriched_cves = []
        for cve in cves:
            enriched = await self._enrich_single_cve(cve, kev_data)
            enriched_cves.append(enriched)
        
        logger.info(f"Enrichment complete. {len(enriched_cves)} CVEs enriched.")
        if self.config.enable_web_search:
            logger.info(f"Web searches performed: {self._web_search_count}/{self.config.max_web_searches_per_run}")
        
        return enriched_cves
    
    async def _load_kev_catalog(self) -> Dict[str, Any]:
        """
        Load CISA KEV catalog with caching.
        
        Returns:
            Dictionary mapping CVE IDs to KEV entries
        """
        # Check cache
        if self._kev_cache and self._kev_cache_time:
            if datetime.now() - self._kev_cache_time < self._cache_ttl:
                logger.debug("Using cached KEV data")
                return self._kev_cache
        
        logger.info("Fetching CISA KEV catalog...")
        try:
            from src.collectors.http_utils import HTTPClient
            
            async with HTTPClient() as client:
                data = await client.get(self.CISA_KEV_URL)
                
                # Build lookup dictionary
                kev_dict = {}
                for vuln in data.get("vulnerabilities", []):
                    cve_id = vuln.get("cveID")
                    if cve_id:
                        kev_dict[cve_id] = {
                            "vendor": vuln.get("vendorProject", ""),
                            "product": vuln.get("product", ""),
                            "vulnerability_name": vuln.get("vulnerabilityName", ""),
                            "date_added": vuln.get("dateAdded", ""),
                            "short_description": vuln.get("shortDescription", ""),
                            "required_action": vuln.get("requiredAction", ""),
                            "due_date": vuln.get("dueDate", ""),
                            "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown")
                        }
                
                self._kev_cache = kev_dict
                self._kev_cache_time = datetime.now()
                
                logger.info(f"Loaded {len(kev_dict)} entries from CISA KEV catalog")
                return kev_dict
                
        except Exception as e:
            logger.error(f"Failed to load CISA KEV catalog: {e}")
            return {}
    
    async def _enrich_single_cve(
        self,
        cve: Dict[str, Any],
        kev_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enrich a single CVE with additional information.
        
        Args:
            cve: CVE dictionary
            kev_data: CISA KEV lookup dictionary
        
        Returns:
            Enriched CVE dictionary
        """
        enriched = cve.copy()
        cve_id = cve.get("cve_id", "")
        
        # Check CISA KEV first
        if cve_id in kev_data:
            kev_entry = kev_data[cve_id]
            enriched["affected_product"] = f"{kev_entry['vendor']} {kev_entry['product']}".strip()
            enriched["exploited"] = True
            enriched["exploited_by"] = self._determine_exploited_by(kev_entry)
            enriched["in_cisa_kev"] = True
            enriched["kev_required_action"] = kev_entry.get("required_action", "")
            enriched["known_ransomware"] = kev_entry.get("known_ransomware", "Unknown")
            
            logger.debug(f"{cve_id} found in CISA KEV catalog")
        else:
            # Not in KEV - try to extract from description or use web search
            enriched["in_cisa_kev"] = False
            enriched["exploited"] = False
            enriched["exploited_by"] = "None known"
            
            # Try to extract product from description
            affected_product = self._extract_product_from_description(cve.get("description", ""))
            enriched["affected_product"] = affected_product if affected_product else "N/A"
            
            # If still N/A and web search is enabled, search for product info
            if enriched["affected_product"] == "N/A" and self.config.enable_web_search:
                # Check if we haven't exceeded search limit
                if self._web_search_count < self.config.max_web_searches_per_run:
                    enriched["affected_product"] = await self._search_for_product(cve_id)
                    self._web_search_count += 1
                else:
                    logger.debug(f"Skipping web search for {cve_id} - limit reached")
        
        # Add exposure status (placeholder - would need org-specific data)
        enriched["exposure"] = "N/A"  # Could be enriched with asset inventory data
        
        return enriched
    
    def _determine_exploited_by(self, kev_entry: Dict[str, Any]) -> str:
        """
        Determine who is exploiting the vulnerability based on KEV data.
        
        Args:
            kev_entry: KEV catalog entry
        
        Returns:
            String describing exploitation activity
        """
        parts = []
        
        if kev_entry.get("known_ransomware") == "Known":
            parts.append("Ransomware groups")
        
        # Could be enhanced with more intelligence sources
        if parts:
            return ", ".join(parts)
        
        return "Active exploitation observed (CISA KEV)"
    
    def _extract_product_from_description(self, description: str) -> Optional[str]:
        """
        Extract product/vendor from CVE description using pattern matching.
        
        Args:
            description: CVE description text
        
        Returns:
            Product name if found, None otherwise
        """
        if not description:
            return None
        
        # Common patterns in CVE descriptions
        patterns = [
            # "Product X version Y"
            # "Vendor Product before version"
            # etc.
        ]
        
        # Simple heuristic: Look for capitalized words near "in", "of", "for"
        import re
        
        # Pattern: "in Product Name before"
        match = re.search(r'\sin\s+([A-Z][A-Za-z0-9\s]+?)\s+(?:before|prior|through|version)', description)
        if match:
            product = match.group(1).strip()
            # Limit length
            if len(product) < 50:
                return product
        
        # Pattern: "Vendor Product version"
        match = re.search(r'([A-Z][a-z]+\s+[A-Z][A-Za-z0-9]+)\s+(?:version|\d)', description)
        if match:
            product = match.group(1).strip()
            if len(product) < 50:
                return product
        
        return None
    
    async def _search_for_product(self, cve_id: str) -> str:
        """
        Search the web for CVE product information.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Product name or "N/A"
        """
        try:
            logger.debug(f"Web searching for {cve_id} product information...")
            
            # Import here to avoid circular dependencies
            import asyncio
            from concurrent.futures import ThreadPoolExecutor
            
            # Web search needs to run in a thread pool as it's not async
            def sync_search():
                try:
                    # Use WebSearch tool via shell command approach
                    # This is a workaround since WebSearch isn't directly available in async context
                    import subprocess
                    import json
                    
                    # Search for CVE details
                    search_query = f"{cve_id} affected product vendor vulnerability"
                    
                    # For now, try to parse from NVD API or CVE.org
                    # TODO: Implement actual Cursor WebSearch tool integration
                    # When Cursor provides async WebSearch, replace this
                    
                    logger.debug(f"Searching: {search_query}")
                    
                    # Placeholder: In a real implementation, this would use WebSearch tool
                    # For now, return N/A to avoid errors
                    return "N/A"
                    
                except Exception as e:
                    logger.warning(f"Search failed for {cve_id}: {e}")
                    return "N/A"
            
            # Run in thread pool with timeout
            with ThreadPoolExecutor(max_workers=1) as executor:
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(executor, sync_search),
                    timeout=self.config.web_search_timeout_seconds
                )
                return result
            
        except asyncio.TimeoutError:
            logger.warning(f"Web search timed out for {cve_id}")
            return "N/A"
        except Exception as e:
            logger.warning(f"Web search failed for {cve_id}: {e}")
            return "N/A"


class ThreatActorMonitoringEnricher:
    """
    Generates monitoring recommendations for threat actors.
    """
    
    # Mapping of threat actors to their common indicators
    ACTOR_MONITORING_GUIDANCE = {
        "CASCADE PANDA": {
            "ttps": ["Spear phishing", "Supply chain compromise", "Living-off-the-land techniques"],
            "indicators": ["Monitor for suspicious PowerShell activity", "Watch for unusual network connections to Asia-Pacific regions", "Scan for signs of credential harvesting"],
            "focus": "Intellectual property theft in biotech/pharma sectors"
        },
        "PLUMP SPIDER": {
            "ttps": ["Ransomware deployment", "Data exfiltration", "Initial access broker collaboration"],
            "indicators": ["Anomalous SMB traffic", "Unusual administrative tool usage", "Large data transfers to external IPs"],
            "focus": "Ransomware attacks on healthcare and research institutions"
        },
        "ROYAL SPIDER": {
            "ttps": ["Royal ransomware deployment", "Double extortion", "Vulnerability exploitation"],
            "indicators": ["Monitor for Royal ransomware indicators", "Watch for data staging activities", "Detect lateral movement patterns"],
            "focus": "Targeting healthcare and life sciences organizations"
        },
        "HOOK SPIDER": {
            "ttps": ["Initial access via phishing", "Credential theft", "Privilege escalation"],
            "indicators": ["Suspicious email attachments", "Unusual login patterns", "Elevated privilege usage"],
            "focus": "Financial crime and data theft"
        },
        "MUSTANG PANDA": {
            "ttps": ["PlugX malware", "Strategic web compromises", "Document exploitation"],
            "indicators": ["Monitor for PlugX signatures", "Detect malicious documents", "Watch for C2 beaconing patterns"],
            "focus": "Espionage targeting government and research sectors"
        }
    }
    
    def enrich_threat_actors(self, actors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enrich threat actor data with monitoring recommendations.
        
        Args:
            actors: List of threat actor dictionaries
        
        Returns:
            Enriched list with monitoring guidance
        """
        enriched = []
        
        for actor in actors:
            actor_data = actor.copy()
            actor_name = actor.get("actor", actor.get("name", "")).upper()
            
            # Check if we have guidance for this actor
            for known_actor, guidance in self.ACTOR_MONITORING_GUIDANCE.items():
                if known_actor in actor_name:
                    actor_data["monitoring_guidance"] = guidance["indicators"]
                    actor_data["known_ttps"] = guidance["ttps"]
                    actor_data["focus_area"] = guidance["focus"]
                    break
            else:
                # Generic monitoring guidance
                actor_data["monitoring_guidance"] = [
                    "Monitor for indicators associated with this actor",
                    "Review logs for suspicious authentication attempts",
                    "Watch for unusual lateral movement patterns"
                ]
            
            enriched.append(actor_data)
        
        return enriched
