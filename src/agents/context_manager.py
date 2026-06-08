"""
Agent Context Manager for Historical Analysis Tracking.

Manages AI agent context and historical analysis in Azure Blob Storage.
Enables week-over-week and quarter-over-quarter trend analysis.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
from collections import defaultdict

from src.utils.cache_manager import CacheManager

logger = logging.getLogger(__name__)


class AgentContextManager:
    """
    Manages AI agent context and historical analysis in Blob Storage.
    
    Key Features:
    - Stores complete analysis results for each report
    - Tracks CVE history across reports (new, persistent, resolved)
    - Maintains threat actor activity timelines
    - Enables trend analysis and pattern detection
    - Supports both weekly and quarterly reports
    """
    
    def __init__(self, cache_manager: CacheManager):
        """
        Initialize context manager.
        
        Args:
            cache_manager: CacheManager instance for blob storage operations
        """
        self.cache = cache_manager
        logger.info("AgentContextManager initialized")
    
    def save_analysis_context(
        self,
        report_type: str,
        report_date: datetime,
        analysis_result: Dict[str, Any]
    ) -> bool:
        """
        Save analysis results for future reference.
        
        Stores:
        - Complete analysis result (CVEs, APT activity, incidents, recommendations)
        - CVE tracking data for quick trend calculations
        - Threat actor timeline
        - Executive summary for pattern matching
        
        Args:
            report_type: "weekly" or "quarterly"
            report_date: Date of the report
            analysis_result: Complete analysis dictionary from ThreatAnalystAgent
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Format date for consistent keys
            date_str = report_date.strftime("%Y-%m-%d")
            
            # Store complete analysis context
            context_key = f"analysis-context-{report_type}-{date_str}"
            logger.info(f"Saving analysis context: {context_key}")
            
            # Add metadata for context tracking
            context_data = {
                "report_type": report_type,
                "report_date": date_str,
                "saved_at": datetime.now().isoformat(),
                "analysis": analysis_result
            }
            
            success = self.cache.set_cache(context_key, context_data)
            
            if success:
                # Store CVE tracking separately for fast lookups
                self._save_cve_tracking(report_type, date_str, analysis_result)
                
                # Store threat actor timeline
                self._save_actor_timeline(report_type, date_str, analysis_result)
                
                logger.info(f"Analysis context saved successfully: {context_key}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error saving analysis context: {e}", exc_info=True)
            return False
    
    def _save_cve_tracking(
        self,
        report_type: str,
        date_str: str,
        analysis_result: Dict[str, Any]
    ):
        """Save CVE tracking data for trend analysis."""
        try:
            cve_analysis = analysis_result.get("cve_analysis", [])
            
            # Extract CVE IDs with severity and exploitation status
            cve_tracking = {
                "cves": [
                    {
                        "cve_id": cve.get("cve_id"),
                        "severity": cve.get("severity"),
                        "actively_exploited": cve.get("actively_exploited", False),
                        "in_cisa_kev": cve.get("in_cisa_kev", False),
                        "affected_product": cve.get("affected_product", ""),
                        "exposure": cve.get("exposure", "N/A")
                    }
                    for cve in cve_analysis
                    if cve.get("cve_id")
                ],
                "date": date_str,
                "total_count": len(cve_analysis)
            }
            
            tracking_key = f"cve-tracking-{report_type}-{date_str}"
            self.cache.set_cache(tracking_key, cve_tracking)
            logger.debug(f"CVE tracking saved: {len(cve_analysis)} CVEs")
            
        except Exception as e:
            logger.error(f"Error saving CVE tracking: {e}")
    
    def _save_actor_timeline(
        self,
        report_type: str,
        date_str: str,
        analysis_result: Dict[str, Any]
    ):
        """Save threat actor timeline for historical tracking."""
        try:
            apt_activity = analysis_result.get("apt_activity", [])
            
            actor_timeline = {
                "actors": [
                    {
                        "actor": apt.get("actor"),
                        "country": apt.get("country"),
                        "motivation": apt.get("motivation"),
                        "activity_summary": apt.get("activity", "")[:200]  # Truncate for storage
                    }
                    for apt in apt_activity
                    if apt.get("actor")
                ],
                "date": date_str,
                "total_count": len(apt_activity)
            }
            
            timeline_key = f"actor-timeline-{report_type}-{date_str}"
            self.cache.set_cache(timeline_key, actor_timeline)
            logger.debug(f"Actor timeline saved: {len(apt_activity)} actors")
            
        except Exception as e:
            logger.error(f"Error saving actor timeline: {e}")
    
    def get_previous_context(
        self,
        report_type: str,
        current_date: Optional[datetime] = None,
        lookback_weeks: int = 4
    ) -> List[Dict[str, Any]]:
        """
        Retrieve previous analysis contexts for comparison.
        
        Args:
            report_type: "weekly" or "quarterly"
            current_date: Reference date (defaults to now)
            lookback_weeks: Number of weeks to look back
            
        Returns:
            List of previous analysis contexts, most recent first
        """
        if current_date is None:
            current_date = datetime.now()
        
        contexts = []
        
        # Determine lookback interval based on report type
        if report_type == "quarterly":
            # For quarterly reports, look back by quarters (13 weeks)
            interval_days = 90
            lookback_count = max(1, lookback_weeks // 13)  # Convert weeks to quarters
        else:
            # For weekly reports, look back by weeks
            interval_days = 7
            lookback_count = lookback_weeks
        
        logger.info(f"Retrieving {lookback_count} previous {report_type} contexts")
        
        for i in range(1, lookback_count + 1):
            previous_date = current_date - timedelta(days=interval_days * i)
            date_str = previous_date.strftime("%Y-%m-%d")
            context_key = f"analysis-context-{report_type}-{date_str}"
            
            # Try to get context (30-day TTL for historical data)
            cached_context = self.cache.get_cache(context_key, max_age_hours=24 * 30)
            
            if cached_context:
                logger.debug(f"Found context: {context_key}")
                contexts.append(cached_context)
            else:
                # Try nearby dates (reports might not be exactly 7 days apart)
                for offset in [-1, 1, -2, 2]:
                    alt_date = previous_date + timedelta(days=offset)
                    alt_key = f"analysis-context-{report_type}-{alt_date.strftime('%Y-%m-%d')}"
                    cached_context = self.cache.get_cache(alt_key, max_age_hours=24 * 30)
                    if cached_context:
                        logger.debug(f"Found context at offset {offset}: {alt_key}")
                        contexts.append(cached_context)
                        break
        
        logger.info(f"Retrieved {len(contexts)} previous contexts for {report_type} report")
        return contexts
    
    def calculate_cve_trends(
        self,
        current_cves: List[Dict[str, Any]],
        previous_contexts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculate CVE trends: new, persistent, resolved.
        
        Args:
            current_cves: List of CVE dicts from current analysis
            previous_contexts: List of previous analysis contexts
            
        Returns:
            Dictionary with trend analysis:
            - new_cves: CVEs appearing for the first time
            - persistent_cves: CVEs present in previous report
            - resolved_cves: CVEs from last report no longer present
            - recurrent_cves: CVEs that disappeared and reappeared
            - trend_summary: Human-readable summary
        """
        if not previous_contexts:
            logger.info("No previous contexts available for trend analysis")
            return {
                "new_cves": [cve.get("cve_id") for cve in current_cves if cve.get("cve_id")],
                "persistent_cves": [],
                "resolved_cves": [],
                "recurrent_cves": [],
                "trend_summary": "First report - no historical comparison available"
            }
        
        # Current CVE IDs
        current_cve_ids = {cve.get("cve_id") for cve in current_cves if cve.get("cve_id")}
        
        # Last week's CVE IDs
        last_context = previous_contexts[0]
        last_analysis = last_context.get("analysis", {})
        last_cve_analysis = last_analysis.get("cve_analysis", [])
        last_cve_ids = {cve.get("cve_id") for cve in last_cve_analysis if cve.get("cve_id")}
        
        # Historical CVE IDs (all previous reports)
        historical_cve_ids = set()
        for context in previous_contexts:
            analysis = context.get("analysis", {})
            cve_analysis = analysis.get("cve_analysis", [])
            historical_cve_ids.update(
                cve.get("cve_id") for cve in cve_analysis if cve.get("cve_id")
            )
        
        # Calculate trends
        new_cves = list(current_cve_ids - historical_cve_ids)
        persistent_cves = list(current_cve_ids & last_cve_ids)
        resolved_cves = list(last_cve_ids - current_cve_ids)
        recurrent_cves = list((current_cve_ids & historical_cve_ids) - last_cve_ids)
        
        # Build summary
        trend_lines = []
        trend_lines.append(f"{len(new_cves)} new CVEs detected")
        trend_lines.append(f"{len(persistent_cves)} CVEs remain unresolved from last report")
        trend_lines.append(f"{len(resolved_cves)} CVEs resolved since last report")
        if recurrent_cves:
            trend_lines.append(f"{len(recurrent_cves)} CVEs reappeared after previous resolution")
        
        trend_summary = "; ".join(trend_lines)
        
        logger.info(f"CVE Trends: {trend_summary}")
        
        return {
            "new_cves": new_cves,
            "persistent_cves": persistent_cves,
            "resolved_cves": resolved_cves,
            "recurrent_cves": recurrent_cves,
            "trend_summary": trend_summary,
            "weeks_analyzed": len(previous_contexts) + 1
        }
    
    def calculate_actor_trends(
        self,
        current_actors: List[Dict[str, Any]],
        previous_contexts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculate threat actor trends.
        
        Args:
            current_actors: List of APT activity dicts from current analysis
            previous_contexts: List of previous analysis contexts
            
        Returns:
            Dictionary with actor trend analysis
        """
        if not previous_contexts:
            return {
                "new_actors": [a.get("actor") for a in current_actors if a.get("actor")],
                "persistent_actors": [],
                "inactive_actors": [],
                "trend_summary": "First report - no historical actor tracking available"
            }
        
        # Current actor names
        current_actor_names = {a.get("actor") for a in current_actors if a.get("actor")}
        
        # Last report's actors
        last_context = previous_contexts[0]
        last_analysis = last_context.get("analysis", {})
        last_apt = last_analysis.get("apt_activity", [])
        last_actor_names = {a.get("actor") for a in last_apt if a.get("actor")}
        
        # Historical actors
        historical_actor_names = set()
        for context in previous_contexts:
            analysis = context.get("analysis", {})
            apt_activity = analysis.get("apt_activity", [])
            historical_actor_names.update(
                a.get("actor") for a in apt_activity if a.get("actor")
            )
        
        # Calculate trends
        new_actors = list(current_actor_names - historical_actor_names)
        persistent_actors = list(current_actor_names & last_actor_names)
        inactive_actors = list(last_actor_names - current_actor_names)
        
        # Build summary
        trend_lines = []
        if new_actors:
            trend_lines.append(f"{len(new_actors)} new threat actors identified")
        if persistent_actors:
            trend_lines.append(f"{len(persistent_actors)} actors remain active from last report")
        if inactive_actors:
            trend_lines.append(f"{len(inactive_actors)} actors show reduced activity")
        
        trend_summary = "; ".join(trend_lines) if trend_lines else "No significant actor changes"
        
        logger.info(f"Actor Trends: {trend_summary}")
        
        return {
            "new_actors": new_actors,
            "persistent_actors": persistent_actors,
            "inactive_actors": inactive_actors,
            "trend_summary": trend_summary
        }
    
    def get_historical_statistics(
        self,
        report_type: str,
        lookback_weeks: int = 12
    ) -> Dict[str, Any]:
        """
        Get historical statistics for trend visualization.
        
        Args:
            report_type: "weekly" or "quarterly"
            lookback_weeks: Number of weeks to analyze
            
        Returns:
            Dictionary with historical metrics over time
        """
        contexts = self.get_previous_context(report_type, lookback_weeks=lookback_weeks)
        
        if not contexts:
            return {
                "available": False,
                "message": "No historical data available"
            }
        
        # Extract metrics from each historical report
        timeline = []
        for context in reversed(contexts):  # Chronological order
            analysis = context.get("analysis", {})
            report_date = context.get("report_date", "Unknown")
            
            cve_analysis = analysis.get("cve_analysis", [])
            apt_activity = analysis.get("apt_activity", [])
            statistics = analysis.get("statistics", {})
            
            timeline.append({
                "date": report_date,
                "total_cves": len(cve_analysis),
                "critical_cves": sum(1 for c in cve_analysis if c.get("severity") == "CRITICAL"),
                "exploited_cves": sum(1 for c in cve_analysis if c.get("actively_exploited")),
                "threat_actors": len(apt_activity),
                "peer_incidents": statistics.get("peer_incidents", 0)
            })
        
        return {
            "available": True,
            "timeline": timeline,
            "weeks_analyzed": len(timeline)
        }
    
    def list_available_contexts(
        self,
        report_type: Optional[str] = None
    ) -> List[str]:
        """
        List all available analysis contexts in storage.
        
        Args:
            report_type: Optional filter by report type ("weekly" or "quarterly")
            
        Returns:
            List of context keys
        """
        try:
            prefix = f"analysis-context-{report_type}-" if report_type else "analysis-context-"
            context_keys = self.cache.list_cache_keys(prefix=prefix)
            
            logger.info(f"Found {len(context_keys)} available contexts with prefix '{prefix}'")
            return context_keys
            
        except Exception as e:
            logger.error(f"Error listing contexts: {e}")
            return []
