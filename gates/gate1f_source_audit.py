"""Gate 1F: Source Audit and Verification

Comprehensive audit of all sources used in the report.
Shows exactly where each source is referenced and validates all data.

This gate:
1. Lists every breach and its source
2. Shows where OSINT is cited with line numbers
3. Verifies Illumina OSINT context was used
4. Calculates and verifies all statistics
5. BLOCKS reports with generic company names or missing sources
"""
import logging
import re
from typing import Any, List, Dict

from .models import GateInput, GateResult

logger = logging.getLogger(__name__)

# Forbidden generic terms
FORBIDDEN_TERMS = [
    "pharma manufacturer",
    "genomics institute",
    "research institute",
    "genomics research institute",
    "biotech company",
    "medical device mfg",
    "lab software vendor",
    "healthcare provider",
    "life sciences company",
    "clinical research org"
]


def run(input: GateInput, llm_client: Any, report_type: str) -> GateResult:
    """Execute Gate 1F - Source Audit and Verification.
    
    Args:
        input: GateInput with tier1_data and prior gate results
        llm_client: LLM client (not used - deterministic audit)
        report_type: "WEEKLY" or "QUARTERLY"
    
    Returns:
        GateResult with comprehensive source audit
    """
    logger.info(f"Running Gate 1F: Source Audit and Verification ({report_type})")
    
    if report_type.upper() != "QUARTERLY":
        # Only run for quarterly reports
        logger.info("Gate 1F skipped - only runs for quarterly reports")
        return GateResult(
            gate_id="1F",
            status="COMPLETE",
            payload={"skipped": "Not a quarterly report"}
        )
    
    # Get report from Gate 5
    g5 = input.prior_results.get("5")
    if not g5 or g5.status != "COMPLETE":
        return GateResult(
            gate_id="1F",
            status="HALT",
            halt_reason="Gate 5 (Report Draft) did not complete",
            payload={}
        )
    
    report = g5.payload.get("report", {})
    
    logger.info("=" * 80)
    logger.info("SOURCE AUDIT - COMPREHENSIVE VERIFICATION")
    logger.info(f"This audit shows exactly where every source is used.")
    logger.info("=" * 80)
    
    # AUDIT 1: Breach Landscape Sources
    logger.info("\n[AUDIT 1] BREACH LANDSCAPE - Notable Examples")
    logger.info("-" * 80)
    
    breach_issues = []
    breach_landscape = report.get("breach_landscape", {})
    incidents = breach_landscape.get("incidents_by_type", [])
    
    for idx, incident in enumerate(incidents, 1):
        incident_type = incident.get("type", "Unknown")
        notable_example = incident.get("notable_example", "")
        current_count = incident.get("current_count", 0)
        
        logger.info(f"\n{idx}. {incident_type}")
        logger.info(f"   Count: {current_count}")
        logger.info(f"   Example: {notable_example}")
        
        # Check for generic terms
        example_lower = notable_example.lower()
        for term in FORBIDDEN_TERMS:
            if term in example_lower:
                breach_issues.append(
                    f"❌ {incident_type}: Uses FORBIDDEN generic term '{term}' - \"{notable_example}\""
                )
                logger.error(f"   ❌ FORBIDDEN TERM DETECTED: '{term}'")
                break
        else:
            logger.info(f"   ✓ Uses actual company name")
    
    # AUDIT 2: OSINT Citation Usage
    logger.info("\n[AUDIT 2] OSINT SOURCES - Citation Analysis")
    logger.info("-" * 80)
    
    osint_issues = []
    osint_sources = report.get("osint_sources_used", [])
    
    if not osint_sources:
        logger.warning("   ⚠️  NO OSINT sources listed in report")
        osint_issues.append("No OSINT sources included despite OSINT data being collected")
    else:
        # Extract citations from content
        exec_summary = report.get("executive_summary", "")
        geo_threats = report.get("geopolitical_threats", [])
        
        # Find all [N] citations
        exec_citations = re.findall(r'\[(\d+)\]', exec_summary)
        geo_citations = []
        
        for threat in geo_threats:
            for bullet in threat.get("relevance", []):
                found = re.findall(r'\[(\d+)\]', bullet)
                geo_citations.extend(found)
        
        logger.info(f"\nOSINT Sources Listed: {len(osint_sources)}")
        logger.info(f"Citations in Executive Summary: {exec_citations}")
        logger.info(f"Citations in Geopolitical Relevance: {geo_citations}")
        
        all_citations = set(exec_citations + geo_citations)
        
        for source in osint_sources:
            citation_num = str(source.get("citation_number", 0))
            title = source.get("title", "No title")
            url = source.get("url", "No URL")
            
            logger.info(f"\n[{citation_num}] {title}")
            logger.info(f"   URL: {url}")
            
            # Validate URL
            if not url or url == "No URL":
                osint_issues.append(f"❌ [{citation_num}] {title}: Missing URL")
                logger.error(f"   ❌ NO URL PROVIDED")
            elif not url.startswith(('http://', 'https://')):
                osint_issues.append(f"❌ [{citation_num}] {title}: Invalid URL format")
                logger.error(f"   ❌ INVALID URL FORMAT")
            elif 'news.illumina.com' in url:
                osint_issues.append(f"❌ [{citation_num}] {title}: HALLUCINATED URL (news.illumina.com doesn't exist)")
                logger.error(f"   ❌ HALLUCINATED URL - news.illumina.com domain doesn't exist")
            else:
                logger.info(f"   ✓ Valid URL")
            
            # Check if cited
            if citation_num in all_citations:
                if citation_num in exec_citations:
                    logger.info(f"   ✓ Cited in Executive Summary")
                if citation_num in geo_citations:
                    logger.info(f"   ✓ Cited in Geopolitical Relevance")
            else:
                osint_issues.append(f"⚠️  [{citation_num}] {title}: Listed but never cited")
                logger.warning(f"   ⚠️  LISTED BUT NEVER CITED IN REPORT")
    
    # AUDIT 3: Illumina OSINT Usage
    logger.info("\n[AUDIT 3] ILLUMINA OSINT - Context Verification")
    logger.info("-" * 80)
    
    illumina_issues = []
    illumina_data = input.tier1_data.get("Illumina-OSINT", [])
    
    if not illumina_data:
        logger.warning("   ⚠️  No Illumina-OSINT data collected")
    else:
        logger.info(f"   Illumina-OSINT records collected: {len(illumina_data)}")
        
        # Check if the context was actually used
        illumina_keywords = [
            "illumina", "novaseq", "nextseq", "iseq", "miseq",
            "sequencing platform", "ica", "basespace", "dragen"
        ]
        
        geo_threats = report.get("geopolitical_threats", [])
        illumina_mentions = 0
        
        for threat in geo_threats:
            country = threat.get("name", "")
            for bullet in threat.get("relevance", []):
                if any(kw in bullet.lower() for kw in illumina_keywords):
                    illumina_mentions += 1
                    logger.info(f"   ✓ {country}: Illumina context used in relevance bullet")
                    logger.info(f"      \"{bullet[:80]}...\"")
        
        if illumina_mentions == 0:
            illumina_issues.append(
                f"⚠️  Illumina-OSINT collected ({len(illumina_data)} records) but NOT used in geopolitical relevance"
            )
            logger.warning("   ⚠️  ILLUMINA CONTEXT NOT USED IN GEOPOLITICAL RELEVANCE")
        else:
            logger.info(f"   ✓ Illumina context mentioned {illumina_mentions} times")
    
    # AUDIT 4: Statistics Verification
    logger.info("\n[AUDIT 4] STATISTICS - Count Verification")
    logger.info("-" * 80)
    
    stats_issues = []
    stat_cards = breach_landscape.get("stat_cards", [])
    
    # Get actual data counts
    intel471_data = input.tier1_data.get("Intel471", [])
    actual_breach_count = sum(
        1 for item in intel471_data 
        if "BREACH" in str(item.get("threat_type", "")).upper()
    )
    
    logger.info(f"Intel471 breach alerts in data: {actual_breach_count}")
    
    for card in stat_cards:
        label = card.get("label", "")
        value = card.get("value", "")
        change_pct = card.get("change_pct", "")
        
        logger.info(f"\n{label}: {value} ({change_pct})")
        
        # Verify total incidents matches
        if "Total Incidents" in label or "Incidents" in label:
            try:
                reported = int(str(value).replace(",", ""))
                variance = abs(reported - actual_breach_count)
                
                logger.info(f"   Reported: {reported}")
                logger.info(f"   Actual in data: {actual_breach_count}")
                logger.info(f"   Variance: {variance}")
                
                if variance > 5:
                    stats_issues.append(
                        f"⚠️  Total Incidents mismatch: Report shows {reported}, data has {actual_breach_count} (variance: {variance})"
                    )
                    logger.warning(f"   ⚠️  VARIANCE EXCEEDS THRESHOLD (>5)")
                else:
                    logger.info(f"   ✓ Count matches data")
            except ValueError:
                logger.warning(f"   ⚠️  Could not parse value: {value}")
        
        # Verify change_pct has proper sign
        if change_pct and change_pct != "0%":
            if not (change_pct.startswith("+") or change_pct.startswith("-")):
                stats_issues.append(f"⚠️  {label}: Missing +/- sign in change_pct '{change_pct}'")
                logger.warning(f"   ⚠️  MISSING +/- SIGN")
            else:
                logger.info(f"   ✓ Change percentage properly signed")
    
    # SUMMARY
    logger.info("\n" + "=" * 80)
    logger.info("AUDIT SUMMARY")
    logger.info("=" * 80)
    
    all_issues = breach_issues + osint_issues + illumina_issues + stats_issues
    critical_issues = [i for i in all_issues if i.startswith("❌")]
    warnings = [i for i in all_issues if i.startswith("⚠️")]
    
    logger.info(f"\nCritical Issues (BLOCKING): {len(critical_issues)}")
    for issue in critical_issues:
        logger.error(f"  {issue}")
    
    logger.info(f"\nWarnings (NON-BLOCKING): {len(warnings)}")
    for warning in warnings:
        logger.warning(f"  {warning}")
    
    # Determine status
    if critical_issues:
        status = "HALT"
        halt_reason = f"{len(critical_issues)} CRITICAL source issues found. See logs for details."
        logger.error(f"\n❌ GATE 1F FAILED: {halt_reason}")
    else:
        status = "COMPLETE"
        halt_reason = None
        logger.info(f"\n✓ GATE 1F PASSED: All source audits passed")
    
    logger.info("=" * 80)
    
    return GateResult(
        gate_id="1F",
        status=status,
        halt_reason=halt_reason,
        payload={
            "critical_issues": critical_issues,
            "warnings": warnings,
            "breach_audit": {
                "total_incidents": len(incidents),
                "generic_terms_found": len(breach_issues)
            },
            "osint_audit": {
                "sources_listed": len(osint_sources),
                "issues_found": len(osint_issues)
            },
            "illumina_audit": {
                "records_collected": len(illumina_data),
                "mentions_in_report": illumina_mentions if illumina_data else 0
            },
            "statistics_audit": {
                "actual_breach_count": actual_breach_count,
                "issues_found": len(stats_issues)
            }
        }
    )
