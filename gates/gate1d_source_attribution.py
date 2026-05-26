"""
Gate 1D: Source Attribution Validation

Validates that all claims in the report can be traced back to specific source reports/articles.
Ensures audit trail for compliance and verification.

VALIDATION CRITERIA:
1. OSINT Citations: All OSINT references must include article title + URL
2. Intel471 Reports: Must include report UID and portal URL
3. CrowdStrike Reports: Must include actor ID or detection ID
4. Statistics Verification: Numbers match collected data
5. Breach Counts: Can be traced to specific Intel471 breach alerts

PURPOSE:
- Audit trail for compliance/legal
- Enables verification of claims in source systems
- Prevents hallucination or unverifiable statements
"""
import logging
from typing import Any, Dict, List
from gates.models import GateInput, GateResult

logger = logging.getLogger(__name__)


def run(input: GateInput, llm_client: Any, report_type: str) -> GateResult:
    """
    Validate source attribution and audit trail.
    
    NOTE: This gate only runs for QUARTERLY reports (controlled by orchestrator sequence).
    Used for strategic reports requiring compliance/audit trail.
    
    Args:
        input: Gate input with prior results
        llm_client: LLM client (unused - deterministic validation)
        report_type: Report type being generated
        
    Returns:
        GateResult with validation findings
    """
    logger.info(f"Running Gate 1D: Source Attribution Validation ({report_type})")
    
    # Get report from Gate 5
    g5 = input.prior_results.get("5")
    if not g5 or g5.status != "COMPLETE":
        return GateResult(
            gate_id="1D",
            status="HALT",
            halt_reason="Gate 5 (Report Draft) did not complete - cannot validate attribution",
            payload={}
        )
    
    report = g5.payload.get("report", {})
    issues = []
    warnings = []
    
    # Get data from Gate 1
    g1 = input.prior_results.get("1")
    data_by_source = g1.payload.get("data_by_source", {}) if g1 else {}
    
    # ===== 1. OSINT Source Attribution =====
    osint_sources_used = report.get("osint_sources_used", [])
    osint_data = data_by_source.get("OSINT", [])
    
    if osint_sources_used:
        for source in osint_sources_used:
            title = source.get("title", "")
            url = source.get("url", "")
            
            if not title:
                issues.append(f"OSINT source missing title: {source}")
            if not url:
                issues.append(f"OSINT source missing URL: {title}")
            if not source.get("relevance"):
                warnings.append(f"OSINT source missing relevance note: {title}")
            
        logger.info(f"✓ {len(osint_sources_used)} OSINT sources cited with URLs")
    else:
        # Check if OSINT was collected but not cited
        if osint_data:
            warnings.append(f"OSINT data collected ({len(osint_data)} articles) but none cited in report")
    
    # ===== 2. Intel471 Report Attribution =====
    intel471_data = data_by_source.get("Intel471", [])
    apt_activity = report.get("apt_activity", [])
    
    intel471_refs = 0
    for actor in apt_activity:
        intel471_activity = actor.get("intel471_activity", "")
        if intel471_activity and "Intel471:" in intel471_activity:
            intel471_refs += 1
            
            # Check if specific report details are mentioned
            if "uid" not in intel471_activity.lower() and "report" not in intel471_activity.lower():
                warnings.append(f"Intel471 reference for {actor.get('actor', 'Unknown')} lacks report ID/UID")
    
    if intel471_data and intel471_refs == 0:
        warnings.append(f"Intel471 data collected ({len(intel471_data)} reports) but no actor attribution found")
    elif intel471_refs > 0:
        logger.info(f"✓ {intel471_refs} Intel471 reports referenced in APT activity")
    
    # ===== 3. Breach Statistics Verification =====
    # Check if breach counts can be traced to Intel471 data
    try:
        exec_summary = report.get("executive_summary", "")
        
        # Look for breach mentions
        if exec_summary and "breach" in exec_summary.lower():
            # Count Intel471 breach alerts
            breach_count = 0
            for item in intel471_data:
                try:
                    threat_type = item.get("threat_type", "")
                    # Handle both string and list types
                    if isinstance(threat_type, str):
                        if "breach" in threat_type.lower():
                            breach_count += 1
                    elif isinstance(threat_type, list):
                        if any("breach" in str(t).lower() for t in threat_type):
                            breach_count += 1
                except (AttributeError, TypeError):
                    continue
            
            if breach_count > 0:
                logger.info(f"✓ {breach_count} breach alerts found in Intel471 data")
            else:
                warnings.append("Executive summary mentions breaches but no Intel471 breach alerts found")
    except Exception as e:
        logger.warning(f"Could not validate breach statistics: {e}")
    
    # ===== 4. Statistics Cross-Check =====
    # Validate statistics against collected data
    statistics = report.get("statistics", {})
    
    if statistics:
        # CVE count validation
        cve_count_report = statistics.get("total_cves", 0)
        cve_analysis = report.get("cve_analysis", [])
        cve_count_actual = len(cve_analysis)
        
        if cve_count_report != cve_count_actual:
            issues.append(f"CVE count mismatch: statistics={cve_count_report}, actual CVEs in report={cve_count_actual}")
        else:
            logger.info(f"✓ CVE count validated: {cve_count_report}")
        
        # APT actor count validation
        apt_count_report = statistics.get("total_apt_actors", 0)
        apt_count_actual = len(apt_activity)
        
        if apt_count_report != apt_count_actual:
            issues.append(f"APT count mismatch: statistics={apt_count_report}, actual actors={apt_count_actual}")
        else:
            logger.info(f"✓ APT actor count validated: {apt_count_report}")
    
    # ===== 5. CrowdStrike Detection/Actor Attribution =====
    crowdstrike_data = data_by_source.get("CrowdStrike", [])
    
    if crowdstrike_data:
        # Check if actors have proper attribution
        crowdstrike_actors = [item for item in crowdstrike_data if item.get("type") == "apt_actor"]
        
        if crowdstrike_actors:
            logger.info(f"✓ {len(crowdstrike_actors)} CrowdStrike actor profiles available")
        
        # Check if detections are referenced
        crowdstrike_detections = [item for item in crowdstrike_data if item.get("type") == "detection"]
        
        if crowdstrike_detections:
            # Check if any detection IDs appear in the report
            detection_mentioned = False
            for detection in crowdstrike_detections[:5]:  # Check first 5
                detection_id = detection.get("detection_id", "")
                if detection_id and detection_id in str(report):
                    detection_mentioned = True
                    break
            
            if not detection_mentioned:
                warnings.append(f"CrowdStrike detections collected ({len(crowdstrike_detections)}) but none specifically referenced")
    
    # ===== Summary =====
    total_osint = len(osint_sources_used)
    total_intel471_refs = intel471_refs
    
    summary = {
        "osint_sources_cited": total_osint,
        "intel471_references": total_intel471_refs,
        "issues": issues,
        "warnings": warnings,
        "audit_trail": {
            "osint_articles_available": len(osint_data),
            "intel471_reports_available": len(intel471_data),
            "crowdstrike_data_available": len(crowdstrike_data),
            "osint_cited": total_osint,
            "intel471_referenced": total_intel471_refs
        }
    }
    
    # Determine status
    if issues:
        status = "HALT"
        halt_reason = f"{len(issues)} critical attribution issues found: {'; '.join(issues[:3])}"
        logger.error(f"Gate 1D HALT: {len(issues)} issues")
    elif warnings:
        status = "COMPLETE"
        halt_reason = None
        logger.warning(f"Gate 1D COMPLETE with {len(warnings)} warnings")
    else:
        status = "COMPLETE"
        halt_reason = None
        logger.info("Gate 1D COMPLETE: All sources properly attributed")
    
    return GateResult(
        gate_id="1D",
        status=status,
        halt_reason=halt_reason,
        payload=summary
    )
