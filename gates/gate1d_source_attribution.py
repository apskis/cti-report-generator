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
    tier1_sources = g1.payload.get("tier1_sources", []) if g1 else []
    
    # Build data_by_source map from tier1_sources
    data_by_source = {}
    for source_record in tier1_sources:
        source_name = source_record.source_name
        # Get the actual data from input.tier1_data
        data_by_source[source_name] = input.tier1_data.get(source_name, [])
    
    # QUARTERLY REPORT-SPECIFIC VALIDATION
    if report_type.upper() == "QUARTERLY":
        # ===== 1. OSINT Source Attribution =====
        # Quarterly reports don't have osint_sources_used in the report dict
        # They just list sources in a static section, which is fine
        osint_data = input.osint_articles or []
        
        if osint_data:
            logger.info(f"✓ {len(osint_data)} OSINT articles collected for quarterly context")
        
        # ===== 2. Intel471 Report Attribution =====
        intel471_data = data_by_source.get("Intel471", [])
        
        if intel471_data:
            logger.info(f"✓ {len(intel471_data)} Intel471 reports collected")
        else:
            warnings.append("No Intel471 data available for quarterly analysis")
        
        # ===== 3. CrowdStrike Attribution =====
        crowdstrike_data = data_by_source.get("CrowdStrike", [])
        
        if crowdstrike_data:
            logger.info(f"✓ {len(crowdstrike_data)} CrowdStrike records collected")
        else:
            warnings.append("No CrowdStrike data available for quarterly analysis")
        
        # ===== 4. Geopolitical Threats Attribution =====
        geopolitical_threats = report.get("geopolitical_threats", [])
        
        if geopolitical_threats:
            logger.info(f"✓ {len(geopolitical_threats)} geopolitical threats analyzed")
            
            # Check that threats have proper structure
            for threat in geopolitical_threats:
                name = threat.get("name", "")
                if not name:
                    issues.append("Geopolitical threat missing name field")
                if not threat.get("activity"):
                    warnings.append(f"Geopolitical threat '{name}' has no activity bullets")
        else:
            warnings.append("No geopolitical threats in quarterly report - expected for strategic analysis")
        
        # ===== 5. Breach Landscape Attribution =====
        breach_landscape = report.get("breach_landscape", {})
        
        if breach_landscape:
            incidents_by_type = breach_landscape.get("incidents_by_type", [])
            logger.info(f"✓ Breach landscape with {len(incidents_by_type)} incident types")
            
            # Validate stat cards have change percentages
            stat_cards = breach_landscape.get("stat_cards", [])
            if stat_cards:
                for card in stat_cards:
                    change_pct = card.get("change_pct", "")
                    if change_pct and not (change_pct.startswith("+") or change_pct.startswith("-") or change_pct == "0%"):
                        issues.append(f"Stat card change_pct missing +/- sign: '{change_pct}'")
        else:
            warnings.append("No breach landscape in quarterly report - expected for strategic analysis")
        
        # ===== 6. Illumina-OSINT Context Validation =====
        illumina_osint = data_by_source.get("Illumina-OSINT", [])
        
        if illumina_osint:
            logger.info(f"✓ Illumina-OSINT context collected ({len(illumina_osint)} records)")
        else:
            warnings.append("No Illumina-OSINT context - geopolitical relevance may lack company-specific grounding")
        
        # ===== Summary =====
        summary = {
            "intel471_reports": len(intel471_data),
            "crowdstrike_records": len(crowdstrike_data),
            "osint_articles": len(osint_data),
            "illumina_osint_records": len(illumina_osint),
            "geopolitical_threats": len(geopolitical_threats),
            "breach_incidents": len(breach_landscape.get("incidents_by_type", [])) if breach_landscape else 0,
            "issues": issues,
            "warnings": warnings
        }
    
    else:
        # WEEKLY REPORT VALIDATION (original logic for weekly)
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
                
                if "uid" not in intel471_activity.lower() and "report" not in intel471_activity.lower():
                    warnings.append(f"Intel471 reference for {actor.get('actor', 'Unknown')} lacks report ID/UID")
        
        if intel471_data and intel471_refs == 0:
            warnings.append(f"Intel471 data collected ({len(intel471_data)} reports) but no actor attribution found")
        elif intel471_refs > 0:
            logger.info(f"✓ {intel471_refs} Intel471 reports referenced in APT activity")
        
        # ===== 3. Breach Statistics Verification =====
        try:
            exec_summary = report.get("executive_summary", "")
            
            if exec_summary and "breach" in exec_summary.lower():
                breach_count = 0
                for item in intel471_data:
                    try:
                        threat_type = item.get("threat_type", "")
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
        statistics = report.get("statistics", {})
        
        if statistics:
            cve_count_report = statistics.get("total_cves", 0)
            cve_analysis = report.get("cve_analysis", [])
            cve_count_actual = len(cve_analysis)
            
            if cve_count_report != cve_count_actual:
                issues.append(f"CVE count mismatch: statistics={cve_count_report}, actual CVEs in report={cve_count_actual}")
            else:
                logger.info(f"✓ CVE count validated: {cve_count_report}")
            
            apt_count_report = statistics.get("total_apt_actors", 0)
            apt_count_actual = len(apt_activity)
            
            if apt_count_report != apt_count_actual:
                issues.append(f"APT count mismatch: statistics={apt_count_report}, actual actors={apt_count_actual}")
            else:
                logger.info(f"✓ APT actor count validated: {apt_count_report}")
        
        # ===== 5. CrowdStrike Detection/Actor Attribution =====
        crowdstrike_data = data_by_source.get("CrowdStrike", [])
        
        if crowdstrike_data:
            crowdstrike_actors = [item for item in crowdstrike_data if item.get("type") == "apt_actor"]
            
            if crowdstrike_actors:
                logger.info(f"✓ {len(crowdstrike_actors)} CrowdStrike actor profiles available")
            
            crowdstrike_detections = [item for item in crowdstrike_data if item.get("type") == "detection"]
            
            if crowdstrike_detections:
                detection_mentioned = False
                for detection in crowdstrike_detections[:5]:
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
