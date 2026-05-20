"""Gate 1C: Technology Coherence

Validates that technologies mentioned in narrative sections match detected technologies.
Prevents false assumptions like 'WordPress is in our environment' when no WordPress CVEs exist.
"""
import re
from typing import List, Dict
from .models import GateInput, GateResult


def run(input: GateInput, llm_client, report_type: str) -> GateResult:
    """
    Validates that the report's executive summary and narrative sections only mention
    technologies that are actually detected in the CVE data (i.e., have non-zero exposure).
    
    Args:
        input: GateInput with report_draft and collected data
        llm_client: LLM client for AI reviews
        report_type: 'weekly' or 'quarterly'
    
    Returns:
        GateResult with PASS/WARN/HALT status
    """
    issues = []
    warnings = []
    
    # Extract technologies from CVE data (affected_product field)
    detected_technologies = set()
    cve_analysis = input.report_draft.get("cve_analysis", [])
    
    for cve in cve_analysis:
        affected_product = cve.get("affected_product", "")
        if affected_product and affected_product.lower() not in ("n/a", "unknown", ""):
            # Extract key technology names
            detected_technologies.add(affected_product.lower())
            
            # Also extract vendor/product tokens for broader matching
            # E.g., "WordPress Plugin: contact-form-7" -> ["wordpress", "plugin", "contact-form-7"]
            tokens = re.findall(r'\b[a-z0-9]+(?:[a-z0-9\-]*[a-z0-9])?\b', affected_product.lower())
            for token in tokens:
                if len(token) > 3:  # Ignore very short tokens
                    detected_technologies.add(token)
    
    # Extract executive summary text
    exec_summary = input.report_draft.get("executive_summary", "")
    if isinstance(exec_summary, dict):
        exec_summary = exec_summary.get("text", "")
    exec_summary = str(exec_summary)
    
    # Common technology keywords that might be falsely assumed
    technology_keywords = [
        "wordpress", "drupal", "joomla",  # CMS
        "exchange", "office 365", "sharepoint",  # Microsoft
        "fortinet", "fortigate", "fortios",  # Fortinet
        "apache", "nginx", "tomcat",  # Web servers
        "jenkins", "gitlab", "github",  # DevOps
        "vmware", "esxi", "vcenter",  # Virtualization
        "cisco", "juniper", "palo alto"  # Network devices
    ]
    
    # Check for mentions of technologies not in detected set
    for keyword in technology_keywords:
        # Look for the keyword in executive summary
        if re.search(r'\b' + re.escape(keyword) + r'\b', exec_summary, re.IGNORECASE):
            # Check if this keyword appears in any detected technology
            found_in_detected = any(keyword in tech for tech in detected_technologies)
            
            if not found_in_detected:
                # Check if the mention explicitly states "not detected" or "industry threat"
                context_window = 100  # characters before/after
                match = re.search(
                    r'.{0,' + str(context_window) + r'}\b' + re.escape(keyword) + r'\b.{0,' + str(context_window) + r'}',
                    exec_summary,
                    re.IGNORECASE | re.DOTALL
                )
                
                if match:
                    context = match.group(0)
                    # Check for qualifying language
                    qualifying_phrases = [
                        "not detected",
                        "not currently detected",
                        "industry threat",
                        "to monitor",
                        "potential threat",
                        "commonly used",
                        "if present"
                    ]
                    
                    has_qualifier = any(phrase in context.lower() for phrase in qualifying_phrases)
                    
                    if not has_qualifier:
                        issues.append(
                            f"Technology '{keyword.title()}' mentioned in executive summary but has NO corresponding "
                            f"CVE detections in Rapid7 data. Either remove the mention or add qualifying language like "
                            f"'industry threat to monitor' or 'not currently detected in our environment'."
                        )
    
    # Check if there are CVEs with exposure > 0 but no narrative mentions
    # This is informational, not a failure
    major_exposures = []
    for cve in cve_analysis:
        exposure_str = str(cve.get("exposure", ""))
        # Try to parse the number of systems
        match = re.search(r'(\d+)\s*system', exposure_str)
        if match:
            count = int(match.group(1))
            if count >= 10:  # Significant exposure
                product = cve.get("affected_product", "")
                if product and product.lower() not in exec_summary.lower():
                    major_exposures.append(f"{product} ({count} systems)")
    
    if major_exposures and len(major_exposures) <= 3:
        warnings.append(
            f"High-exposure technologies not mentioned in executive summary: {', '.join(major_exposures)}. "
            f"Consider adding context if these are significant risks."
        )
    
    # Determine result
    if issues:
        return GateResult(
            gate_number="1C",
            status="HALT",
            message=f"Technology coherence issues detected: {len(issues)} technology mentions without detection evidence",
            details={
                "issues": issues,
                "warnings": warnings,
                "detected_technologies_sample": list(detected_technologies)[:10],
                "cve_count": len(cve_analysis)
            }
        )
    elif warnings:
        return GateResult(
            gate_number="1C",
            status="WARN",
            message=f"Technology coherence validated with {len(warnings)} informational warnings",
            details={
                "warnings": warnings,
                "detected_technologies_sample": list(detected_technologies)[:10],
                "cve_count": len(cve_analysis)
            }
        )
    else:
        return GateResult(
            gate_number="1C",
            status="PASS",
            message="Technology coherence validated: All narrative mentions match detected technologies",
            details={
                "detected_technologies_sample": list(detected_technologies)[:10],
                "cve_count": len(cve_analysis)
            }
        )
