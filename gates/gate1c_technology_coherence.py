"""Gate 1C: Technology Coherence

Dynamically validates that technologies mentioned in narrative sections match detected technologies.
Learns from actual Rapid7 scan data - no hardcoded technology list.
Prevents false assumptions like 'WordPress is in our environment' when no WordPress CVEs exist.
"""
import re
from typing import List, Dict, Set, Tuple
from .models import GateInput, GateResult


def _extract_technology_keywords(detected_technologies: Set[str]) -> Set[str]:
    """
    Extract meaningful technology/vendor keywords from detected product names.
    Returns a set of keywords that should be checked in the executive summary.
    """
    keywords = set()
    
    # Common vendor/product patterns to extract
    # E.g., "WordPress Plugin: contact-form-7" -> "wordpress"
    # E.g., "Microsoft Exchange Server 2019" -> "microsoft", "exchange"
    # E.g., "Fortinet FortiOS" -> "fortinet", "fortios"
    
    for tech in detected_technologies:
        # Split on common delimiters and extract meaningful tokens
        tokens = re.findall(r'\b[a-z][a-z0-9\-]+\b', tech.lower())
        
        for token in tokens:
            # Skip common noise words
            noise_words = {
                "plugin", "server", "system", "service", "application", "software",
                "product", "version", "update", "patch", "security", "enterprise",
                "professional", "standard", "edition", "platform", "suite"
            }
            
            # Keep tokens that are meaningful vendor/product names (4+ chars, not noise)
            if len(token) >= 4 and token not in noise_words:
                keywords.add(token)
    
    return keywords


def _extract_product_mentions(text: str, min_word_length: int = 4) -> Set[str]:
    """
    Extract potential product/vendor mentions from narrative text.
    Focuses on capitalized words that might be technology names.
    """
    mentions = set()
    
    # Find capitalized words (likely product/vendor names)
    # Match: "WordPress", "FortiOS", "Exchange Server"
    capitalized_words = re.findall(r'\b[A-Z][a-zA-Z0-9\-]+(?:\s+[A-Z][a-zA-Z0-9\-]+)*\b', text)
    
    for word in capitalized_words:
        # Normalize to lowercase for comparison
        normalized = word.lower()
        
        # Skip common proper nouns that aren't technologies
        skip_words = {
            "the", "this", "that", "these", "those", "cisa", "kev", "cve",
            "rapid7", "intel471", "crowdstrike", "threatq", "osint",
            "january", "february", "march", "april", "may", "june",
            "july", "august", "september", "october", "november", "december",
            "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"
        }
        
        if len(normalized) >= min_word_length and normalized not in skip_words:
            mentions.add(normalized)
    
    return mentions


def run(input: GateInput, llm_client, report_type: str) -> GateResult:
    """
    Dynamically validates that technologies mentioned in the executive summary
    are actually detected in Rapid7 scans. Learns from your actual environment.
    
    Args:
        input: GateInput with report_draft and collected data
        llm_client: LLM client for AI reviews
        report_type: 'weekly' or 'quarterly'
    
    Returns:
        GateResult with PASS/WARN/HALT status
    """
    issues = []
    warnings = []
    
    # Extract ALL technologies from CVE data (learns from Rapid7 scans)
    detected_technologies = set()
    detected_products_full = set()  # Full product names for reference
    cve_analysis = input.report_draft.get("cve_analysis", [])
    
    for cve in cve_analysis:
        affected_product = cve.get("affected_product", "")
        if affected_product and affected_product.lower() not in ("n/a", "unknown", ""):
            detected_products_full.add(affected_product)
            detected_technologies.add(affected_product.lower())
            
            # Extract vendor/product tokens for broader matching
            tokens = re.findall(r'\b[a-z0-9]+(?:[a-z0-9\-]*[a-z0-9])?\b', affected_product.lower())
            for token in tokens:
                if len(token) > 3:  # Ignore very short tokens
                    detected_technologies.add(token)
    
    # Extract meaningful technology keywords from detected technologies
    technology_keywords = _extract_technology_keywords(detected_technologies)
    
    # Extract executive summary text
    exec_summary = input.report_draft.get("executive_summary", "")
    if isinstance(exec_summary, dict):
        exec_summary = exec_summary.get("text", "")
    exec_summary = str(exec_summary)
    
    # Extract technology mentions from the executive summary
    mentioned_products = _extract_product_mentions(exec_summary)
    
    # Check each mentioned product against detected technologies
    for product in mentioned_products:
        # Check if this product appears in any detected technology
        found_in_detected = any(product in tech for tech in detected_technologies)
        
        if not found_in_detected:
            # Check if the mention explicitly states "not detected" or "industry threat"
            context_window = 150  # characters before/after
            pattern = r'.{0,' + str(context_window) + r'}\b' + re.escape(product) + r'\b.{0,' + str(context_window) + r'}'
            match = re.search(pattern, exec_summary, re.IGNORECASE | re.DOTALL)
            
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
                    "if present",
                    "may be affected",
                    "could impact",
                    "external threat",
                    "broader industry"
                ]
                
                has_qualifier = any(phrase in context.lower() for phrase in qualifying_phrases)
                
                if not has_qualifier:
                    issues.append(
                        f"Technology '{product.title()}' mentioned in executive summary but has NO corresponding "
                        f"CVE detections in Rapid7 data. Either remove the mention or add qualifying language like "
                        f"'industry threat to monitor' or 'not currently detected in our environment'."
                    )
    
    # Check if there are CVEs with high exposure but no narrative mentions (informational)
    major_exposures = []
    for cve in cve_analysis:
        exposure_str = str(cve.get("exposure", ""))
        # Try to parse the number of systems
        match = re.search(r'(\d+)\s*system', exposure_str)
        if match:
            count = int(match.group(1))
            if count >= 10:  # Significant exposure threshold
                product = cve.get("affected_product", "")
                # Check if product is mentioned in summary (case insensitive)
                if product and not re.search(r'\b' + re.escape(product) + r'\b', exec_summary, re.IGNORECASE):
                    major_exposures.append(f"{product} ({count} systems)")
    
    if major_exposures and len(major_exposures) <= 3:
        warnings.append(
            f"High-exposure technologies not mentioned in executive summary: {', '.join(major_exposures)}. "
            f"Consider adding context if these are significant risks."
        )
    
    # Build informative details
    detected_sample = sorted(list(detected_products_full))[:15]  # Show up to 15 actual products
    
    # Determine result
    if issues:
        return GateResult(
            gate_number="1C",
            status="HALT",
            message=f"Technology coherence issues: {len(issues)} technology mentions without detection evidence",
            details={
                "issues": issues,
                "warnings": warnings,
                "detected_technologies_sample": detected_sample,
                "total_cve_count": len(cve_analysis),
                "unique_products_detected": len(detected_products_full),
                "mentioned_products": sorted(list(mentioned_products))
            }
        )
    elif warnings:
        return GateResult(
            gate_number="1C",
            status="WARN",
            message=f"Technology coherence validated with {len(warnings)} informational warnings",
            details={
                "warnings": warnings,
                "detected_technologies_sample": detected_sample,
                "total_cve_count": len(cve_analysis),
                "unique_products_detected": len(detected_products_full)
            }
        )
    else:
        return GateResult(
            gate_number="1C",
            status="PASS",
            message=f"Technology coherence validated: All {len(mentioned_products)} narrative mentions match detected technologies",
            details={
                "detected_technologies_sample": detected_sample,
                "total_cve_count": len(cve_analysis),
                "unique_products_detected": len(detected_products_full),
                "mentioned_products": sorted(list(mentioned_products))
            }
        )
