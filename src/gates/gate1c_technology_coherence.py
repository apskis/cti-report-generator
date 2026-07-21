"""Gate 1C: Technology Coherence

Dynamically validates that technologies mentioned in narrative sections match detected technologies.
Learns from the collected CVE data - no hardcoded technology list.
Prevents false assumptions like 'WordPress is in our environment' when no WordPress CVEs exist.
"""

import re

from .models import GateInput, GateResult


def _extract_technology_keywords(detected_technologies: set[str]) -> set[str]:
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
        tokens = re.findall(r"\b[a-z][a-z0-9\-]+\b", tech.lower())

        for token in tokens:
            # Skip common noise words
            noise_words = {
                "plugin",
                "server",
                "system",
                "service",
                "application",
                "software",
                "product",
                "version",
                "update",
                "patch",
                "security",
                "enterprise",
                "professional",
                "standard",
                "edition",
                "platform",
                "suite",
            }

            # Keep tokens that are meaningful vendor/product names (4+ chars, not noise)
            if len(token) >= 4 and token not in noise_words:
                keywords.add(token)

    return keywords


# Narrative-bearing fields to scan for technology mentions. We deliberately exclude
# cve_analysis (the structured detection data itself is the source of truth, not a
# claim to be validated against it).
_NARRATIVE_STRING_FIELDS = ("executive_summary", "key_takeaways", "outlook", "narrative", "conclusion")
_NARRATIVE_LIST_FIELDS = ("recommendations", "apt_activity", "industry_incidents", "geopolitical_threats")
_NARRATIVE_SUBFIELDS = ("summary", "description", "activity", "details", "impact", "relevance", "notable_example")


def _coerce_text(value) -> str:
    """Flatten a report field (str / dict / list of either) to plain narrative text."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(_coerce_text(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_coerce_text(v) for v in value)
    return ""


def _gather_narrative_text(report: dict) -> str:
    """Concatenate the report's free-text narrative across the WHOLE report.

    Gate 1C used to inspect only the executive summary, so a fabricated technology
    mentioned anywhere else (APT write-ups, incident details, recommendations) sailed
    through. This gathers narrative from every prose-bearing section.
    """
    parts: list[str] = []

    for key in _NARRATIVE_STRING_FIELDS:
        parts.append(_coerce_text(report.get(key)))

    for key in _NARRATIVE_LIST_FIELDS:
        for item in report.get(key) or []:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                for sub in _NARRATIVE_SUBFIELDS:
                    if sub in item:
                        parts.append(_coerce_text(item[sub]))

    return "\n".join(p for p in parts if p)


def _mention_tokens(mention: str) -> set[str]:
    """Distinctive lowercase tokens (4+ chars) of a mentioned product/vendor name."""
    return {t for t in re.findall(r"[a-z0-9]{4,}", mention.lower())}


def _extract_product_mentions(text: str, min_word_length: int = 4) -> set[str]:
    """
    Extract potential product/vendor mentions from narrative text.
    Focuses on capitalized words that might be technology names.
    """
    mentions = set()

    # Find capitalized words (likely product/vendor names)
    # Match: "WordPress", "FortiOS", "Exchange Server"
    capitalized_words = re.findall(r"\b[A-Z][a-zA-Z0-9\-]+(?:\s+[A-Z][a-zA-Z0-9\-]+)*\b", text)

    for word in capitalized_words:
        # Normalize to lowercase for comparison
        normalized = word.lower()

        # Skip common proper nouns that aren't technologies
        skip_words = {
            "the",
            "this",
            "that",
            "these",
            "those",
            "cisa",
            "kev",
            "cve",
            "intel471",
            "crowdstrike",
            "osint",
            "january",
            "february",
            "march",
            "april",
            "may",
            "june",
            "july",
            "august",
            "september",
            "october",
            "november",
            "december",
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "saturday",
            "sunday",
        }

        if len(normalized) >= min_word_length and normalized not in skip_words:
            mentions.add(normalized)

    return mentions


def run(input: GateInput, llm_client, report_type: str) -> GateResult:
    """
    Dynamically validates that technologies mentioned in the executive summary
    are actually present in the collected CVE data.

    Runs after Gate 5 to validate the drafted report.

    Args:
        input: GateInput with prior_results containing Gate 5's report draft
        llm_client: LLM client for AI reviews
        report_type: 'weekly' or 'quarterly'

    Returns:
        GateResult with PASS/WARN/HALT status
    """
    issues = []
    warnings = []

    # Get the report draft from Gate 5
    g5 = input.prior_results.get("5")
    if g5 is None:
        raise RuntimeError("Gate 1C requires Gate 5 GateResult in input.prior_results['5']")

    report = g5.payload.get("report", {})

    # Extract ALL technologies from the collected CVE data
    detected_technologies = set()
    detected_products_full = set()  # Full product names for reference
    cve_analysis = report.get("cve_analysis", [])

    for cve in cve_analysis:
        affected_product = cve.get("affected_product", "")
        if affected_product and affected_product.lower() not in ("n/a", "unknown", ""):
            detected_products_full.add(affected_product)
            detected_technologies.add(affected_product.lower())

            # Extract vendor/product tokens for broader matching
            tokens = re.findall(r"\b[a-z0-9]+(?:[a-z0-9\-]*[a-z0-9])?\b", affected_product.lower())
            for token in tokens:
                if len(token) > 3:  # Ignore very short tokens
                    detected_technologies.add(token)

    # Fold vendor/product keywords derived from detected technologies into the token
    # set we match against (previously computed then discarded).
    detected_technologies |= _extract_technology_keywords(detected_technologies)

    # Scan the WHOLE report narrative, not just the executive summary.
    narrative_text = _gather_narrative_text(report)

    # Extract technology mentions from the full narrative
    mentioned_products = _extract_product_mentions(narrative_text)

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
        "broader industry",
    ]

    # Check each mentioned product against detected technologies using TOKENIZED
    # matching (exact token overlap) rather than fuzzy substring, which previously
    # both over-matched (short substrings) and under-matched (normalization drift).
    for product in mentioned_products:
        product_tokens = _mention_tokens(product)
        if not product_tokens:
            continue

        found_in_detected = bool(product_tokens & detected_technologies)

        if not found_in_detected:
            # Check if the mention explicitly states "not detected" / "industry threat".
            context_window = 150  # characters before/after
            pattern = (
                r".{0," + str(context_window) + r"}\b" + re.escape(product) + r"\b.{0," + str(context_window) + r"}"
            )
            match = re.search(pattern, narrative_text, re.IGNORECASE | re.DOTALL)
            context = match.group(0) if match else ""

            has_qualifier = any(phrase in context.lower() for phrase in qualifying_phrases)

            if not has_qualifier:
                issues.append(
                    f"Technology '{product.title()}' mentioned in the report narrative but has NO corresponding "
                    f"CVE detections in the collected data. Either remove the mention or add qualifying language like "
                    f"'industry threat to monitor' or 'not currently detected in our environment'."
                )

    # Check if there are CVEs with high exposure but no narrative mentions (informational)
    major_exposures = []
    for cve in cve_analysis:
        exposure_str = str(cve.get("exposure", ""))
        # Try to parse the number of systems
        match = re.search(r"(\d+)\s*system", exposure_str)
        if match:
            count = int(match.group(1))
            if count >= 10:  # Significant exposure threshold
                product = cve.get("affected_product", "")
                # Check if product is mentioned anywhere in the narrative (case insensitive)
                if product and not re.search(r"\b" + re.escape(product) + r"\b", narrative_text, re.IGNORECASE):
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
        # Return COMPLETE with issues in payload (don't block automated runs)
        # Gate 6 will pick up these issues in adversarial review
        return GateResult(
            gate_id="1C",
            status="COMPLETE",
            payload={
                "validation_status": "issues_found",
                "issues": issues,
                "warnings": warnings,
                "detected_technologies_sample": detected_sample,
                "total_cve_count": len(cve_analysis),
                "unique_products_detected": len(detected_products_full),
                "mentioned_products": sorted(list(mentioned_products)),
                "message": f"⚠️ Technology coherence issues: {len(issues)} technology mentions without detection evidence",
            },
            awaiting_clearance=False,  # Don't block - let it proceed to Gate 6
        )
    elif warnings:
        return GateResult(
            gate_id="1C",
            status="COMPLETE",
            payload={
                "validation_status": "warnings",
                "warnings": warnings,
                "detected_technologies_sample": detected_sample,
                "total_cve_count": len(cve_analysis),
                "unique_products_detected": len(detected_products_full),
                "message": f"✓ Technology coherence validated with {len(warnings)} informational warnings",
            },
            awaiting_clearance=False,
        )
    else:
        return GateResult(
            gate_id="1C",
            status="COMPLETE",
            payload={
                "validation_status": "passed",
                "detected_technologies_sample": detected_sample,
                "total_cve_count": len(cve_analysis),
                "unique_products_detected": len(detected_products_full),
                "mentioned_products": sorted(list(mentioned_products)),
                "message": f"✓ Technology coherence validated: All {len(mentioned_products)} narrative mentions match detected technologies",
            },
            awaiting_clearance=False,
        )
