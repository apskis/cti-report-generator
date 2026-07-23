"""Gate 1E: AI Output Quality Validation

Validates the quality and accuracy of AI-generated quarterly report content.
Runs after Gate 5 (Report Draft) but before Gate 6 (Adversarial Review).

This gate catches AI quality issues that the adversarial review doesn't address:
- Generic company names vs actual organizations
- Missing or incorrect citations
- Risk ratings not matching stated criteria
- Trend indicators not aligned with statistics
"""

import logging
import re
from typing import Any

from src.core.config import customer_profile

from .models import GateInput, GateResult

logger = logging.getLogger(__name__)

# Forbidden generic terms for company names
FORBIDDEN_GENERIC_TERMS = [
    "pharma manufacturer",
    "genomics institute",
    "research institute",
    "genomics research institute",
    "biotech company",
    "medical device mfg",
    "lab software vendor",
    "healthcare provider",
    "life sciences company",
    "clinical research org",
]


def _validate_company_names(report: dict) -> list[str]:
    """Validate breach examples use actual company names, not generic terms."""
    issues = []

    breach_landscape = report.get("breach_landscape", {})
    incidents = breach_landscape.get("incidents_by_type", [])

    for incident in incidents:
        example = incident.get("notable_example", "").lower()
        incident_type = incident.get("type", "Unknown")

        for term in FORBIDDEN_GENERIC_TERMS:
            if term in example:
                issues.append(
                    f"{incident_type} uses generic term '{term}' instead of actual company name: {incident.get('notable_example')}"
                )
                break

    if issues:
        logger.warning(f"Found {len(issues)} generic company name issues")

    return issues


def _validate_osint_citations(report: dict) -> list[str]:
    """Validate OSINT sources are actually cited in report content and URLs are valid."""
    issues = []

    osint_sources = report.get("osint_sources_used", [])
    if not osint_sources:
        return issues  # No sources to validate

    # Extract all citation numbers from report
    exec_summary = report.get("executive_summary", "")
    geo_threats = report.get("geopolitical_threats", [])

    # Find all [N] citations
    citations_found = re.findall(r"\[(\d+)\]", exec_summary)

    for threat in geo_threats:
        for bullet in threat.get("relevance", []):
            citations_found.extend(re.findall(r"\[(\d+)\]", bullet))

    citations_found = set(citations_found)

    # Check each source is cited AND has a valid URL
    uncited_sources = []
    invalid_urls = []

    for source in osint_sources:
        citation_num = str(source.get("citation_number", 0))
        url = source.get("url", "")
        title = source.get("title", "Unknown")

        # Check if cited
        if citation_num not in citations_found:
            uncited_sources.append(title)

        # Check if URL is provided and looks valid
        if not url:
            invalid_urls.append(f"{title}: No URL provided")
        elif not url.startswith(("http://", "https://")):
            invalid_urls.append(f"{title}: Invalid URL format '{url}'")
        elif "news.illumina.com" in url:
            # Special check: news.illumina.com doesn't exist - likely hallucinated
            invalid_urls.append(
                f"{title}: URL uses non-existent domain 'news.illumina.com' (actual domain is www.illumina.com)"
            )

    if uncited_sources:
        issues.append(f"{len(uncited_sources)} OSINT sources listed but never cited: {', '.join(uncited_sources[:3])}")
        logger.warning(f"Uncited OSINT sources: {uncited_sources}")

    if invalid_urls:
        issues.append(
            f"{len(invalid_urls)} OSINT sources have invalid/hallucinated URLs: {'; '.join(invalid_urls[:2])}"
        )
        logger.error(f"Invalid OSINT URLs detected: {invalid_urls}")

    return issues


def _validate_illumina_context_usage(gate_input: GateInput, report: dict) -> list[str]:
    """Validate the company-OSINT context was used in geopolitical relevance bullets."""
    warnings = []

    # Check if company-OSINT data exists
    company_data = gate_input.tier1_data.get(customer_profile.osint_source_name, [])
    if not company_data:
        return warnings  # No company context to validate

    # Check if geopolitical threats reference the company's products/platforms
    geo_threats = report.get("geopolitical_threats", [])

    company_keywords = customer_profile.product_keywords

    company_mentions = 0
    for threat in geo_threats:
        for bullet in threat.get("relevance", []):
            if any(keyword in bullet.lower() for keyword in company_keywords):
                company_mentions += 1
                break

    if company_mentions == 0:
        warnings.append(
            f"{customer_profile.osint_source_name} context provided ({len(company_data)} records) but no "
            f"{customer_profile.name}-specific products or platforms mentioned in geopolitical relevance bullets"
        )
        logger.warning("Illumina context not used in geopolitical relevance")

    return warnings


def _validate_executive_summary_completeness(report: dict) -> list[str]:
    """Validate the executive summary is present and covers the required topics.

    The strategic prompt intentionally caps the summary at a concise ~3 sentences in a
    single paragraph (see the "HARD LIMITS" section), so paragraph count is no longer a
    completeness signal — we only flag an empty summary here and rely on topic coverage.
    """
    warnings = []

    exec_summary = report.get("executive_summary", "")
    if not exec_summary:
        warnings.append("Executive summary is empty")
        return warnings

    # Check if key topics are covered
    required_topics = {
        "threat landscape": ["breach", "threat", "incident", "attack"],
        "geopolitical": ["china", "russia", "nation-state", "geopolitical", "apt"],
        "impact": ["impact", "cost", "disruption", "recovery"],
    }

    missing_topics = []
    for topic, keywords in required_topics.items():
        if not any(kw in exec_summary.lower() for kw in keywords):
            missing_topics.append(topic)

    if missing_topics:
        warnings.append(f"Executive summary may be missing coverage of: {', '.join(missing_topics)}")

    return warnings


def _validate_geopolitical_threat_levels(report: dict, crowdstrike_data: list) -> list[str]:
    """Validate geopolitical threat levels match stated criteria."""
    issues = []

    geo_threats = report.get("geopolitical_threats", [])

    for threat in geo_threats:
        country = threat.get("name", "Unknown")
        threat_level = threat.get("level", "")

        # Count actor groups for this country from CrowdStrike data
        country_actors = [
            actor for actor in crowdstrike_data if country.lower() in str(actor.get("origins", [])).lower()
        ]

        actor_count = len(country_actors)

        # Validate against criteria (from prompt):
        # HIGH: 5+ actor groups OR confirmed intrusions OR systematic IP theft
        # MEDIUM: 2-4 actor groups OR opportunistic targeting
        # LOW: ≤1 actor group OR minimal activity

        if threat_level == "HIGH":
            # Check for HIGH justification beyond just actor count
            activity_bullets = threat.get("activity", [])

            # Look for HIGH indicators in activity bullets
            high_indicators = [
                "intrusion",
                "intrusions",
                "breached",
                "compromised",
                "ip theft",
                "espionage",
                "systematic",
                "campaign",
                "targeting",
                "conducted",
                "multiple",
            ]

            has_high_activity = any(
                any(indicator in str(bullet).lower() for indicator in high_indicators) for bullet in activity_bullets
            )

            # Only flag as issue if:
            # - Low actor count (<2) AND
            # - No HIGH activity indicators AND
            # - No specific intrusion/campaign language
            if actor_count < 2 and not has_high_activity:
                issues.append(
                    f"{country} rated HIGH but only {actor_count} actor groups observed "
                    f"and no confirmed intrusions/campaigns in activity bullets "
                    f"(criteria requires 5+ actor groups OR confirmed intrusions for HIGH)"
                )

        elif threat_level == "LOW" and actor_count >= 4:
            issues.append(
                f"{country} rated LOW but {actor_count} actor groups observed (criteria: LOW = ≤1 actor group)"
            )

    if issues:
        logger.warning(f"Geopolitical threat level inconsistencies: {len(issues)}")

    return issues


def _validate_risk_assessment_criteria(report: dict, intel471_data: list, breach_data: list) -> list[str]:
    """Validate risk assessment ratings follow stated criteria."""
    issues = []

    risk_assessment = report.get("risk_assessment", {})

    # If breach_data is None or empty, try to extract from intel471_data
    if not breach_data:
        breach_data = [item for item in intel471_data if "BREACH" in str(item.get("threat_type", "")).upper()]

    # Ransomware validation
    ransomware_rating = risk_assessment.get("ransomware", "")

    # Count ransomware breaches
    ransomware_breaches = sum(1 for breach in breach_data if "ransomware" in str(breach).lower())

    # Criteria: HIGH = 10+ incidents, MEDIUM = 5-9, LOW = <5
    if ransomware_rating == "HIGH" and ransomware_breaches < 10:
        # Allow if there's a significant increase trend
        ransomware_trend = risk_assessment.get("ransomware_trend", "")
        if ransomware_trend != "↑" and ransomware_breaches < 7:
            issues.append(
                f"Ransomware rated HIGH but only {ransomware_breaches} incidents observed "
                f"(criteria requires 10+ for HIGH, or 7+ with increasing trend)"
            )
    elif ransomware_rating == "LOW" and ransomware_breaches >= 5:
        issues.append(f"Ransomware rated LOW but {ransomware_breaches} incidents observed (criteria: <5 for LOW)")

    # Nation-state validation
    nation_state_rating = risk_assessment.get("nation_state", "")

    # Count APT groups from intel471 or crowdstrike
    apt_mentions = sum(1 for item in intel471_data if "apt" in str(item).lower() or "espionage" in str(item).lower())

    # Criteria: HIGH = 3+ APT groups, MEDIUM = 1-2, LOW = minimal
    if nation_state_rating == "HIGH" and apt_mentions < 3:
        # Check if there are geopolitical threats marked as HIGH
        geo_threats = report.get("geopolitical_threats", [])
        high_geo_threats = [t for t in geo_threats if t.get("level") == "HIGH"]

        if len(high_geo_threats) < 2 and apt_mentions < 2:
            issues.append(
                f"Nation-State rated HIGH but only {apt_mentions} APT-related reports "
                f"(criteria requires 3+ APT groups for HIGH)"
            )

    if issues:
        logger.warning(f"Risk assessment criteria inconsistencies: {len(issues)}")

    return issues


def _pct_magnitude(change_pct: Any) -> int | None:
    """Extract the integer magnitude from a change_pct (e.g. '+45%', '-12', 45) or None.

    Robust against non-string, missing-sign, and missing-'%' values so a malformed
    AI-produced field can never raise ValueError/AttributeError.
    """
    if change_pct is None:
        return None
    m = re.search(r"-?\d+", str(change_pct))
    return abs(int(m.group(0))) if m else None


def _validate_risk_trends(report: dict) -> list[str]:
    """Validate risk trends (↑/↓) align with breach statistics."""
    warnings = []

    risk_assessment = report.get("risk_assessment") or {}
    breach_landscape = report.get("breach_landscape") or {}
    stat_cards = [c for c in (breach_landscape.get("stat_cards") or []) if isinstance(c, dict)]

    # Check ransomware trend vs ransomware stat card
    ransomware_trend = risk_assessment.get("ransomware_trend", "")
    ransomware_card = next((card for card in stat_cards if "Ransomware" in str(card.get("label", ""))), None)

    if ransomware_card and ransomware_trend:
        change_pct = str(ransomware_card.get("change_pct", ""))

        # If trend is ↑ but change_pct is negative or 0%, that's inconsistent
        if ransomware_trend == "↑" and (change_pct.startswith("-") or change_pct == "0%"):
            warnings.append(f"Ransomware trend shows ↑ (increasing) but stat card shows {change_pct} change")
        elif ransomware_trend == "↓" and change_pct.startswith("+"):
            warnings.append(f"Ransomware trend shows ↓ (decreasing) but stat card shows {change_pct} increase")

    # Check total incidents trend
    total_incidents_card = next((card for card in stat_cards if "Total Incidents" in str(card.get("label", ""))), None)

    if total_incidents_card:
        change_pct = str(total_incidents_card.get("change_pct", ""))
        magnitude = _pct_magnitude(change_pct)

        # If there's a significant increase but no risk trends showing ↑, warn
        if change_pct.startswith("+") and magnitude is not None and magnitude > 30:
            increasing_risks = [
                risk
                for risk in ["nation_state_trend", "ransomware_trend", "supply_chain_trend"]
                if risk_assessment.get(risk) == "↑"
            ]

            if len(increasing_risks) == 0:
                warnings.append(
                    f"Total incidents increased {change_pct} but no risk categories show increasing trend (↑)"
                )

    if warnings:
        logger.info(f"Risk trend alignment warnings: {len(warnings)}")

    return warnings


def run(input: GateInput, llm_client: Any, report_type: str) -> GateResult:
    """Execute Gate 1E - AI Output Quality Validation.

    Args:
        input: GateInput with tier1_data, osint_articles, and prior gate results
        llm_client: LLM client (not used - deterministic validation)
        report_type: "WEEKLY" or "QUARTERLY"

    Returns:
        GateResult with validation findings
    """
    logger.info(f"Running Gate 1E: AI Output Quality Validation ({report_type})")

    if report_type.upper() != "QUARTERLY":
        # Only run for quarterly reports
        logger.info("Gate 1E skipped - only runs for quarterly reports")
        return GateResult(gate_id="1E", status="COMPLETE", payload={"skipped": "Not a quarterly report"})

    # Get report from Gate 5
    g5 = input.prior_results.get("5")
    if not g5 or g5.status != "COMPLETE":
        return GateResult(
            gate_id="1E",
            status="HALT",
            halt_reason="Gate 5 (Report Draft) did not complete - cannot validate AI output",
            payload={},
        )

    report = g5.payload.get("report", {})
    issues = []
    warnings = []

    logger.info("Running AI output quality validations...")

    # Run all quality validations
    issues.extend(_validate_company_names(report))
    issues.extend(_validate_osint_citations(report))
    warnings.extend(_validate_illumina_context_usage(input, report))
    warnings.extend(_validate_executive_summary_completeness(report))
    issues.extend(_validate_geopolitical_threat_levels(report, input.tier1_data.get("CrowdStrike", [])))

    # For risk assessment, try to get breach_data from different sources
    breach_data = None
    if "breach_data" in input.tier1_data:
        breach_data = input.tier1_data["breach_data"]
    else:
        # Extract from Intel471 data
        intel471_data = input.tier1_data.get("Intel471", [])
        breach_data = [item for item in intel471_data if "BREACH" in str(item.get("threat_type", "")).upper()]

    issues.extend(_validate_risk_assessment_criteria(report, input.tier1_data.get("Intel471", []), breach_data))
    warnings.extend(_validate_risk_trends(report))

    # Log results
    if issues:
        logger.error(f"Gate 1E found {len(issues)} critical quality issues")
        for issue in issues:
            logger.error(f"  ❌ {issue}")

    if warnings:
        logger.warning(f"Gate 1E found {len(warnings)} warnings")
        for warning in warnings:
            logger.warning(f"  ⚠️  {warning}")

    if not issues and not warnings:
        logger.info("✓ Gate 1E: All AI output quality checks passed")

    # Gate 1E is non-halting: it surfaces critical AI-quality issues in the payload,
    # and Gate 6 folds payload['issues'] into Track A to block publish. This keeps a
    # single blocking chokepoint (Gate 6) with a complete findings list, rather than
    # halting mid-sequence and hiding downstream findings.
    #
    # The previous behaviour downgraded the most concrete fabrication check here
    # (generic/fake victim names) to a non-blocking warning, so fabricated victims
    # could never stop a report. That downgrade is removed: generic-term issues now
    # stay in `issues` and therefore block via Gate 6.
    if issues:
        logger.error(f"Gate 1E surfacing {len(issues)} critical quality issue(s) for Gate 6 to block on")
    status = "COMPLETE"
    halt_reason = None

    return GateResult(
        gate_id="1E",
        status=status,
        halt_reason=halt_reason,
        payload={
            "issues": issues,
            "warnings": warnings,
            "validations_run": [
                "company_name_specificity",
                "osint_inline_citations",
                "illumina_context_usage",
                "executive_summary_completeness",
                "geopolitical_threat_levels",
                "risk_assessment_criteria",
                "risk_trend_alignment",
            ],
            "summary": {"total_validations": 7, "critical_issues": len(issues), "warnings": len(warnings)},
        },
    )
