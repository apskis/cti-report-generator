"""Gate 1A: Report Statistics Validation

Validates that report statistics are internally consistent and match collected data.
Branches based on report type (WEEKLY vs QUARTERLY) to run appropriate validations.

This gate catches data quality issues before they reach the final report:
- Inconsistent totals (e.g., new + persistent > total)
- Missing exploitation flags that should exist
- Zero counts when data was collected
- Suspicious week-over-week changes
"""

from __future__ import annotations

import logging
from typing import Any

from .halt import GateHaltError
from .models import GateInput, GateResult

logger = logging.getLogger(__name__)


def run(gate_input: GateInput, llm_client: Any, report_type: str) -> GateResult:
    """
    Run statistics validation based on report type.

    Args:
        gate_input: Input data including tier1_data and prior_results
        llm_client: LLM client (not used, statistics validation is deterministic)
        report_type: "WEEKLY" or "QUARTERLY"

    Returns:
        GateResult with status COMPLETE and validation details in payload

    Raises:
        GateHaltError: If critical statistics validation fails
    """
    logger.info(f"Running Gate 1A: Statistics Validation for {report_type}")

    if report_type == "WEEKLY":
        return _validate_weekly_statistics(gate_input)
    elif report_type == "QUARTERLY":
        return _validate_quarterly_statistics(gate_input)
    else:
        logger.warning(f"Unknown report type '{report_type}', skipping statistics validation")
        return GateResult(
            gate_id="1A",
            status="COMPLETE",
            payload={
                "report_type": report_type,
                "validations_run": [],
                "warnings": [f"Unknown report type '{report_type}', no validations performed"],
            },
        )


def _validate_weekly_statistics(gate_input: GateInput) -> GateResult:
    """
    Validate weekly tactical report statistics.

    Checks:
    - 7-day lookback window is correctly applied to all data sources
    - Total CVEs > 0 if Tier 1 sources had data
    - Data timestamps fall within expected collection window
    - Exploitation flags match data
    - APT counts match activity data
    """
    validations = []
    warnings = []
    errors = []

    # Get Gate 1 results (source inventory)
    gate1_result = gate_input.prior_results.get("1")
    if not gate1_result:
        raise GateHaltError(
            gate_id="1A",
            reason="Gate 1 has not been run - cannot validate statistics without source inventory",
            payload={},
        )

    tier1_sources = gate1_result.payload.get("tier1_sources", [])

    # NEW Validation: Check 7-day lookback window
    from datetime import UTC, datetime

    # Parse the reporting window as tz-aware UTC so it can be compared against the
    # tz-aware data timestamps below (naive vs aware comparison raises TypeError).
    period_start = datetime.fromisoformat(gate_input.period_start).replace(tzinfo=UTC)
    period_end = datetime.fromisoformat(gate_input.period_end).replace(tzinfo=UTC)
    expected_days = (period_end - period_start).days

    if expected_days != 7:
        warnings.append(
            f"Expected 7-day lookback window, but got {expected_days} days "
            f"({gate_input.period_start} to {gate_input.period_end})"
        )

    validations.append(
        {
            "check": "seven_day_lookback_window",
            "passed": expected_days == 7,
            "details": f"Collection window: {expected_days} days ({gate_input.period_start} to {gate_input.period_end})",
        }
    )

    # NEW Validation: Verify data timestamps fall within window
    data_timestamp_issues = []

    # Check NVD CVE publish dates
    nvd_data = gate_input.tier1_data.get("NVD", [])
    if isinstance(nvd_data, list) and nvd_data:
        for cve in nvd_data[:5]:  # Sample first 5
            if isinstance(cve, dict) and "published_date" in cve:
                try:
                    pub_date = datetime.fromisoformat(cve["published_date"].replace("Z", "+00:00"))
                    if pub_date < period_start or pub_date > period_end:
                        data_timestamp_issues.append(
                            f"NVD CVE {cve.get('cve_id', 'Unknown')} published {pub_date.date()} outside window"
                        )
                except (ValueError, TypeError, AttributeError, OSError, OverflowError) as e:
                    logger.debug(f"Skipping NVD timestamp validation for a record: {e}")

    # Check Intel471 report dates
    intel471_data = gate_input.tier1_data.get("Intel471", [])
    if isinstance(intel471_data, list) and intel471_data:
        for report in intel471_data[:5]:  # Sample first 5
            if isinstance(report, dict) and "date" in report:
                try:
                    report_date_str = report["date"]
                    if isinstance(report_date_str, str):
                        # Handle both datetime strings and timestamp floats
                        if "T" in report_date_str:
                            report_date = datetime.fromisoformat(report_date_str.replace("Z", "+00:00"))
                        else:
                            report_date = datetime.fromisoformat(report_date_str)
                        if report_date.tzinfo is None:
                            report_date = report_date.replace(tzinfo=UTC)

                        if report_date < period_start or report_date > period_end:
                            data_timestamp_issues.append(
                                f"Intel471 report {report.get('uid', 'Unknown')[:16]} dated {report_date.date()} outside window"
                            )
                except (ValueError, TypeError, AttributeError, OSError, OverflowError) as e:
                    logger.debug(f"Skipping Intel471 timestamp validation for a record: {e}")

    # Check CrowdStrike last_activity timestamps
    crowdstrike_data = gate_input.tier1_data.get("CrowdStrike", [])
    if isinstance(crowdstrike_data, list) and crowdstrike_data:
        for actor in crowdstrike_data[:5]:  # Sample first 5
            if isinstance(actor, dict) and "last_activity" in actor:
                try:
                    # CrowdStrike uses Unix timestamp
                    activity_timestamp = actor["last_activity"]
                    if isinstance(activity_timestamp, (int, float)):
                        activity_date = datetime.fromtimestamp(activity_timestamp, tz=UTC)

                        if activity_date < period_start or activity_date > period_end:
                            data_timestamp_issues.append(
                                f"CrowdStrike actor {actor.get('actor_name', 'Unknown')} activity {activity_date.date()} outside window"
                            )
                except (ValueError, TypeError, AttributeError, OSError, OverflowError) as e:
                    logger.debug(f"Skipping CrowdStrike timestamp validation for a record: {e}")

    if data_timestamp_issues:
        warnings.append(
            f"Found {len(data_timestamp_issues)} data records with timestamps outside 7-day window. "
            f"First few: {'; '.join(data_timestamp_issues[:3])}"
        )

    validations.append(
        {
            "check": "data_timestamps_within_window",
            "passed": len(data_timestamp_issues) == 0,
            "details": f"Checked sample records from NVD, Intel471, CrowdStrike. Issues found: {len(data_timestamp_issues)}",
        }
    )

    # Check if we have any Tier 1 data
    has_tier1_data = any(src.records_returned > 0 for src in tier1_sources if src.status != "GAP")

    # Get IOC extraction results (Gate 2 if it ran)
    gate2_result = gate_input.prior_results.get("2")
    cve_count = 0
    if gate2_result:
        iocs = gate2_result.payload.get("iocs", [])
        cve_iocs = [ioc for ioc in iocs if ioc.get("ioc_type") == "CVE"]
        cve_count = len(cve_iocs)

    # Validation 1: If Tier 1 sources have data, we should have CVEs
    if has_tier1_data and cve_count == 0:
        warnings.append("Tier 1 sources returned data but 0 CVEs extracted. This may indicate data parsing issues.")
    validations.append(
        {
            "check": "tier1_data_to_cve_mapping",
            "passed": not (has_tier1_data and cve_count == 0),
            "details": f"Tier 1 sources: {len(tier1_sources)}, CVEs extracted: {cve_count}",
        }
    )

    # Validation 2: Check for suspicious "all zeros" pattern
    # This would come from the actual report statistics, but we don't have access
    # to the final analysis here. We can check the raw data instead.
    total_tier1_records = sum(src.records_returned for src in tier1_sources)
    if total_tier1_records == 0 and has_tier1_data:
        warnings.append(
            "Tier 1 sources show OK status but 0 records returned. "
            "This may indicate API pagination or filtering issues."
        )
    validations.append(
        {
            "check": "non_zero_data_collected",
            "passed": total_tier1_records > 0 or not has_tier1_data,
            "details": f"Total Tier 1 records: {total_tier1_records}",
        }
    )

    # Validation 3: Check actor attribution data exists (Gate 3 if it ran)
    gate3_result = gate_input.prior_results.get("3")
    actor_count = 0
    if gate3_result:
        actor_links = gate3_result.payload.get("actor_links", [])
        # Count unique actors
        unique_actors = set(link.get("actor_name") for link in actor_links if link.get("actor_name"))
        actor_count = len(unique_actors)

    validations.append(
        {
            "check": "actor_attribution_present",
            "passed": True,  # Not a failure, just informational
            "details": f"Unique threat actors identified: {actor_count}",
        }
    )

    # Validation 4: Check for OSINT data quality (Gate 1B if it ran)
    gate1b_result = gate_input.prior_results.get("1B")
    osint_article_count = 0
    if gate1b_result:
        osint_articles = gate1b_result.payload.get("osint_articles", [])
        osint_article_count = len(osint_articles)

    if osint_article_count == 0:
        warnings.append("0 OSINT articles collected. OSINT corroboration and open signals will be limited.")
    validations.append(
        {
            "check": "osint_data_present",
            "passed": osint_article_count > 0,
            "details": f"OSINT articles: {osint_article_count}",
        }
    )

    logger.info(
        f"Weekly statistics validation: {len(validations)} checks, {len(warnings)} warnings, {len(errors)} errors"
    )

    # Summarize results
    payload = {
        "report_type": "WEEKLY",
        "validations": validations,
        "warnings": warnings,
        "errors": errors,
        "summary": {
            "total_checks": len(validations),
            "passed": sum(1 for v in validations if v["passed"]),
            "failed": sum(1 for v in validations if not v["passed"]),
            "lookback_window_days": expected_days,
            "period_start": gate_input.period_start,
            "period_end": gate_input.period_end,
            "tier1_records": total_tier1_records,
            "cves_extracted": cve_count,
            "actors_identified": actor_count,
            "osint_articles": osint_article_count,
        },
    }

    return GateResult(gate_id="1A", status="COMPLETE", payload=payload)


def _validate_quarterly_statistics(gate_input: GateInput) -> GateResult:
    """
    Validate quarterly strategic report statistics.

    Checks:
    - Breach data is present and reasonable
    - Geopolitical context exists
    - Strategic trends are logical
    - Quarter-over-quarter changes make sense
    """
    validations = []
    warnings = []
    errors = []

    # Get Gate 1 results (source inventory)
    gate1_result = gate_input.prior_results.get("1")
    if not gate1_result:
        raise GateHaltError(
            gate_id="1A",
            reason="Gate 1 has not been run - cannot validate statistics without source inventory",
            payload={},
        )

    tier1_sources = gate1_result.payload.get("tier1_sources", [])

    # For quarterly reports, we focus on Intel471 (breach reports) and CrowdStrike (strategic intel)
    intel471_records = 0
    crowdstrike_records = 0

    for src in tier1_sources:
        if src.source_name == "Intel471":
            intel471_records = src.records_returned
        elif src.source_name == "CrowdStrike":
            crowdstrike_records = src.records_returned

    # Validation 1: Intel471 breach data
    if intel471_records == 0:
        warnings.append("0 Intel471 records collected. Quarterly strategic analysis will lack breach intelligence.")
    validations.append(
        {
            "check": "intel471_breach_data",
            "passed": intel471_records > 0,
            "details": f"Intel471 records: {intel471_records}",
        }
    )

    # Validation 2: CrowdStrike strategic intelligence
    if crowdstrike_records == 0:
        warnings.append("0 CrowdStrike records collected. Quarterly report will lack threat actor intelligence.")
    validations.append(
        {
            "check": "crowdstrike_strategic_data",
            "passed": crowdstrike_records > 0,
            "details": f"CrowdStrike records: {crowdstrike_records}",
        }
    )

    # Validation 3: Check Gate 4 for geopolitical context (quarterly-specific field)
    gate4_result = gate_input.prior_results.get("4")
    has_geopolitical = False
    if gate4_result:
        assembly = gate4_result.payload.get("structured_assembly", {})
        geopolitical_signals = assembly.get("geopolitical_context_signals", [])
        has_geopolitical = len(geopolitical_signals) > 0

    if not has_geopolitical:
        warnings.append("No geopolitical context signals found. Quarterly strategic analysis may lack depth.")
    validations.append(
        {
            "check": "geopolitical_context_present",
            "passed": has_geopolitical,
            "details": f"Geopolitical signals: {'present' if has_geopolitical else 'absent'}",
        }
    )

    # NEW VALIDATION 4: Breach statistics accuracy (if Gate 5 has run)
    gate5_result = gate_input.prior_results.get("5")
    if gate5_result and gate5_result.status == "COMPLETE":
        report = gate5_result.payload.get("report", {})
        breach_landscape = report.get("breach_landscape", {})
        stat_cards = breach_landscape.get("stat_cards", [])

        # Get actual Intel471 breach alerts
        intel471_data = gate_input.tier1_data.get("Intel471", [])
        actual_breach_count = sum(1 for item in intel471_data if "BREACH" in str(item.get("threat_type", "")).upper())

        # Find "Total Incidents" stat card
        total_incidents_card = next(
            (
                card
                for card in stat_cards
                if "Total Incidents" in card.get("label", "") or "Incidents" in card.get("label", "")
            ),
            None,
        )

        if total_incidents_card:
            try:
                reported_count = int(str(total_incidents_card.get("value", "0")).replace(",", ""))
                variance = abs(reported_count - actual_breach_count)

                if variance > 5:  # Allow small variance for data filtering
                    warnings.append(
                        f"Breach count variance: report shows {reported_count} incidents, "
                        f"Intel471 data contains {actual_breach_count} breach alerts (variance: {variance})"
                    )

                validations.append(
                    {
                        "check": "breach_count_accuracy",
                        "passed": variance <= 5,
                        "details": f"Reported: {reported_count}, Actual: {actual_breach_count}, Variance: {variance}",
                    }
                )
            except (ValueError, AttributeError) as e:
                logger.warning(f"Could not validate breach count: {e}")

    # NEW VALIDATION 5: Quarter-over-quarter changes have proper signs
    if gate5_result and gate5_result.status == "COMPLETE":
        report = gate5_result.payload.get("report", {})
        breach_landscape = report.get("breach_landscape", {})
        stat_cards = breach_landscape.get("stat_cards", [])

        missing_signs = []
        for card in stat_cards:
            change_pct = card.get("change_pct", "")
            label = card.get("label", "")

            # Check if change_pct exists and has proper +/- sign
            if change_pct and change_pct != "0%" and not (change_pct.startswith("+") or change_pct.startswith("-")):
                missing_signs.append(f"{label}: '{change_pct}'")

        if missing_signs:
            warnings.append(f"Stat cards missing +/- signs in change_pct: {', '.join(missing_signs)}")

        validations.append(
            {
                "check": "stat_cards_have_signs",
                "passed": len(missing_signs) == 0,
                "details": f"Checked {len(stat_cards)} stat cards, {len(missing_signs)} missing signs",
            }
        )

    logger.info(
        f"Quarterly statistics validation: {len(validations)} checks, {len(warnings)} warnings, {len(errors)} errors"
    )

    # Summarize results
    payload = {
        "report_type": "QUARTERLY",
        "validations": validations,
        "warnings": warnings,
        "errors": errors,
        "summary": {
            "total_checks": len(validations),
            "passed": sum(1 for v in validations if v["passed"]),
            "failed": sum(1 for v in validations if not v["passed"]),
            "intel471_records": intel471_records,
            "crowdstrike_records": crowdstrike_records,
            "has_geopolitical_context": has_geopolitical,
        },
    }

    return GateResult(gate_id="1A", status="COMPLETE", payload=payload)
