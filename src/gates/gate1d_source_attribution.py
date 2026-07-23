"""
Gate 1D: Source Attribution Validation (QUARTERLY only)

Validates that claims in the strategic quarterly report can be traced to collected
source data, for compliance/audit purposes.

This gate is NON-HALTING: it surfaces `issues` (Track A / blocking) and `warnings`
(Track B / advisory) in its payload, and Gate 6 folds them into the publish decision.
It must never `return status="HALT"` — the orchestrator turns a non-clearable status
into an uncaught RuntimeError. A genuine structural precondition failure (Gate 5 did
not run) raises GateHaltError, which the pipeline catches.

Gate 1D only appears in the quarterly sequence, so there is no weekly branch.
"""

import logging
from typing import Any

from src.core.config import customer_profile
from src.gates.halt import GateHaltError
from src.gates.models import GateInput, GateResult

logger = logging.getLogger(__name__)


def run(input: GateInput, llm_client: Any, report_type: str) -> GateResult:
    """Validate source attribution for the quarterly report. Non-halting."""
    logger.info(f"Running Gate 1D: Source Attribution Validation ({report_type})")

    g5 = input.prior_results.get("5")
    if not g5 or g5.status != "COMPLETE":
        # Structural precondition failure — raise (caught by the pipeline) rather than
        # returning a non-clearable status.
        raise GateHaltError(
            gate_id="1D",
            reason="Gate 5 (Report Draft) did not complete - cannot validate attribution",
            payload={},
        )

    report = g5.payload.get("report", {})
    issues: list[str] = []
    warnings: list[str] = []

    g1 = input.prior_results.get("1")
    tier1_sources = g1.payload.get("tier1_sources", []) if g1 else []
    data_by_source = {sr.source_name: input.tier1_data.get(sr.source_name, []) for sr in tier1_sources}

    osint_data = input.osint_articles or []
    intel471_data = data_by_source.get("Intel471", [])
    crowdstrike_data = data_by_source.get("CrowdStrike", [])
    company_osint = data_by_source.get(customer_profile.osint_source_name, [])

    if not intel471_data:
        warnings.append("No Intel471 data available for quarterly analysis")
    if not crowdstrike_data:
        warnings.append("No CrowdStrike data available for quarterly analysis")

    # Geopolitical threats attribution
    geopolitical_threats = report.get("geopolitical_threats") or []
    for threat in geopolitical_threats:
        if not isinstance(threat, dict):
            continue
        name = threat.get("name") or threat.get("country") or ""
        if not name:
            issues.append("Geopolitical threat missing name field")
        if not threat.get("activity"):
            warnings.append(f"Geopolitical threat '{name or 'unnamed'}' has no activity bullets")
    if geopolitical_threats:
        logger.info(f"Reviewed {len(geopolitical_threats)} geopolitical threats")

    # Breach landscape: stat-card change_pct sign hygiene. Robust against non-string /
    # malformed values (the AI can emit "+high%", "+40", 0.4, or None). Downgraded to a
    # WARNING to match Gate 1A/1F (a missing +/- sign is cosmetic, not a hard block).
    breach_landscape = report.get("breach_landscape") or {}
    for card in breach_landscape.get("stat_cards") or []:
        if not isinstance(card, dict):
            continue
        change_pct = card.get("change_pct")
        if change_pct in (None, "", "0%"):
            continue
        cp = str(change_pct).strip()
        if not (cp.startswith("+") or cp.startswith("-")):
            warnings.append(f"Stat card change_pct missing +/- sign: '{cp}'")

    # Company-OSINT context is structurally optional (never routed into tier1_data in
    # this pipeline), so its absence is a log line, not a warning that would spam Gate 6.
    if company_osint:
        logger.info(f"{customer_profile.osint_source_name} context collected ({len(company_osint)} records)")

    summary = {
        "intel471_reports": len(intel471_data),
        "crowdstrike_records": len(crowdstrike_data),
        "osint_articles": len(osint_data),
        "company_osint_records": len(company_osint),
        "geopolitical_threats": len(geopolitical_threats),
        "breach_incidents": len(breach_landscape.get("incidents_by_type") or []),
        "issues": issues,
        "warnings": warnings,
    }

    logger.info(f"Gate 1D COMPLETE: {len(issues)} issue(s), {len(warnings)} warning(s)")
    return GateResult(gate_id="1D", status="COMPLETE", payload=summary)
