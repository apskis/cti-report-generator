"""Gate 1: Tier 1 source inventory and data scope confirmation.

Builds a typed inventory of the 4 Tier 1 paid APIs from collector results and
calls the LLM for the analyst-facing inventory table. No analysis, no
extraction, no narrative. Runs the 2-or-more Tier 1 gaps halt check before
returning.

NOTE: Rapid7 removed from Tier 1 sources - reports now focus on threat intelligence
only (Intel471, CrowdStrike, NVD, ThreatQ, OSINT) without environment/vulnerability
management data.
"""

from __future__ import annotations

import logging
from typing import Any

from .escape_handler import detect_gate_bleed, detect_prose_leakage
from .halt import check_tier1_halt
from .models import GateInput, GateResult, SourceRecord
from .prompts import GATE_1_PROMPT_TEMPLATE, SYSTEM_PROMPT_GATE_1

logger = logging.getLogger(__name__)

# All potential Tier 1 sources (will be filtered by collectors.yaml)
ALL_TIER1_SOURCES = ["ThreatQ", "NVD", "Intel471", "CrowdStrike"]


def _build_source_record(
    source_name: str,
    raw_data: Any,
    period_start: str,
    period_end: str,
    enabled: bool = True,
) -> SourceRecord:
    """Build a SourceRecord from a collector's raw payload.

    raw_data may be:
    - a list of records (success path)
    - None or empty list (gap)
    - a dict with an "error" key (collector failure)
    """
    if raw_data is None:
        status = "GAP: collector returned None"
        records = 0
    elif isinstance(raw_data, dict) and raw_data.get("error"):
        status = f"GAP: {raw_data['error']}"
        records = 0
    elif isinstance(raw_data, list):
        records = len(raw_data)
        status = "OK" if records > 0 else "GAP: zero records returned"
    else:
        records = 0
        status = f"GAP: unexpected payload type {type(raw_data).__name__}"

    return SourceRecord(
        source_name=source_name,
        tier=1,
        records_returned=records,
        period_start=period_start,
        period_end=period_end,
        status=status,
        enabled=enabled,
    )


def _get_enabled_tier1_sources(tier1_data: dict) -> list[str]:
    """Get list of Tier 1 sources that are enabled and actually provided to this gate.

    Only check sources that are present in tier1_data (meaning they're enabled in collectors.yaml).
    This prevents coverage gap warnings for intentionally disabled sources like ThreatQ.
    """
    enabled_sources = []
    for source in ALL_TIER1_SOURCES:
        # Only include if the source actually provided data (even if empty)
        # If a source is disabled in collectors.yaml, it won't be in tier1_data at all
        if source in tier1_data:
            enabled_sources.append(source)

    logger.info(f"Enabled Tier 1 sources (from collectors.yaml): {enabled_sources}")
    return enabled_sources


def _load_collector_config() -> dict:
    """Load collectors.yaml to determine which sources are actually enabled."""
    import os

    import yaml

    config_path = "config/collectors.yaml"
    if not os.path.exists(config_path):
        logger.warning(f"collectors.yaml not found at {config_path}, assuming all sources enabled")
        return {}

    try:
        with open(config_path) as f:
            config = yaml.safe_load(f)

        # Build dict of source name -> enabled status
        enabled_map = {}
        for collector in config.get("collectors", []):
            name = collector.get("name", "")
            enabled = collector.get("enabled", True)
            # Normalize names: "threatq" -> "ThreatQ", "intel471" -> "Intel471", etc.
            if name.lower() == "threatq":
                enabled_map["ThreatQ"] = enabled
            elif name.lower() == "intel471":
                enabled_map["Intel471"] = enabled
            elif name.lower() == "crowdstrike":
                enabled_map["CrowdStrike"] = enabled
            elif name.lower() == "nvd":
                enabled_map["NVD"] = enabled

        logger.info(f"Loaded collector config: {enabled_map}")
        return enabled_map
    except Exception as e:
        logger.warning(f"Error loading collectors.yaml: {e}, assuming all sources enabled")
        return {}


def run(input: GateInput, llm_client, report_type: str) -> GateResult:
    """Execute Gate 1.

    The llm_client must expose a `.complete(system_prompt, user_prompt) -> str`
    interface. The orchestrator injects it; this module never imports an API
    client directly.
    """
    # Load collector config to know which sources are actually enabled
    collector_config = _load_collector_config()

    # Only check sources that are actually enabled in collectors.yaml
    tier1_sources = _get_enabled_tier1_sources(input.tier1_data)

    tier1_records: list[SourceRecord] = []
    for source in tier1_sources:
        raw = input.tier1_data.get(source)
        # Mark whether this source is enabled in collectors.yaml
        enabled = collector_config.get(source, True)
        tier1_records.append(_build_source_record(source, raw, input.period_start, input.period_end, enabled))

    # Build source data summary for the LLM (counts and statuses only, no record contents)
    summary_lines = [
        f"{r.source_name}: records={r.records_returned} window={r.period_start}..{r.period_end} status={r.status}"
        for r in tier1_records
    ]
    source_data_block = "\n".join(summary_lines)

    user_prompt = GATE_1_PROMPT_TEMPLATE.format(
        report_type=report_type,
        period_start=input.period_start,
        period_end=input.period_end,
        source_data=source_data_block,
    )

    llm_text = llm_client.complete(SYSTEM_PROMPT_GATE_1, user_prompt)

    # Halt check before escape check: a halt means analyst decision, not model misbehavior
    check_tier1_halt(tier1_records)

    # Escape checks against the raw model output
    detect_gate_bleed(llm_text, expected_gate_id="1")
    detect_prose_leakage(llm_text, gate_id="1")

    return GateResult(
        gate_id="1",
        status="COMPLETE",
        payload={
            "tier1_sources": tier1_records,
            "inventory_text": llm_text,
            "report_type": report_type,
            "period_start": input.period_start,
            "period_end": input.period_end,
        },
        awaiting_clearance=True,
    )
