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

from typing import Any

from .escape_handler import detect_gate_bleed, detect_prose_leakage
from .halt import check_tier1_halt
from .models import GateInput, GateResult, SourceRecord
from .prompts import GATE_1_PROMPT_TEMPLATE, SYSTEM_PROMPT_GATE_1


TIER1_SOURCES = ["ThreatQ", "NVD", "Intel471", "CrowdStrike"]


def _build_source_record(
    source_name: str,
    raw_data: Any,
    period_start: str,
    period_end: str,
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
        enabled=True,
    )


def run(input: GateInput, llm_client, report_type: str) -> GateResult:
    """Execute Gate 1.

    The llm_client must expose a `.complete(system_prompt, user_prompt) -> str`
    interface. The orchestrator injects it; this module never imports an API
    client directly.
    """
    tier1_records: list[SourceRecord] = []
    for source in TIER1_SOURCES:
        raw = input.tier1_data.get(source)
        tier1_records.append(
            _build_source_record(source, raw, input.period_start, input.period_end)
        )

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
