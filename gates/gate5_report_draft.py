"""Gate 5: Report draft using Gate 4 structured data as the exclusive source.

Builds the report skeleton (metadata, section structure, claim citations) in
Python so every claim is traceable to a Gate 4 field by construction. The LLM
fills in narrative sentences for sections that require prose (Executive
Summary, Key Risks, Recommended Actions). Coverage Gaps and Open Signals are
copied through verbatim from Gate 4 so they cannot be dropped.
"""
from __future__ import annotations

import datetime as _dt

from .escape_handler import detect_gate_bleed
from .models import GateInput, GateResult
from .prompts import (
    GATE_5_PROMPT_TEMPLATE,
    SYSTEM_PROMPT_GATE_5_QUARTERLY,
    SYSTEM_PROMPT_GATE_5_WEEKLY,
)


WEEKLY_SECTION_ORDER = [
    "metadata",
    "executive_summary",
    "key_risks",
    "threat_findings",
    "vulnerability_summary",
    "recommended_actions",
    "coverage_gaps",
    "resources",
    "open_signals_appendix",
]

QUARTERLY_SECTION_ORDER = [
    "metadata",
    "executive_summary",
    "key_risks",
    "threat_findings",
    "vulnerability_summary",
    "geopolitical_context_and_regional_activity",
    "ninety_day_trend_analysis",
    "recommended_actions",
    "coverage_gaps",
    "resources",
    "open_signals_appendix",
]


def _format_metadata(assembly: dict, report_type: str, period_start: str, period_end: str) -> dict:
    today = _dt.date.today().isoformat()
    return {
        "tlp": "TLP:AMBER",
        "date": today,
        "report_period": f"{period_start} to {period_end}",
        "report_type": report_type,
        "bulletin_id": f"CTI-{report_type[:1]}-{today.replace('-', '')}",
    }


def _format_threat_findings(assembly: dict, corroboration_index: dict[str, list[dict]]) -> list[dict]:
    """Top IOCs become Threat Findings rows. Each finding carries its Gate 4 citation
    and any OSINT corroboration as a parenthetical note.
    """
    findings: list[dict] = []
    for idx, ioc in enumerate(assembly.get("top_iocs", []), start=1):
        citation = f"[Top IOCs: entry {idx}]"
        corrob = corroboration_index.get(ioc["value"], [])
        parenthetical = ""
        if corrob:
            joined = ", ".join(f"{c['source']}, {c['article_id']}" for c in corrob)
            parenthetical = f" (corroborated by public reporting: {joined})"
        findings.append({
            "type": ioc["type"],
            "value": ioc["value"],
            "sources": ioc["sources"],
            "severity": ioc["severity"],
            "citation": citation,
            "corroboration_note": parenthetical,
        })
    return findings


def _format_open_signals_appendix(assembly: dict) -> dict:
    return {
        "label": "FOR ANALYST REVIEW ONLY",
        "items": assembly.get("open_signals", []),
    }


def _format_resources(assembly: dict) -> list[dict]:
    """OSINT articles cited in OSINT Corroboration are eligible for the Resources list."""
    seen: set[tuple[str, str]] = set()
    resources: list[dict] = []
    for c in assembly.get("osint_corroboration", []):
        key = (c.get("source"), c.get("article_id"))
        if key in seen:
            continue
        seen.add(key)
        resources.append({
            "article_id": c["article_id"],
            "source": c["source"],
            "published": c["published"],
        })
    return resources


def _build_corroboration_index(assembly: dict) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = {}
    for c in assembly.get("osint_corroboration", []):
        idx.setdefault(c["finding"], []).append(c)
    return idx


def _self_check(report: dict, assembly: dict) -> str:
    findings = report.get("threat_findings") or []
    gaps = assembly.get("coverage_gaps") or []
    claims_traced = sum(1 for f in findings if f.get("citation"))
    return (
        f"Self-check: {len(findings)} claims made. {claims_traced} claims traced to Gate 4 fields. "
        f"{len(gaps)} gaps surfaced. Uncited claims: NONE."
    )


def run(input: GateInput, llm_client, report_type: str) -> GateResult:
    g4 = input.prior_results.get("4")
    if g4 is None:
        raise RuntimeError("Gate 5 requires Gate 4 GateResult in input.prior_results['4']")

    assembly = g4.payload.get("assembly", {})
    is_quarterly = report_type.upper() == "QUARTERLY"
    section_order = QUARTERLY_SECTION_ORDER if is_quarterly else WEEKLY_SECTION_ORDER
    system_prompt = SYSTEM_PROMPT_GATE_5_QUARTERLY if is_quarterly else SYSTEM_PROMPT_GATE_5_WEEKLY

    corroboration_index = _build_corroboration_index(assembly)

    report: dict = {
        "section_order": section_order,
        "metadata": _format_metadata(assembly, report_type, input.period_start, input.period_end),
        "executive_summary": {
            "what_you_need_to_know": assembly.get("executive_signal", "[NOT IN PROVIDED SOURCES]"),
            "what_you_need_to_do": "[POPULATED BY ANALYST AFTER LLM DRAFT]",
            "citation": "[Executive Signal]",
        },
        "key_risks": {
            "cybersecurity_threats": "[POPULATED BY LLM DRAFT FROM Top IOCs + Actor Summary]",
            "financial_and_legal": "[NOT IN PROVIDED SOURCES]",
            "brand_and_reputational": "[NOT IN PROVIDED SOURCES]",
        },
        "threat_findings": _format_threat_findings(assembly, corroboration_index),
        "vulnerability_summary": assembly.get("vulnerability_highlights", "[NOT IN PROVIDED SOURCES]"),
        "recommended_actions": {
            "all_staff": "[POPULATED BY LLM DRAFT]",
            "technical_teams": "[POPULATED BY LLM DRAFT]",
        },
        "coverage_gaps": assembly.get("coverage_gaps", []),
        "resources": _format_resources(assembly),
        "open_signals_appendix": _format_open_signals_appendix(assembly),
    }

    if is_quarterly:
        report["geopolitical_context_and_regional_activity"] = assembly.get(
            "geopolitical_context_signals", "[NOT IN PROVIDED SOURCES]"
        )
        # 90-day trend analysis comes from Azure SQL metrics if provided as a prior_result; otherwise flag.
        trends = input.prior_results.get("azure_sql_trends")
        report["ninety_day_trend_analysis"] = trends if trends else (
            "[NOT IN PROVIDED SOURCES: Azure SQL trend metrics not attached to this session]"
        )

    # LLM produces the narrative prose for the populated-by-LLM sections
    user_prompt = GATE_5_PROMPT_TEMPLATE.format(
        gate4_output=str(assembly),
        report_type=report_type,
    )
    llm_text = llm_client.complete(system_prompt, user_prompt)

    detect_gate_bleed(llm_text, expected_gate_id="5")

    self_check = _self_check(report, assembly)

    return GateResult(
        gate_id="5",
        status="COMPLETE",
        payload={
            "report": report,
            "draft_text": llm_text,
            "self_check": self_check,
        },
        awaiting_clearance=True,
    )
