"""Gate 2: IOC extraction and severity scoring from Tier 1 sources only.

Extracts IOCs deterministically from the structured Tier 1 records confirmed
in Gate 1. Severity is taken verbatim from source data; if a source provides
no severity field, the IOC carries [NO SCORE IN SOURCE]. Halts if zero IOCs
were extracted across all sources.
"""
from __future__ import annotations

import re
from typing import Any

from .escape_handler import detect_gate_bleed, detect_prose_leakage
from .halt import check_ioc_halt
from .models import GateInput, GateResult, IOC
from .prompts import GATE_2_PROMPT_TEMPLATE, SYSTEM_PROMPT_GATE_2


_IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_URL_RE = re.compile(r"\bhttps?://[^\s'\")]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def _classify(value: str) -> str | None:
    """Return the canonical IOC type for value, or None if it does not look like an IOC."""
    if _CVE_RE.match(value):
        return None  # CVEs are vulnerabilities, not IOCs
    if _URL_RE.fullmatch(value):
        return "url"
    if _EMAIL_RE.fullmatch(value):
        return "email"
    if _HASH_RE.fullmatch(value):
        return "hash"
    if _IPV4_RE.fullmatch(value) or _IPV6_RE.fullmatch(value):
        return "ip"
    if _DOMAIN_RE.fullmatch(value):
        return "domain"
    return None


def _pull_record_iocs(record: dict) -> list[tuple[str, str]]:
    """Return list of (type, value) IOC tuples from a single Tier 1 record.

    Looks at common fields used across the existing collectors. Unknown
    structures are scanned for IOC-shaped substrings in string-valued fields.
    """
    pairs: list[tuple[str, str]] = []

    indicator = record.get("indicator") or record.get("value") or record.get("ioc")
    indicator_type = record.get("indicator_type") or record.get("type")
    if indicator and isinstance(indicator, str):
        t = _classify(indicator) or (indicator_type if isinstance(indicator_type, str) else None)
        if t:
            pairs.append((t.lower(), indicator))

    for field in ("indicators", "iocs", "indicator_list"):
        items = record.get(field)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    v = item.get("value") or item.get("indicator")
                    t = item.get("type") or (_classify(v) if isinstance(v, str) else None)
                    if v and t:
                        pairs.append((str(t).lower(), str(v)))
                elif isinstance(item, str):
                    t = _classify(item)
                    if t:
                        pairs.append((t, item))

    return pairs


def _pull_severity(record: dict) -> str:
    for key in ("severity", "score", "confidence", "tlp", "criticality", "cvss_score", "cvss"):
        v = record.get(key)
        if v not in (None, ""):
            return str(v)
    return "[NO SCORE IN SOURCE]"


def _extract_from_tier1(tier1_records: list, tier1_data: dict) -> list[IOC]:
    """Walk Tier 1 raw records by source and collect IOC objects."""
    bucket: dict[tuple[str, str], dict[str, Any]] = {}

    for source_record in tier1_records:
        if source_record.tier != 1:
            continue
        source_name = source_record.source_name
        raw = tier1_data.get(source_name)
        if not isinstance(raw, list):
            continue
        for rec in raw:
            if not isinstance(rec, dict):
                continue
            severity = _pull_severity(rec)
            for ioc_type, value in _pull_record_iocs(rec):
                key = (ioc_type, value)
                entry = bucket.setdefault(
                    key,
                    {"sources": [], "severities": []},
                )
                if source_name not in entry["sources"]:
                    entry["sources"].append(source_name)
                entry["severities"].append(severity)

    iocs: list[IOC] = []
    for (ioc_type, value), entry in bucket.items():
        non_empty_sev = [s for s in entry["severities"] if s != "[NO SCORE IN SOURCE]"]
        severity = non_empty_sev[0] if non_empty_sev else "[NO SCORE IN SOURCE]"
        iocs.append(
            IOC(
                ioc_type=ioc_type,
                value=value,
                sources=entry["sources"],
                source_severity=severity,
                cross_source_hit=len(entry["sources"]) > 1,
            )
        )
    return iocs


def run(input: GateInput, llm_client, report_type: str) -> GateResult:
    gate1 = input.prior_results.get("1")
    if gate1 is None:
        raise RuntimeError("Gate 2 requires Gate 1 GateResult in input.prior_results['1']")

    tier1_records = gate1.payload.get("tier1_sources", [])
    iocs = _extract_from_tier1(tier1_records, input.tier1_data)

    # Halt before LLM round-trip if zero IOCs
    check_ioc_halt(iocs)

    # Build a compact summary for the LLM (no record contents, just counts)
    gate1_summary = "\n".join(
        f"{r.source_name}: {r.records_returned} records, status={r.status}"
        for r in tier1_records
    )
    user_prompt = GATE_2_PROMPT_TEMPLATE.format(gate1_output=gate1_summary)
    llm_text = llm_client.complete(SYSTEM_PROMPT_GATE_2, user_prompt)

    detect_gate_bleed(llm_text, expected_gate_id="2")
    detect_prose_leakage(llm_text, gate_id="2")

    return GateResult(
        gate_id="2",
        status="COMPLETE",
        payload={
            "iocs": iocs,
            "extraction_text": llm_text,
        },
        awaiting_clearance=True,
    )
