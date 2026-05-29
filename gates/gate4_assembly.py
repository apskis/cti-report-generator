"""Gate 4: Structured data assembly merging Tier 1 evidence and OSINT corroboration.

This is the last gate before narrative begins. Tier 1 and Tier 2 data are
combined here under strict labeling rules:

- Every Tier 1 finding (IOC, actor, CVE) is cross-checked against Gate 1B
  OSINTSignal values. Matches become OSINTCorroboration records.
- Every Gate 1B signal that has no Tier 1 backing becomes an OpenSignal,
  labeled [OSINT ONLY: NOT VERIFIED BY TIER 1]. These go to the analyst-only
  appendix, never to Threat Findings.
- Every section with no source data is explicitly marked [NOT IN PROVIDED
  SOURCES] rather than left empty.
- For quarterly reports, the Geopolitical Context Signals section is sourced
  ONLY from Intel471 and CrowdStrike Falcon data.

Calls detect_osint_promotion on the assembled payload as a structural fence.
"""
from __future__ import annotations

from .escape_handler import detect_gate_bleed, detect_osint_promotion, detect_prose_leakage
from .models import (
    ActorLink,
    GateInput,
    GateResult,
    IOC,
    OpenSignal,
    OSINTArticle,
    OSINTCorroboration,
    OSINTSignal,
    SourceRecord,
)
from .prompts import GATE_4_PROMPT_TEMPLATE, SYSTEM_PROMPT_GATE_4


_GOV_ADVISORY_SOURCES = {"CISA Alerts", "US-CERT Current Activity"}
_GEOPOLITICAL_SOURCES = {"Intel471", "CrowdStrike"}


def _severity_key(severity: str) -> tuple[int, str]:
    """Sort key: severity ranked, then by string for stable order. Higher = more severe."""
    rank_map = {
        "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
        "informational": 0,
    }
    s = severity.lower() if isinstance(severity, str) else ""
    if s in rank_map:
        return (rank_map[s], severity)
    try:
        # Numeric CVSS-style scores
        return (min(int(float(s) * 10), 100), severity)
    except (TypeError, ValueError):
        return (-1, severity)


def _build_corroboration(
    tier1_values: dict[str, str],
    osint_signals: list[OSINTSignal],
    osint_articles: list[OSINTArticle],
) -> tuple[list[OSINTCorroboration], set[str]]:
    """For each Tier 1 value, find OSINT articles that reference it.

    Returns (corroborations, matched_signal_values).
    """
    article_by_id = {a.article_id: a for a in osint_articles}
    corroborations: list[OSINTCorroboration] = []
    matched_signal_values: set[str] = set()

    for value, _value_kind in tier1_values.items():
        for sig in osint_signals:
            if value in sig.iocs_mentioned or value in sig.cve_ids or value in sig.actor_names:
                article = article_by_id.get(sig.article_id)
                if article is None:
                    continue
                corroborations.append(
                    OSINTCorroboration(
                        finding_value=value,
                        article_id=sig.article_id,
                        source_name=article.source_name,
                        publication_date=article.published_date,
                        is_gov_advisory=article.source_name in _GOV_ADVISORY_SOURCES,
                    )
                )
                matched_signal_values.add(value)

    return corroborations, matched_signal_values


def _build_open_signals(
    osint_signals: list[OSINTSignal],
    tier1_values: dict[str, str],
) -> list[OpenSignal]:
    """OSINT signals with no Tier 1 backing become OpenSignals."""
    open_signals: list[OpenSignal] = []
    for sig in osint_signals:
        for ioc in sig.iocs_mentioned:
            if ioc not in tier1_values:
                open_signals.append(
                    OpenSignal(
                        article_id=sig.article_id, signal_type="ioc",
                        value=ioc, context_quote=sig.context_quote,
                    )
                )
        for cve in sig.cve_ids:
            if cve not in tier1_values:
                open_signals.append(
                    OpenSignal(
                        article_id=sig.article_id, signal_type="cve",
                        value=cve, context_quote=sig.context_quote,
                    )
                )
        for actor in sig.actor_names:
            if actor not in tier1_values:
                open_signals.append(
                    OpenSignal(
                        article_id=sig.article_id, signal_type="actor",
                        value=actor, context_quote=sig.context_quote,
                    )
                )
    return open_signals


def _build_top_iocs(iocs: list[IOC], limit: int = 10) -> list[dict]:
    ranked = sorted(iocs, key=lambda i: _severity_key(i.source_severity), reverse=True)
    top: list[dict] = []
    for ioc in ranked[:limit]:
        top.append({
            "type": ioc.ioc_type,
            "value": ioc.value,
            "sources": ioc.sources,
            "severity": ioc.source_severity,
            "cross_source_hit": ioc.cross_source_hit,
        })
    return top


def _collect_coverage_gaps(
    tier1_sources: list[SourceRecord],
    osint_sources: list[SourceRecord],
    iocs: list[IOC],
    actor_links: list[ActorLink],
) -> list[str]:
    gaps: list[str] = []
    
    # Only report gaps for ENABLED sources
    for r in tier1_sources:
        if r.enabled and r.status.startswith("GAP"):
            gaps.append(f"[NOT IN PROVIDED SOURCES] {r.source_name}: {r.status}")
    
    for r in osint_sources:
        if r.enabled and r.records_returned == 0:
            gaps.append(f"[NO ARTICLES] {r.source_name}: no articles in lookback window")
    
    if not iocs:
        gaps.append("[NO IOCs IN SOURCE: all Tier 1 sources]")
    if not any(link.actor_name != "[UNATTRIBUTED]" for link in actor_links):
        gaps.append("[NOT IN PROVIDED SOURCES] No actor attribution in any Tier 1 source for this period")
    return gaps


def _build_geopolitical_signals(
    actor_links: list[ActorLink],
    tier1_data: dict,
) -> list[dict]:
    """Pull geopolitical context from Intel471 and CrowdStrike records only."""
    signals: list[dict] = []
    for source in _GEOPOLITICAL_SOURCES:
        records = tier1_data.get(source)
        if not isinstance(records, list):
            continue
        for rec in records:
            if not isinstance(rec, dict):
                continue
            region = rec.get("region") or rec.get("origin_country") or rec.get("country")
            geo_context = rec.get("geopolitical_context") or rec.get("nation_state")
            if not (region or geo_context):
                continue
            signals.append({
                "source": source,
                "region": region,
                "context": geo_context,
                "actor": rec.get("actor") or rec.get("actor_name"),
            })
    return signals


def run(input: GateInput, llm_client, report_type: str) -> GateResult:
    g1 = input.prior_results.get("1")
    g1b = input.prior_results.get("1B")
    g2 = input.prior_results.get("2")
    g3 = input.prior_results.get("3")
    if not all((g1, g1b, g2, g3)):
        raise RuntimeError("Gate 4 requires Gates 1, 1B, 2, 3 GateResults in input.prior_results")

    tier1_sources: list[SourceRecord] = g1.payload.get("tier1_sources", [])
    osint_articles: list[OSINTArticle] = g1b.payload.get("osint_articles", [])
    osint_signals: list[OSINTSignal] = g1b.payload.get("osint_signals", [])
    osint_sources: list[SourceRecord] = g1b.payload.get("osint_sources", [])
    iocs: list[IOC] = g2.payload.get("iocs", [])
    actor_links: list[ActorLink] = g3.payload.get("actor_links", [])

    # Index all Tier 1 values (IOC values + actor names + CVEs from IOC list)
    tier1_values: dict[str, str] = {}
    for ioc in iocs:
        tier1_values[ioc.value] = "ioc"
    for link in actor_links:
        if link.actor_name and link.actor_name != "[UNATTRIBUTED]":
            tier1_values[link.actor_name] = "actor"

    corroborations, _matched = _build_corroboration(tier1_values, osint_signals, osint_articles)
    open_signals = _build_open_signals(osint_signals, tier1_values)

    top_iocs = _build_top_iocs(iocs)
    coverage_gaps = _collect_coverage_gaps(tier1_sources, osint_sources, iocs, actor_links)

    # Actor summary: Tier 1 only, [UNATTRIBUTED] excluded
    actor_summary = [
        {
            "ioc": link.ioc_value, "actor": link.actor_name,
            "source": link.attribution_source, "campaign": link.campaign,
            "confidence": link.confidence, "region": link.region,
        }
        for link in actor_links
        if link.actor_name != "[UNATTRIBUTED]"
    ] or "[NOT IN PROVIDED SOURCES]"

    executive_signal = (
        f"Highest severity Tier 1 IOC: {top_iocs[0]['value']} ({top_iocs[0]['severity']}) "
        f"from {','.join(top_iocs[0]['sources'])}"
        if top_iocs
        else "[NOT IN PROVIDED SOURCES]"
    )

    assembly: dict = {
        "report_type": report_type,
        "executive_signal": executive_signal,
        "top_iocs": top_iocs,
        "actor_summary": actor_summary,
        "vulnerability_highlights": "[NOT IN PROVIDED SOURCES]",  # populated by LLM extraction text if needed
        "osint_corroboration": [
            {
                "finding": c.finding_value, "article_id": c.article_id,
                "source": c.source_name, "published": c.publication_date,
                "is_gov_advisory": c.is_gov_advisory,
            }
            for c in corroborations
        ],
        "open_signals": [
            {
                "article_id": s.article_id, "type": s.signal_type,
                "value": s.value, "context": s.context_quote, "label": s.label,
            }
            for s in open_signals
        ],
        "coverage_gaps": coverage_gaps,
    }

    if report_type.upper() == "QUARTERLY":
        geopolitical = _build_geopolitical_signals(actor_links, input.tier1_data)
        assembly["geopolitical_context_signals"] = geopolitical or (
            f"[NO GEOPOLITICAL CONTEXT IN PROVIDED SOURCES: Intel471 returned "
            f"{len(input.tier1_data.get('Intel471') or [])} records, CrowdStrike Falcon returned "
            f"{len(input.tier1_data.get('CrowdStrike') or [])} records, neither contained "
            f"geopolitical attribution data for this period.]"
        )
        assembly["campaign_themes"] = "[NOT IN PROVIDED SOURCES]"  # quarterly-only narrative field, populated by LLM
        assembly["regional_actor_activity"] = actor_summary
        assembly["vulnerability_trends"] = "[NOT IN PROVIDED SOURCES]"

    # Structural fence: ensure no OpenSignal value leaked into top_iocs without a Tier 1 source
    detect_osint_promotion(assembly, open_signals)

    # LLM produces the analyst-facing structured-data text block
    def _summarize(obj, max_lines=15) -> str:
        if isinstance(obj, list):
            lines = [str(item) for item in obj[:max_lines]]
            return "\n".join(lines) or "[empty]"
        return str(obj)

    user_prompt = GATE_4_PROMPT_TEMPLATE.format(
        gate1_output=_summarize(tier1_sources),
        gate1b_output=_summarize(osint_articles),
        gate2_output=_summarize(iocs),
        gate3_output=_summarize(actor_links),
        report_type=report_type,
    )
    llm_text = llm_client.complete(SYSTEM_PROMPT_GATE_4, user_prompt)

    detect_gate_bleed(llm_text, expected_gate_id="4")
    detect_prose_leakage(llm_text, gate_id="4")

    return GateResult(
        gate_id="4",
        status="COMPLETE",
        payload={
            "assembly": assembly,
            "assembly_text": llm_text,
            "corroborations": corroborations,
            "open_signals_objects": open_signals,
        },
        awaiting_clearance=True,
    )
