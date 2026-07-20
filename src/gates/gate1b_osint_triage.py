"""Gate 1B: OSINT article triage and structured signal extraction.

Reads osint_sources.yaml to know which sources are enabled vs disabled,
assigns sequential Article IDs, enforces the 30-article cap, and extracts
structured signals (CVE IDs and IOC-shaped strings) from article text. Actor
name extraction is left to the LLM analyst-facing pass; the structured signal
list is generated deterministically from regex matches so the test fence does
not depend on model output.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from .escape_handler import detect_gate_bleed, detect_prose_leakage
from .models import GateInput, GateResult, OSINTArticle, OSINTSignal, SourceRecord
from .prompts import GATE_1B_PROMPT_TEMPLATE, SYSTEM_PROMPT_GATE_1B

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


def _load_osint_config(path: str) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        return {"sources": []}
    with config_path.open() as fh:
        return yaml.safe_load(fh) or {"sources": []}


def _context_quote(text: str, max_words: int = 15) -> str:
    words = re.split(r"\s+", text.strip())
    quote = " ".join(words[:max_words])
    return quote.strip()


def _extract_signals(article: dict, article_id: str) -> OSINTSignal:
    title = article.get("title", "")
    summary = article.get("summary", "")
    body = f"{title} {summary}"

    cve_ids = sorted(set(article.get("cves_mentioned") or []) | set(_CVE_RE.findall(body)))
    iocs: list[str] = []
    iocs.extend(_IPV4_RE.findall(body))
    iocs.extend(_HASH_RE.findall(body))
    iocs.extend(_EMAIL_RE.findall(body))
    iocs = sorted(set(iocs))

    quote = _context_quote(summary or title)

    has_structured = bool(cve_ids or iocs)

    return OSINTSignal(
        article_id=article_id,
        iocs_mentioned=iocs,
        actor_names=[],
        cve_ids=cve_ids,
        context_quote=quote,
        has_structured_signals=has_structured,
    )


def run(input: GateInput, llm_client, report_type: str) -> GateResult:
    osint_config_path = input.prior_results.get("osint_config_path", "config/osint_sources.yaml")
    config = _load_osint_config(osint_config_path)
    configured_sources = config.get("sources", [])
    max_total = int(config.get("max_total_articles", 30))

    articles_in = list(input.osint_articles or [])

    cap_hit = len(articles_in) > max_total
    truncated_sources: list[str] = []
    if cap_hit:
        kept = articles_in[:max_total]
        truncated_names = {a.get("source", "") for a in articles_in[max_total:]}
        truncated_sources = sorted(s for s in truncated_names if s)
        articles_in = kept

    osint_articles: list[OSINTArticle] = []
    osint_signals: list[OSINTSignal] = []
    per_source_counts: dict[str, int] = {}

    for idx, raw in enumerate(articles_in, start=1):
        article_id = f"A{idx:03d}"
        source_name = raw.get("source", "")
        per_source_counts[source_name] = per_source_counts.get(source_name, 0) + 1
        osint_articles.append(
            OSINTArticle(
                article_id=article_id,
                source_name=source_name,
                title=raw.get("title", ""),
                published_date=raw.get("published_date", ""),
                url=raw.get("url", ""),
            )
        )
        osint_signals.append(_extract_signals(raw, article_id))

    # Build SourceRecord rows for each configured source (enabled and disabled)
    source_records: list[SourceRecord] = []
    for source in configured_sources:
        name = source.get("name", "")
        enabled = bool(source.get("enabled", True))
        count = per_source_counts.get(name, 0) if enabled else 0
        if not enabled:
            status = "[DISABLED IN CONFIG]"
        elif count == 0:
            status = "OK: no articles in lookback window"
        else:
            status = "OK"
        source_records.append(
            SourceRecord(
                source_name=name,
                tier=2,
                records_returned=count,
                period_start=input.period_start,
                period_end=input.period_end,
                status=status,
                enabled=enabled,
            )
        )

    # LLM produces the analyst-facing triage tables
    article_data_block = (
        "\n".join(
            f"{a.article_id} | {a.source_name} | {a.title} | {a.published_date} | {a.url}" for a in osint_articles
        )
        or "[NO ARTICLES COLLECTED]"
    )

    user_prompt = GATE_1B_PROMPT_TEMPLATE.format(article_data=article_data_block)
    llm_text = llm_client.complete(SYSTEM_PROMPT_GATE_1B, user_prompt)

    detect_gate_bleed(llm_text, expected_gate_id="1B")
    detect_prose_leakage(llm_text, gate_id="1B")

    payload = {
        "osint_articles": osint_articles,
        "osint_signals": osint_signals,
        "osint_sources": source_records,
        "triage_text": llm_text,
        "cap_hit": cap_hit,
        "truncated_sources": truncated_sources,
        "max_total_articles": max_total,
    }
    return GateResult(gate_id="1B", status="COMPLETE", payload=payload, awaiting_clearance=True)
