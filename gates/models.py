"""Shared dataclasses passed between gates.

Every gate consumes and produces these typed models, never raw dicts. This is
how Tier 1 and Tier 2 data stay in separate lanes through Gates 2 and 3, and
how the OSINT corroboration vs Open Signals split is enforced structurally
rather than by convention.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SourceRecord:
    source_name: str
    tier: int
    records_returned: int
    period_start: str
    period_end: str
    status: str
    enabled: bool = True


@dataclass
class IOC:
    ioc_type: str
    value: str
    sources: list[str]
    source_severity: str
    cross_source_hit: bool


@dataclass
class ActorLink:
    ioc_value: str
    actor_name: str
    attribution_source: str
    campaign: str | None = None
    confidence: str | None = None
    region: str | None = None


@dataclass
class OSINTArticle:
    article_id: str
    source_name: str
    title: str
    published_date: str
    url: str


@dataclass
class OSINTSignal:
    article_id: str
    iocs_mentioned: list[str]
    actor_names: list[str]
    cve_ids: list[str]
    context_quote: str
    has_structured_signals: bool


@dataclass
class OSINTCorroboration:
    finding_value: str
    article_id: str
    source_name: str
    publication_date: str
    is_gov_advisory: bool


@dataclass
class OpenSignal:
    article_id: str
    signal_type: str
    value: str
    context_quote: str
    label: str = "[OSINT ONLY: NOT VERIFIED BY TIER 1]"


@dataclass
class GateInput:
    report_type: str
    period_start: str
    period_end: str
    tier1_data: dict = field(default_factory=dict)
    osint_articles: list = field(default_factory=list)
    prior_results: dict = field(default_factory=dict)


@dataclass
class GateResult:
    gate_id: str
    status: str
    payload: dict
    halt_reason: str | None = None
    escape_type: str | None = None
    awaiting_clearance: bool = True
