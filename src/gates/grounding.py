"""Deterministic source-grounding for the gate framework.

This is the anti-hallucination primitive the framework was missing: instead of
comparing a report's fields to *other report fields* (internal consistency) or to
keyword blocklists, these functions verify that each concrete claim in an
AI-generated report actually **resolves to a real source record**.

Everything here is pure Python — no LLM, no network — so it can catch fabrications
autonomously (no human in the loop) and is fully unit-testable. The design is:

1. `build_source_index(tier1_data, osint_articles)` — index the raw collected data
   (CVE ids, actor names, a lowercased text blob) with no interpretation.
2. `verify_report_grounding(report, index)` — for every CVE, actor, and named
   victim in the report, check it appears in the source; unresolved -> a finding.
3. `rederive_statistics(report)` — recompute the headline metrics from the report's
   own arrays and flag mismatches (kept deterministic; complements #2).

Findings are returned as plain strings (Track-A style) so callers (Gate 6) can
fold them into the block/pass decision.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# Tokens worth matching an actor/org name on: alphanumeric runs of 4+ chars, plus
# any ALLCAPS/alnum designator like "APT29" / "FIN7" / "TA505".
_TOKEN_RE = re.compile(r"[A-Za-z0-9]{4,}|[A-Z]{2,}\d{1,4}|[A-Z]+\d+")


@dataclass
class SourceIndex:
    """A read-only index of the raw collected source data."""

    cve_ids: set[str] = field(default_factory=set)  # upper-cased
    actor_names: set[str] = field(default_factory=set)  # lower-cased, from known fields
    text_blob: str = ""  # lowercased concatenation of all source text, for substring checks

    def has_cve(self, cve_id: str) -> bool:
        return bool(cve_id) and cve_id.upper() in self.cve_ids

    def mentions(self, name: str) -> bool:
        """True if a name is grounded in the source.

        Grounded means: the whole (normalized) name appears in the source text, OR
        it matches a known actor name, OR at least one distinctive token of it (4+
        chars, or an APT-style designator) appears in the source text. The token
        fallback tolerates name normalization ("Cozy Bear (APT29)" vs "APT29")
        while still rejecting names with no source footprint at all.
        """
        norm = (name or "").strip().lower()
        if not norm:
            return True  # nothing to verify
        if norm in self.text_blob or norm in self.actor_names:
            return True
        tokens = {t.lower() for t in _TOKEN_RE.findall(name) if t.lower() not in _STOPWORDS}
        return any(tok in self.text_blob or tok in self.actor_names for tok in tokens)


# Common words that must not, on their own, make a fabricated name look "grounded".
_STOPWORDS = {
    "group",
    "team",
    "gang",
    "actor",
    "threat",
    "gmbh",
    "corp",
    "corporation",
    "company",
    "limited",
    "inc",
    "llc",
    "ltd",
    "the",
    "and",
    "for",
    "with",
}


def _iter_records(tier1_data: dict) -> list[dict]:
    records: list[dict] = []
    for value in (tier1_data or {}).values():
        if isinstance(value, list):
            records.extend(r for r in value if isinstance(r, dict))
    return records


def build_source_index(tier1_data: dict, osint_articles: list | None = None) -> SourceIndex:
    """Index the raw collected source data (tier1_data + OSINT) with no interpretation."""
    idx = SourceIndex()
    text_parts: list[str] = []

    records = _iter_records(tier1_data)
    for rec in records:
        # CVE ids: from explicit fields and from any text in the record.
        for key in ("cve_id",):
            v = rec.get(key)
            if isinstance(v, str):
                idx.cve_ids.update(m.upper() for m in _CVE_RE.findall(v))
        for v in rec.get("cve_ids") or []:
            if isinstance(v, str):
                idx.cve_ids.update(m.upper() for m in _CVE_RE.findall(v))
        # Actor names: known fields.
        for key in ("actor_name", "threat_actor"):
            v = rec.get(key)
            if isinstance(v, str) and v.strip() and v.strip().lower() not in {"unknown", "n/a", ""}:
                idx.actor_names.add(v.strip().lower())

    # OSINT articles contribute victim/company/actor text (titles + summaries + urls).
    osint_records: list[dict] = []
    for art in osint_articles or []:
        if isinstance(art, dict):
            osint_records.append(art)

    # Text blob: serialize every source record so substring checks see all fields
    # (descriptions, summaries, article titles, victim names in free text, etc.).
    for rec in records + osint_records:
        text_parts.append(json.dumps(rec, default=str))
    idx.text_blob = " ".join(text_parts).lower()

    # Any CVE mentioned anywhere in the source text is grounded, even if not in a
    # dedicated field (e.g. an Intel471 report body).
    idx.cve_ids.update(m.upper() for m in _CVE_RE.findall(idx.text_blob))

    return idx


def verify_report_grounding(report: dict, index: SourceIndex) -> list[str]:
    """Return a finding for every report claim that does not resolve to a source record.

    Checks:
    - Every ``cve_analysis[].cve_id`` must exist in the source (exact token; strong).
    - Every ``apt_activity[].actor_name`` must be grounded in the source.
    - Every ``industry_incidents[].organization`` (named victim) must appear in the source.
    """
    findings: list[str] = []

    for cve in report.get("cve_analysis") or []:
        if not isinstance(cve, dict):
            continue
        cve_id = str(cve.get("cve_id", "")).strip()
        if cve_id and not index.has_cve(cve_id):
            findings.append(f"Ungrounded CVE: {cve_id} appears in the report but not in any source record")

    for apt in report.get("apt_activity") or []:
        if not isinstance(apt, dict):
            continue
        actor = str(apt.get("actor_name", "")).strip()
        if actor and actor.lower() not in {"unknown", "n/a", "unattributed"} and not index.mentions(actor):
            findings.append(f"Ungrounded threat actor: '{actor}' is not present in any source record")

    for incident in report.get("industry_incidents") or []:
        if not isinstance(incident, dict):
            continue
        org = str(incident.get("organization", "")).strip()
        if org and org.lower() not in {"unknown", "n/a", "undisclosed", "unnamed"} and not index.mentions(org):
            findings.append(f"Ungrounded incident victim: '{org}' is not present in any source record")

    return findings


def rederive_statistics(report: dict) -> list[str]:
    """Recompute the headline metrics from the report's own arrays and flag mismatches.

    This is internal-consistency (report vs report), kept deterministic and separate
    from source grounding above. Only fires when a statistics block is present.
    """
    findings: list[str] = []
    stats = report.get("statistics") or {}
    if not isinstance(stats, dict) or not stats:
        return findings

    def _count(key: str) -> int:
        return sum(1 for x in (report.get(key) or []) if isinstance(x, dict))

    checks = {
        "threat_actors": _count("apt_activity"),
        "peer_incidents": _count("industry_incidents"),
        "total_cves": _count("cve_analysis"),
    }
    for metric, actual in checks.items():
        if metric in stats and isinstance(stats[metric], int) and stats[metric] != actual:
            findings.append(f"Statistic '{metric}' = {stats[metric]} but the report contains {actual}")

    return findings
