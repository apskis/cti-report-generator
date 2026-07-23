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
    records_by_id: dict[str, dict] = field(default_factory=dict)  # stable record ids -> raw records

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

    def get_record(self, record_id: str) -> dict | None:
        """Retrieve a source record by its stable ID."""
        return self.records_by_id.get(record_id)

    def record_contains_entity(self, record_id: str, entity: str) -> bool:
        """Check if a specific record contains the given entity (CVE, actor, victim name).

        Used for Tier 2 LLM citation validation: the model must cite a record that
        actually supports its claim.
        """
        rec = self.get_record(record_id)
        if not rec:
            return False
        rec_text = json.dumps(rec, default=str).lower()
        entity_norm = entity.strip().lower()
        return entity_norm in rec_text


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


def _iter_records(tier1_data: dict) -> list[tuple[str, dict]]:
    """Yield (source_key, record) pairs with stable IDs for each record."""
    records: list[tuple[str, dict]] = []
    for source_key, value in (tier1_data or {}).items():
        if isinstance(value, list):
            for idx, rec in enumerate(value):
                if isinstance(rec, dict):
                    # Stable ID: source_key + sequential index
                    record_id = f"{source_key}_{idx}"
                    records.append((record_id, rec))
    return records


def build_source_index(tier1_data: dict, osint_articles: list | None = None) -> SourceIndex:
    """Index the raw collected source data (tier1_data + OSINT) with no interpretation."""
    idx = SourceIndex()
    text_parts: list[str] = []

    records = _iter_records(tier1_data)
    for record_id, rec in records:
        # Store with stable ID
        idx.records_by_id[record_id] = rec

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
    osint_records: list[tuple[str, dict]] = []
    for idx_num, art in enumerate(osint_articles or []):
        if isinstance(art, dict):
            osint_id = f"osint_{idx_num}"
            idx.records_by_id[osint_id] = art
            osint_records.append((osint_id, art))

    # Text blob: serialize every source record so substring checks see all fields
    # (descriptions, summaries, article titles, victim names in free text, etc.).
    for _record_id, rec in list(records) + osint_records:
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

    # Quarterly-shape grounding: the strategic report carries named victims inside
    # ``breach_landscape.incidents_by_type[].notable_example`` and named actors under
    # ``geopolitical_threats[].name`` — neither of which the weekly keys above touch.
    findings.extend(_verify_quarterly_grounding(report, index))

    return findings


# Victim/actor placeholders that must not be treated as a concrete, groundable name.
_GENERIC_ENTITY_PHRASES = {
    "",
    "n/a",
    "na",
    "none",
    "unknown",
    "undisclosed",
    "unnamed",
    "multiple",
    "multiple organizations",
    "multiple organisations",
    "multiple victims",
    "multiple companies",
    "multiple firms",
    "various",
    "various organizations",
    "several",
    "several organizations",
    "numerous",
    "not disclosed",
    "not specified",
    "not applicable",
    "unspecified",
    "confidential",
    "anonymous",
    "redacted",
}


def _extract_victim_name(notable_example: str) -> str:
    """Extract the named victim from a ``notable_example`` string.

    The strategic schema renders these as ``"<Company>: <what happened>"``; the
    victim is the segment before the first colon. Returns an empty string when the
    entry names no specific, groundable company.
    """
    text = (notable_example or "").strip()
    if not text:
        return ""
    candidate = text.split(":", 1)[0].strip() if ":" in text else text
    # Trailing parentheticals like "Acme (a biotech firm)" -> "Acme".
    candidate = re.sub(r"\s*\(.*?\)\s*$", "", candidate).strip()
    if candidate.lower() in _GENERIC_ENTITY_PHRASES:
        return ""
    # A whole-sentence "notable_example" with no colon and many words is a
    # description, not a company name — don't try to ground it as an entity.
    if ":" not in text and len(candidate.split()) > 6:
        return ""
    return candidate


def _verify_quarterly_grounding(report: dict, index: SourceIndex) -> list[str]:
    """Ground the quarterly report's named victims and geopolitical actors.

    - Every ``incidents_by_type[].notable_example`` victim (accepted at the top level
      or nested under ``breach_landscape``) must appear in the source.
    - Every ``geopolitical_threats[].name`` actor must be grounded in the source.
    """
    findings: list[str] = []

    breach = report.get("breach_landscape")
    breach = breach if isinstance(breach, dict) else {}
    incidents = breach.get("incidents_by_type") or report.get("incidents_by_type") or []
    for incident in incidents:
        if not isinstance(incident, dict):
            continue
        victim = _extract_victim_name(str(incident.get("notable_example", "")))
        if victim and not index.mentions(victim):
            findings.append(
                f"Ungrounded breach victim: '{victim}' (in notable_example) is not present in any source record"
            )

    geo = report.get("geopolitical_threats")
    if isinstance(geo, list):
        geo_entries = geo
    elif isinstance(geo, dict):
        geo_entries = list(geo.values())
    else:
        geo_entries = []
    for entry in geo_entries:
        if not isinstance(entry, dict):
            continue
        actor = str(entry.get("name") or entry.get("actor") or "").strip()
        if actor and actor.lower() not in _GENERIC_ENTITY_PHRASES and not index.mentions(actor):
            findings.append(
                f"Ungrounded geopolitical actor: '{actor}' is not present in any source record"
            )

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


def normalize_whitespace(text: str) -> str:
    """Normalize whitespace for quote matching: collapse runs, lowercase, strip."""
    return re.sub(r"\s+", " ", text.lower().strip())


def validate_quote_in_source(quote: str, index: SourceIndex) -> bool:
    """Check if the exact quote appears anywhere in the source corpus (normalized).

    Corpus-wide check: used for the report's own threat-finding quote-back (the
    finding does not name a specific source record). For an LLM citation that names
    a specific ``source_record_id``, use ``validate_quote_in_record`` instead so the
    quote is checked against the cited record, not merely somewhere in the corpus.
    """
    if not quote or not quote.strip():
        return False
    norm_quote = normalize_whitespace(quote)
    norm_blob = normalize_whitespace(index.text_blob)
    return norm_quote in norm_blob


def validate_quote_in_record(quote: str, record_id: str, index: SourceIndex) -> bool:
    """Check that the exact quote appears in the SPECIFIC cited record (normalized).

    This is the strong form of Tier 2 citation validation: a model must not be able
    to cite record A while quoting text that only exists in record B. Returns False
    if the record is unknown or the quote is empty.
    """
    if not quote or not quote.strip():
        return False
    rec = index.get_record(record_id)
    if rec is None:
        return False
    norm_quote = normalize_whitespace(quote)
    norm_rec = normalize_whitespace(json.dumps(rec, default=str))
    return norm_quote in norm_rec
