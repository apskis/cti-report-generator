"""Gate 6: Adversarial review of the Gate 5 draft.

Three layers:
1. Deterministic checks (Tier 1): scan the Gate 5 report payload for known fence
   violations (filler phrases, em dashes, Open Signal values inside Threat Findings,
   OSINT-only citations, omitted Coverage Gaps, source grounding, statistics).
2. LLM adversary (Tier 2): with the real adapter (GATE_LLM_MODE=azure), require
   structured JSON claims that cite source_record_id + quote, then re-validate
   each citation in Python against the SourceIndex.
3. Multi-sample voting (Tier 2): run the adversarial pass N times (configurable,
   default 3) and majority-vote each finding for consistency.

Track A findings block publish. Track B findings can be corrected in place.

Report-type specific checks:
- Quarterly Strategic: threat_findings, open_signals_appendix, coverage_gaps
- Weekly Tactical: cve_analysis, apt_activity, industry_incidents, statistics
"""

from __future__ import annotations

import json
import os
import re

from .escape_handler import detect_gate_bleed
from .grounding import (
    build_source_index,
    rederive_statistics,
    validate_quote_in_record,
    validate_quote_in_source,
    verify_report_grounding,
)
from .llm_adapter import AzureOpenAILLMClient
from .models import GateInput, GateResult
from .prompts import GATE_6_PROMPT_TEMPLATE, SYSTEM_PROMPT_GATE_6

_FILLER_PHRASES = [
    "it is important to note",
    "this highlights",
    "in conclusion",
    "as mentioned earlier",
    "overall,",
    "based on common threat intelligence patterns",
]


def _scan_filler(text: str) -> list[str]:
    found: list[str] = []
    low = text.lower()
    for phrase in _FILLER_PHRASES:
        if phrase in low:
            found.append(phrase)
    return found


def _scan_em_dashes(text: str) -> int:
    return text.count("—")  # em dash


def _scan_open_signal_leakage(report: dict) -> list[str]:
    """A Track A failure: an Open Signal value appearing inside Threat Findings.

    By Gate 4 construction, a value in open_signals_appendix has NO Tier 1 backing.
    Its presence in threat_findings is leakage regardless of the source list.
    """
    open_values = {item.get("value") for item in report.get("open_signals_appendix", {}).get("items", [])}
    if not open_values:
        return []
    leaked: list[str] = []
    for finding in report.get("threat_findings", []):
        if finding.get("value") in open_values:
            leaked.append(f"Open Signal value '{finding.get('value')}' appears in Threat Findings")
    return leaked


def _scan_osint_only_citations(report: dict) -> list[str]:
    """A Track A failure: a Threat Findings claim citing only an OSINT article."""
    violations: list[str] = []
    for finding in report.get("threat_findings", []):
        sources = finding.get("sources") or []
        if not sources:
            violations.append(f"Threat Finding '{finding.get('value')}' has no sources at all")
            continue
        tier1_present = any(s and not str(s).startswith("OSINT") for s in sources)
        if not tier1_present:
            violations.append(f"Threat Finding '{finding.get('value')}' is cited only from OSINT: {sources}")
    return violations


def _scan_gap_omissions(report: dict, gate4_gaps: list[str]) -> list[str]:
    surfaced = set(report.get("coverage_gaps") or [])
    return [g for g in gate4_gaps if g not in surfaced]


def _scan_osint_overuse(report: dict, gate1b_article_count: int) -> list[str]:
    """
    Track B warning: Check if too many OSINT sources are being cited.

    We collect ~30 OSINT articles but should only cite the ones actually used.
    If more than 15 are cited, likely the AI is being too inclusive.
    """
    violations: list[str] = []

    # Check in resources section
    resources = report.get("resources", [])
    osint_resource_count = sum(1 for r in resources if isinstance(r, dict) and "osint" in str(r).lower())

    if osint_resource_count > 15:
        violations.append(
            f"OSINT overuse: {osint_resource_count} OSINT sources cited out of {gate1b_article_count} collected. "
            f"Should be selective (aim for 5-10 max). Only cite articles actually used in analysis."
        )

    return violations


def _scan_disabled_sources_cited(report: dict, gate1_sources: list) -> list[str]:
    """
    Track B warning: Check if disabled sources are listed in resources.

    If a source returned 0 records or has status GAP, it shouldn't be in the report.
    """
    violations: list[str] = []

    # Get sources that had no data
    disabled_sources = [
        src.source_name
        for src in gate1_sources
        if src.records_returned == 0 or "GAP" in src.status or "DISABLED" in src.status
    ]

    # Check if any of these appear in the report's resources
    resources_text = str(report.get("resources", [])).lower()
    for source in disabled_sources:
        if source.lower() in resources_text:
            violations.append(
                f"Disabled/empty source cited: '{source}' returned 0 records but appears in resources section"
            )

    return violations


def _scan_api_source_citations(report: dict) -> list[str]:
    """
    Track B warning: Check if API sources are properly cited in CVE and APT analysis.

    Weekly tactical reports should have source_citations arrays showing which APIs
    provided intelligence for each finding.
    """
    violations: list[str] = []

    # Check CVE analysis for source citations
    cve_analysis = report.get("cve_analysis", [])
    if cve_analysis:
        missing_citations = []
        for cve in cve_analysis:
            if isinstance(cve, dict):
                cve_id = cve.get("cve_id", "Unknown")
                citations = cve.get("source_citations", [])
                if not citations or not isinstance(citations, list):
                    missing_citations.append(cve_id)

        if missing_citations and len(missing_citations) > len(cve_analysis) * 0.5:
            violations.append(
                f"{len(missing_citations)}/{len(cve_analysis)} CVEs missing source_citations array. "
                f"Should track which APIs (NVD, CISA KEV, Intel471, CrowdStrike) provided each CVE."
            )

    # Check APT activity for source citations
    apt_activity = report.get("apt_activity", [])
    if apt_activity:
        missing_citations = []
        for apt in apt_activity:
            if isinstance(apt, dict):
                actor = apt.get("actor", "Unknown")
                citations = apt.get("source_citations", [])
                if not citations or not isinstance(citations, list):
                    missing_citations.append(actor)

        if missing_citations and len(missing_citations) > len(apt_activity) * 0.5:
            violations.append(
                f"{len(missing_citations)}/{len(apt_activity)} threat actors missing source_citations array. "
                f"Should track which APIs (Intel471, CrowdStrike) provided each actor's intelligence."
            )

    return violations


def _scan_statistics_accuracy(report: dict) -> list[str]:
    """
    Track A violation: Check if statistics match actual data counts.

    Weekly tactical reports have metric boxes - these should accurately reflect
    the actual counts in the data.
    """
    violations: list[str] = []

    stats = report.get("statistics", {})
    if not stats:
        return violations

    # Check threat actors count
    apt_activity = report.get("apt_activity", [])
    reported_actors = stats.get("threat_actors", 0)
    actual_actors = len([apt for apt in apt_activity if isinstance(apt, dict)])

    if reported_actors != actual_actors:
        violations.append(f"Threat Actors metric mismatch: reported {reported_actors}, actual {actual_actors}")

    # Check exploited CVEs count
    cve_analysis = report.get("cve_analysis", [])
    reported_exploited = stats.get("exploited_cves", 0)
    actual_exploited = len(
        [
            cve
            for cve in cve_analysis
            if isinstance(cve, dict)
            and (cve.get("actively_exploited") or cve.get("targeted_by_actors") or cve.get("in_cisa_kev"))
        ]
    )

    if reported_exploited != actual_exploited:
        violations.append(f"Exploited CVEs metric mismatch: reported {reported_exploited}, actual {actual_exploited}")

    # Check peer incidents count
    reported_incidents = stats.get("peer_incidents", 0)
    industry_incidents = report.get("industry_incidents", [])
    actual_incidents = len(industry_incidents) if industry_incidents else 0

    if reported_incidents != actual_incidents:
        violations.append(f"Peer Incidents metric mismatch: reported {reported_incidents}, actual {actual_incidents}")

    return violations


def _scan_exploited_cve_evidence(report: dict) -> list[str]:
    """
    Track B warning: Check if CVEs marked as exploited have proper evidence.

    CVEs with actively_exploited=true should have exploited_by field populated.
    """
    violations: list[str] = []

    cve_analysis = report.get("cve_analysis", [])
    missing_evidence = []

    for cve in cve_analysis:
        if not isinstance(cve, dict):
            continue

        cve_id = cve.get("cve_id", "Unknown")
        actively_exploited = cve.get("actively_exploited", False)
        exploited_by = cve.get("exploited_by", "")

        if actively_exploited and not exploited_by:
            missing_evidence.append(cve_id)

    if missing_evidence:
        violations.append(
            f"{len(missing_evidence)} CVE(s) marked actively_exploited but missing exploited_by evidence: "
            f"{', '.join(missing_evidence[:5])}"
        )

    return violations


def _scan_industry_incidents_quality(report: dict) -> tuple[list[str], list[str]]:
    """
    Check if industry incidents are structured and specific.

    Returns: (track_a_violations, track_b_violations)

    Track A (blocking): Vague/generic organization names
    Track B (quality): Missing citations or structure issues

    NOTE: Empty industry_incidents array is acceptable - some weeks may have no named victims.
    """
    track_a = []
    track_b = []

    industry_incidents = report.get("industry_incidents", [])
    osint_sources = report.get("osint_sources_used", [])

    # Empty incidents array is OK - don't penalize for quiet weeks
    if not industry_incidents:
        return track_a, track_b

    # Track B: Check if AI provided structure but no actual data
    if osint_sources and not industry_incidents:
        track_b.append(
            f"AI provided {len(osint_sources)} OSINT sources but no structured industry_incidents array. "
            f"Report had to fall back to unreliable keyword extraction. AI should explicitly identify breaches."
        )

    # Track A: Check for vague/generic organization names (BLOCKING)
    vague_keywords = [
        "sector",
        "industry",
        "healthcare",
        "biotech",
        "manufacturing",
        "life sciences",
        "health care",
        "companies",
        "organizations",
        "databreach+",
        "site operated by",
        "unnamed",
        "multiple",
        "various",
        "us law firms",
        "medical facilities",
        "no named",
        "not reported",
    ]

    vague_incidents = []
    for inc in industry_incidents:
        if isinstance(inc, dict):
            org = inc.get("organization", "").lower()
            # Check if organization name contains vague keywords
            if any(keyword in org for keyword in vague_keywords):
                vague_incidents.append(inc.get("organization", "Unknown"))
            # Or if it's suspiciously generic (very long or contains parenthetical descriptions)
            elif len(org.split()) > 6 or ("(named" in org or "(site" in org):
                vague_incidents.append(inc.get("organization", "Unknown"))

    if vague_incidents:
        track_a.append(
            f"{len(vague_incidents)} incident(s) have vague/generic organization names: "
            f"{', '.join(vague_incidents[:3])}. Must be SPECIFIC named organizations like 'Morrison & Foerster LLP', not sectors. "
            f"If no specific victims this week, return empty industry_incidents array."
        )

    # Track B: Check if OSINT incidents have proper citation numbers (quality check)
    missing_citations = []
    for inc in industry_incidents:
        if isinstance(inc, dict):
            source = inc.get("source", "")
            org = inc.get("organization", "")
            # Only OSINT incidents need osint_citation_number, Intel471 doesn't
            # Skip if this is a placeholder/error entry
            if "Intel471" not in source and not inc.get("osint_citation_number") and "no named" not in org.lower():
                missing_citations.append(org)

    if missing_citations:
        track_b.append(
            f"{len(missing_citations)} OSINT incident(s) missing osint_citation_number: "
            f"{', '.join(missing_citations[:3])}"
        )

    return track_a, track_b


def _scan_narrative_cohesion(report: dict, gate2_iocs: list, report_type: str = "WEEKLY") -> list[str]:
    """
    Check for narrative cohesion issues between executive summary and detailed sections.

    Track A violations:
    - CVEs mentioned in executive summary but not in CVE analysis section
    - CVEs in analysis not mentioned anywhere in narrative

    NOTE: For weekly tactical reports (threat intelligence focused), we no longer validate
    against "detected in environment" since there is no environment scan data. CVEs are threat intel only.
    """
    violations: list[str] = []

    # Extract CVEs from executive summary - handle both string and dict formats
    exec_summary = report.get("executive_summary", "")
    if isinstance(exec_summary, dict):
        # Sometimes it's a dict with nested content
        exec_summary = str(exec_summary)
    elif not isinstance(exec_summary, str):
        # If it's something else, convert to string
        exec_summary = str(exec_summary) if exec_summary else ""

    # Regex to find CVE IDs in text
    import re

    summary_cves = set(re.findall(r"CVE-\d{4}-\d{4,}", exec_summary, re.IGNORECASE))

    # For weekly tactical reports: Compare against CVE analysis (threat intel CVEs)
    # For quarterly: Compare against threat findings
    if report_type.upper() == "WEEKLY":
        # Extract CVEs from cve_analysis section (threat intelligence CVEs)
        analysis_cves = set()
        for cve in report.get("cve_analysis", []):
            if isinstance(cve, dict):
                cve_id = cve.get("cve_id", "")
                if cve_id:
                    analysis_cves.add(cve_id.upper())

        # Check: CVEs in summary should appear in CVE analysis table
        orphaned_summary_cves = summary_cves - analysis_cves
        if orphaned_summary_cves:
            # For weekly reports, this is informational only - CVEs from threat intel may be mentioned
            # without full analysis. Only flag if it's excessive (>3 orphaned)
            if len(orphaned_summary_cves) > 3:
                violations.append(
                    f"{len(orphaned_summary_cves)} CVEs mentioned in executive summary but not in CVE analysis table. "
                    f"If these are industry threats, consider adding them to the analysis or noting they're external."
                )
    else:
        # Quarterly report: Use threat_findings
        finding_cves = set()
        for finding in report.get("threat_findings", []):
            value = finding.get("value", "")
            if isinstance(value, str) and value.startswith("CVE-"):
                finding_cves.add(value.upper())

        # Check: CVEs in summary should either be in findings or explicitly noted as external threats
        orphaned_summary_cves = summary_cves - finding_cves
        if orphaned_summary_cves:
            for cve in orphaned_summary_cves:
                violations.append(f"CVE {cve} mentioned in executive summary but missing from threat findings table")

    return violations


def _scan_osint_citations(report: dict) -> list[str]:
    """
    Check that OSINT sources used have inline citations in the text.

    Track B violations (quality issue, not blocking):
    - OSINT articles listed but never referenced in narrative or incidents table
    - Claims that should cite OSINT but don't
    """
    violations: list[str] = []

    osint_sources = report.get("osint_sources_used", [])
    if not osint_sources:
        return violations

    # Extract executive summary - handle both string and dict formats
    exec_summary = report.get("executive_summary", "")
    if isinstance(exec_summary, dict):
        exec_summary = str(exec_summary)
    elif not isinstance(exec_summary, str):
        exec_summary = str(exec_summary) if exec_summary else ""

    # Check if any OSINT sources are cited inline (look for superscript numbers or [1] style refs)
    import re

    has_exec_citations = bool(re.search(r"\[\d+\]|¹|²|³|⁴|⁵", exec_summary))

    # Check if OSINT is cited in industry incidents table
    industry_incidents = report.get("industry_incidents", [])
    osint_incidents_count = sum(
        1 for inc in industry_incidents if isinstance(inc, dict) and inc.get("osint_citation_number")
    )

    # If OSINT sources are listed, they should appear SOMEWHERE
    if osint_sources and not has_exec_citations and osint_incidents_count == 0:
        violations.append(
            f"{len(osint_sources)} OSINT sources listed but NOT cited anywhere. "
            f"OSINT must be referenced in executive summary [1][2] OR industry incidents table. "
            f"If not using an article, don't list it in osint_sources_used."
        )
    elif osint_sources and not has_exec_citations and osint_incidents_count < len(osint_sources):
        violations.append(
            f"{len(osint_sources)} OSINT sources listed but only {osint_incidents_count} cited in incidents table. "
            f"Missing citations in executive summary. Add [1], [2] style references."
        )

    return violations


def _scan_uncited_findings(report: dict) -> list[str]:
    return [
        f"Finding '{f.get('value')}' has no Gate 4 citation"
        for f in report.get("threat_findings", [])
        if not f.get("citation")
    ]


def _collect_prior_gate_blockers(prior_results: dict) -> list[str]:
    """Gather blocking findings from the pre-Gate-6 reconciliation gates.

    Gate 1C surfaces ungrounded technology mentions under payload['issues']; Gates
    1E/1F surface their critical findings under payload['issues'] / payload
    ['critical_issues']. Each such finding blocks publish via Track A.
    """
    blockers: list[str] = []
    for gate_id, payload_key in (("1C", "issues"), ("1E", "issues"), ("1F", "critical_issues")):
        result = prior_results.get(gate_id)
        payload = getattr(result, "payload", None)
        if not isinstance(payload, dict):
            continue
        for item in payload.get(payload_key) or []:
            blockers.append(f"[Gate {gate_id}] {item}")
    return blockers


def _parse_llm_findings(llm_text: str) -> tuple[list[str], list[str]]:
    """Parse 'Track A findings:' and 'Track B findings:' sections from the adversarial response."""
    track_a: list[str] = []
    track_b: list[str] = []
    current: list[str] | None = None

    for line in llm_text.splitlines():
        stripped = line.strip()
        if re.match(r"^track\s*a\b", stripped, re.IGNORECASE):
            current = track_a
            continue
        if re.match(r"^track\s*b\b", stripped, re.IGNORECASE):
            current = track_b
            continue
        if re.match(r"^overall\b", stripped, re.IGNORECASE):
            current = None
            continue
        if not stripped or current is None:
            continue
        # Strip bullet/numbered prefixes
        cleaned = re.sub(r"^[\-\*•\d.)\s]+", "", stripped)
        if cleaned and cleaned.lower() not in {"none", "n/a", "[]"}:
            current.append(cleaned)

    return track_a, track_b


def _is_structured_json_response(llm_text: str) -> bool:
    """Check if the LLM returned structured JSON (Tier 2 mode) vs prose (default mode)."""
    stripped = llm_text.strip()
    # Must start with { and contain track_a_findings or track_b_findings keys
    if not stripped.startswith("{"):
        return False
    try:
        parsed = json.loads(stripped)
        return isinstance(parsed, dict) and ("track_a_findings" in parsed or "track_b_findings" in parsed)
    except (json.JSONDecodeError, ValueError):
        return False


def _validate_structured_findings(llm_json: dict, source_index, report: dict) -> tuple[list[str], list[str]]:
    """Tier 2: Validate structured JSON findings from the real LLM adapter.

    For each claim with a source_record_id and quote, re-check them in Python:
    - Record ID must exist in the SourceIndex
    - Quote must appear in THAT specific record (not merely somewhere in the corpus)
    - If validation fails, treat it as a Track A finding (BLOCK)

    This implements the core Tier 2 principle: never trust the model's word,
    always re-validate against the actual source data.
    """
    track_a: list[str] = []
    track_b: list[str] = []

    # Process Track A findings
    for finding in llm_json.get("track_a_findings", []):
        if not isinstance(finding, dict):
            continue

        claim = finding.get("claim", "")
        verdict = finding.get("verdict", "PASS")
        record_id = finding.get("source_record_id")
        quote = finding.get("quote")

        # If the LLM marked it as BLOCK and provided citations, validate them
        if verdict == "BLOCK" and record_id and quote:
            # Re-validate: does the record exist?
            rec = source_index.get_record(record_id)
            if not rec:
                track_a.append(
                    f"[LLM CITATION INVALID] Claim: '{claim}' cites nonexistent record '{record_id}' (BLOCK)"
                )
                continue

            # Re-validate: does the quote appear in THAT cited record specifically?
            if not validate_quote_in_record(quote, record_id, source_index):
                track_a.append(
                    f"[LLM QUOTE UNVERIFIABLE] Claim: '{claim}' cites record '{record_id}' "
                    f"with quote '{quote[:50]}...' but quote not found in that record (BLOCK)"
                )
                continue

            # Both validations passed: trust the LLM's assessment
            track_a.append(f"[LLM] {claim}")
        elif verdict == "BLOCK":
            # LLM said BLOCK but didn't provide citations (pre-Tier-2 style)
            track_a.append(f"[LLM] {claim}")

    # Process Track B findings (no citation validation needed for warnings)
    for finding in llm_json.get("track_b_findings", []):
        if not isinstance(finding, dict):
            continue
        claim = finding.get("claim", "")
        if claim:
            track_b.append(f"[LLM] {claim}")

    return track_a, track_b


def _validate_threat_finding_quotes(report: dict, source_index) -> list[str]:
    """Tier 2 #6: Quote-back challenge for each Threat Finding.

    For every threat finding in the report, require an exact source quote that
    supports it. String-match the quote back into the source corpus. Unverifiable
    quotes are Track A (BLOCK).

    NOTE: This is a separate pass from the LLM structured validation above. This
    directly validates the report's threat_findings array, whereas the LLM pass
    validates the adversarial review's own claims about the report.
    """
    findings: list[str] = []

    for tf in report.get("threat_findings", []):
        if not isinstance(tf, dict):
            continue

        value = tf.get("value", "")
        quote = tf.get("supporting_quote")  # Expected field in threat_findings

        # If a quote is provided, validate it
        if quote and not validate_quote_in_source(quote, source_index):
            findings.append(
                f"Threat Finding '{value}' has unverifiable quote: '{quote[:80]}...' not found in source corpus (BLOCK)"
            )
        # If no quote provided, that's a structural issue but not necessarily a Tier 2 failure
        # (the deterministic checks already flag uncited findings)

    return findings


def _run_adversarial_pass(llm_client, source_index, report: dict, draft_text: str) -> tuple[list[str], list[str], str]:
    """Execute a single adversarial review pass (for multi-sampling).

    Returns (track_a_findings, track_b_findings, raw_llm_text) for this pass.
    """
    user_prompt = GATE_6_PROMPT_TEMPLATE.format(gate5_output=draft_text or str(report))
    llm_text = llm_client.complete(SYSTEM_PROMPT_GATE_6, user_prompt)

    detect_gate_bleed(llm_text, expected_gate_id="6")

    # Check if this is a structured JSON response (Tier 2) or prose (default)
    if _is_structured_json_response(llm_text):
        # Tier 2 path: parse JSON and validate citations
        try:
            llm_json = json.loads(llm_text.strip())
            track_a, track_b = _validate_structured_findings(llm_json, source_index, report)
            return track_a, track_b, llm_text
        except (json.JSONDecodeError, ValueError) as e:
            # JSON parse failed; treat as a finding
            return ([f"LLM returned malformed JSON: {e}"], [], llm_text)
    else:
        # Default prose path (Tier 1 / StructuralLLMClient)
        track_a, track_b = _parse_llm_findings(llm_text)
        return track_a, track_b, llm_text


def _majority_vote_findings(all_passes: list[tuple[list[str], list[str]]]) -> tuple[list[str], list[str], list[str]]:
    """Tier 2 #7: Multi-sample voting across N adversarial passes.

    For each unique finding, count how many passes flagged it. Only findings that
    appear in the majority (>50%) of passes are included in the final Track A/B.
    Returns (track_a_consensus, track_b_consensus, disagreements).

    Disagreements are logged but do not block (they're informational for humans).
    """
    if not all_passes:
        return [], [], []

    n_samples = len(all_passes)
    threshold = n_samples // 2 + 1  # Majority

    # Normalize findings: strip [LLM] prefix and extra whitespace for deduplication
    def normalize(finding: str) -> str:
        return re.sub(r"^\[LLM\]\s*", "", finding.strip())

    # Count occurrences
    track_a_counts: dict[str, int] = {}
    track_b_counts: dict[str, int] = {}

    for track_a, track_b in all_passes:
        for finding in track_a:
            norm = normalize(finding)
            track_a_counts[norm] = track_a_counts.get(norm, 0) + 1
        for finding in track_b:
            norm = normalize(finding)
            track_b_counts[norm] = track_b_counts.get(norm, 0) + 1

    # Majority vote
    track_a_consensus = [f for f, count in track_a_counts.items() if count >= threshold]
    track_b_consensus = [f for f, count in track_b_counts.items() if count >= threshold]

    # Disagreements: findings that appeared but didn't reach threshold
    disagreements = []
    for finding, count in track_a_counts.items():
        if count < threshold:
            disagreements.append(f"Track A split vote ({count}/{n_samples}): {finding}")
    for finding, count in track_b_counts.items():
        if count < threshold:
            disagreements.append(f"Track B split vote ({count}/{n_samples}): {finding}")

    return track_a_consensus, track_b_consensus, disagreements


def run(input: GateInput, llm_client, report_type: str) -> GateResult:
    g1 = input.prior_results.get("1")
    g1b = input.prior_results.get("1B")
    g2 = input.prior_results.get("2")
    g4 = input.prior_results.get("4")
    g5 = input.prior_results.get("5")
    if g5 is None:
        raise RuntimeError("Gate 6 requires Gate 5 GateResult in input.prior_results['5']")

    report = g5.payload.get("report", {})
    draft_text = g5.payload.get("draft_text", "")
    gate4_gaps = (g4.payload.get("assembly", {}).get("coverage_gaps") or []) if g4 else []
    gate2_iocs = (g2.payload.get("iocs") or []) if g2 else []
    gate1b_article_count = len(g1b.payload.get("osint_articles") or []) if g1b else 30
    gate1_sources = (g1.payload.get("tier1_sources") or []) if g1 else []

    track_a: list[str] = []
    track_b: list[str] = []

    # -------------------------------------------------------------------------
    # TIER 1: Deterministic checks (unchanged; always active)
    # -------------------------------------------------------------------------

    # Existing Track A checks
    track_a.extend(_scan_open_signal_leakage(report))
    track_a.extend(_scan_osint_only_citations(report))
    track_a.extend(_scan_uncited_findings(report))

    # Deterministic source grounding (Tier 1 anti-hallucination): verify every
    # concrete claim in the report resolves to a real collected source record, and
    # re-derive the headline statistics from the report's own arrays. Unlike the
    # internal-consistency scanners above, this catches internally-consistent
    # fabrications — the failure mode no other gate covered. Blocking (Track A).
    source_index = build_source_index(input.tier1_data, input.osint_articles)
    track_a.extend(verify_report_grounding(report, source_index))
    track_a.extend(rederive_statistics(report))

    # Fold blocking findings from the reconciliation gates that run before Gate 6
    # (1C tech coherence, 1E AI quality, 1F source audit) into Track A. Those gates
    # are non-halting by design so the pipeline reaches this adversarial review with
    # all findings collected; Gate 6 is where they become a publish block.
    track_a.extend(_collect_prior_gate_blockers(input.prior_results))

    # Coverage gap validation: Different behavior for quarterly vs weekly
    # - Quarterly reports: Gaps are informational only, not blocking. Only block if AI cites empty sources.
    # - Weekly reports: Gaps are now informational (Track B) instead of blocking (Track A)
    #   This allows reports to proceed even if some sources are intentionally disabled
    if report_type.upper() == "QUARTERLY":
        # For quarterly: Gaps are informational (Track B)
        track_b.extend(f"Coverage Gap (informational): {g}" for g in _scan_gap_omissions(report, gate4_gaps))
    else:
        # For weekly: Also make gaps informational (Track B) - don't block on disabled sources
        gap_omissions = _scan_gap_omissions(report, gate4_gaps)
        if gap_omissions:
            track_b.append(
                f"{len(gap_omissions)} coverage gap(s) omitted from report (informational). "
                f"Consider documenting: {'; '.join(gap_omissions[:2])}"
            )

    # NEW: Narrative cohesion checks (Track A - blocking)
    track_a.extend(_scan_narrative_cohesion(report, gate2_iocs, report_type))

    # Existing Track B checks
    filler = _scan_filler(draft_text)
    if filler:
        track_b.extend(f"Filler phrase: '{p}'" for p in filler)
    em_count = _scan_em_dashes(draft_text)
    if em_count:
        track_b.append(f"{em_count} em dash(es) present; framework forbids em dashes")

    # NEW: OSINT citation checks (Track B - quality)
    track_b.extend(_scan_osint_citations(report))

    # NEW: OSINT overuse check (Track B - quality)
    track_b.extend(_scan_osint_overuse(report, gate1b_article_count))

    # NEW: Disabled sources check (Track B - quality)
    track_b.extend(_scan_disabled_sources_cited(report, gate1_sources))

    # NEW: API source citations check (Track B - quality)
    track_b.extend(_scan_api_source_citations(report))

    # NEW: Statistics accuracy check (Track A - blocking)
    track_a.extend(_scan_statistics_accuracy(report))

    # NEW: Exploited CVE evidence check (Track B - quality)
    track_b.extend(_scan_exploited_cve_evidence(report))

    # NEW: Industry incidents quality check (Track A + Track B)
    incidents_track_a, incidents_track_b = _scan_industry_incidents_quality(report)
    track_a.extend(incidents_track_a)
    track_b.extend(incidents_track_b)

    # -------------------------------------------------------------------------
    # TIER 2: LLM adversary with verifiable self-critique (items #5, #6, #7)
    # -------------------------------------------------------------------------

    # Tier 2 activates only with the real Azure adapter or FakeLLMClientTier2 (for tests).
    # With StructuralLLMClient, this degrades gracefully to the existing prose-parsing behavior.
    from .llm_adapter import FakeLLMClientTier2

    is_real_llm = isinstance(llm_client, (AzureOpenAILLMClient, FakeLLMClientTier2))

    # Multi-sample voting only makes sense against a real (non-deterministic) model.
    # The StructuralLLMClient stub is deterministic — N identical passes would be pure
    # wasted work — so it always runs exactly one pass.
    if is_real_llm:
        n_samples = int(os.environ.get("GATE_LLM_SAMPLES", "3"))
        n_samples = max(1, n_samples)
    else:
        n_samples = 1

    all_passes: list[tuple[list[str], list[str]]] = []
    review_text = ""
    for i in range(n_samples):
        llm_track_a, llm_track_b, raw_text = _run_adversarial_pass(llm_client, source_index, report, draft_text)
        all_passes.append((llm_track_a, llm_track_b))
        if i == 0:
            review_text = raw_text  # keep the first pass's raw adversary output for diagnostics

    # Majority vote across passes (Tier 2 #7)
    if is_real_llm and n_samples > 1:
        llm_a_consensus, llm_b_consensus, disagreements = _majority_vote_findings(all_passes)
        track_a.extend(llm_a_consensus)
        track_b.extend(llm_b_consensus)
        # Log disagreements as Track B (informational)
        if disagreements:
            track_b.append(f"Multi-sample disagreements ({n_samples} passes):")
            track_b.extend(f"  - {d}" for d in disagreements)
    else:
        # Single pass or default stub client: use first pass directly
        llm_track_a, llm_track_b = all_passes[0] if all_passes else ([], [])
        track_a.extend(llm_track_a)
        track_b.extend(llm_track_b)

    # Tier 2 #6: Quote-back challenge for Threat Findings (if real LLM)
    # This validates quotes directly in the report's threat_findings array.
    if is_real_llm:
        track_a.extend(_validate_threat_finding_quotes(report, source_index))

    # -------------------------------------------------------------------------
    # Final decision
    # -------------------------------------------------------------------------

    status = "PASS" if not track_a else "BLOCK"

    return GateResult(
        gate_id="6",
        status=status,
        payload={
            "track_a": track_a,
            "track_b": track_b,
            "review_text": review_text,  # raw adversary output from the first pass (diagnostics)
            "tier2_active": is_real_llm,
            "n_samples": n_samples,
        },
        awaiting_clearance=True,
    )
