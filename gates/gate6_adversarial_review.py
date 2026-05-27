"""Gate 6: Adversarial review of the Gate 5 draft.

Two layers:
1. Deterministic checks: scan the Gate 5 report payload for known fence
   violations (filler phrases, em dashes, Open Signal values inside
   Threat Findings, OSINT-only citations, omitted Coverage Gaps).
2. LLM adversary: ask GPT-4.1 to act as adversary and surface anything the
   deterministic pass missed.

Track A findings block publish. Track B findings can be corrected in place.

Report-type specific checks:
- Quarterly Strategic: threat_findings, open_signals_appendix, coverage_gaps
- Weekly Tactical: cve_analysis, apt_activity, industry_incidents, statistics
"""
from __future__ import annotations

import re

from .escape_handler import detect_gate_bleed
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
            leaked.append(
                f"Open Signal value '{finding.get('value')}' appears in Threat Findings"
            )
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
            violations.append(
                f"Threat Finding '{finding.get('value')}' is cited only from OSINT: {sources}"
            )
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
        src.source_name for src in gate1_sources 
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
        violations.append(
            f"Threat Actors metric mismatch: reported {reported_actors}, actual {actual_actors}"
        )
    
    # Check exploited CVEs count
    cve_analysis = report.get("cve_analysis", [])
    reported_exploited = stats.get("exploited_cves", 0)
    actual_exploited = len([
        cve for cve in cve_analysis 
        if isinstance(cve, dict) and (
            cve.get("actively_exploited") or 
            cve.get("targeted_by_actors") or 
            cve.get("in_cisa_kev")
        )
    ])
    
    if reported_exploited != actual_exploited:
        violations.append(
            f"Exploited CVEs metric mismatch: reported {reported_exploited}, actual {actual_exploited}"
        )
    
    # Check peer incidents count
    reported_incidents = stats.get("peer_incidents", 0)
    industry_incidents = report.get("industry_incidents", [])
    actual_incidents = len(industry_incidents) if industry_incidents else 0
    
    if reported_incidents != actual_incidents:
        violations.append(
            f"Peer Incidents metric mismatch: reported {reported_incidents}, actual {actual_incidents}"
        )
    
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


def _scan_industry_incidents_completeness(report: dict) -> list[str]:
    """
    Track B warning: Check if industry incidents are structured or extracted.
    
    AI should provide structured industry_incidents array. If missing, report
    had to fall back to unreliable keyword extraction.
    """
    violations: list[str] = []
    
    industry_incidents = report.get("industry_incidents", [])
    osint_sources = report.get("osint_sources_used", [])
    
    # If we have OSINT sources but no structured incidents, AI didn't do its job
    if osint_sources and not industry_incidents:
        violations.append(
            f"AI provided {len(osint_sources)} OSINT sources but no structured industry_incidents array. "
            f"Report had to fall back to unreliable keyword extraction. AI should explicitly identify breaches."
        )
    
    # Check if incidents have proper OSINT citation numbers
    if industry_incidents:
        missing_citations = [
            inc.get("organization", "Unknown") 
            for inc in industry_incidents 
            if isinstance(inc, dict) and not inc.get("osint_citation_number")
        ]
        
        if missing_citations:
            violations.append(
                f"{len(missing_citations)} industry incident(s) missing osint_citation_number: "
                f"{', '.join(missing_citations[:3])}"
            )
    
    return violations


def _scan_narrative_cohesion(report: dict, gate2_iocs: list) -> list[str]:
    """
    Check for narrative cohesion issues between executive summary and detailed sections.
    
    Track A violations:
    - CVEs mentioned in executive summary but not in threat findings
    - CVEs in threat findings not mentioned anywhere in narrative
    - Statistics that don't match the actual data
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
    summary_cves = set(re.findall(r'CVE-\d{4}-\d{4,}', exec_summary, re.IGNORECASE))
    
    # Extract CVEs from threat findings
    finding_cves = set()
    for finding in report.get("threat_findings", []):
        value = finding.get("value", "")
        if isinstance(value, str) and value.startswith("CVE-"):
            finding_cves.add(value.upper())
    
    # Extract CVEs from Gate 2 IOCs (actual detected CVEs)
    detected_cves = set()
    for ioc in gate2_iocs:
        if isinstance(ioc, dict) and ioc.get("ioc_type") == "CVE":
            cve_value = ioc.get("value", "")
            if isinstance(cve_value, str):
                detected_cves.add(cve_value.upper())
    
    # Check: CVEs in summary should either be in findings or explicitly noted as external threats
    orphaned_summary_cves = summary_cves - finding_cves
    if orphaned_summary_cves:
        for cve in orphaned_summary_cves:
            # Check if it's in detected CVEs - if not, it's an external threat that should be labeled
            if cve.upper() not in detected_cves:
                violations.append(
                    f"CVE {cve} mentioned in executive summary is not detected in environment "
                    f"and not labeled as 'industry threat' or 'external intelligence'"
                )
            else:
                violations.append(
                    f"CVE {cve} mentioned in executive summary but missing from threat findings table"
                )
    
    # Check: CVEs in findings should be mentioned in narrative
    unmentioned_finding_cves = finding_cves - summary_cves
    if len(unmentioned_finding_cves) > 3:  # Allow some to be table-only, but not all
        violations.append(
            f"{len(unmentioned_finding_cves)} CVEs in threat findings are never mentioned in narrative. "
            f"Key findings should be referenced in executive summary."
        )
    
    return violations


def _scan_osint_citations(report: dict) -> list[str]:
    """
    Check that OSINT sources used have inline citations in the text.
    
    Track B violations (quality issue, not blocking):
    - OSINT articles listed but never referenced in narrative
    - Claims that should cite OSINT but don't
    """
    violations: list[str] = []
    
    # Extract executive summary - handle both string and dict formats
    exec_summary = report.get("executive_summary", "")
    if isinstance(exec_summary, dict):
        exec_summary = str(exec_summary)
    elif not isinstance(exec_summary, str):
        exec_summary = str(exec_summary) if exec_summary else ""
    
    osint_sources = report.get("osint_sources_used", [])
    
    # Check if any OSINT sources are cited inline (look for superscript numbers or [1] style refs)
    import re
    has_citations = bool(re.search(r'\[\d+\]|¹|²|³|⁴|⁵', exec_summary))
    
    if osint_sources and not has_citations:
        violations.append(
            f"{len(osint_sources)} OSINT sources listed but no inline citations found in narrative. "
            f"Add [1], [2] style references to show which claims come from which sources."
        )
    
    return violations


def _scan_uncited_findings(report: dict) -> list[str]:
    return [
        f"Finding '{f.get('value')}' has no Gate 4 citation"
        for f in report.get("threat_findings", [])
        if not f.get("citation")
    ]


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
    gate1b_article_count = len((g1b.payload.get("osint_articles") or [])) if g1b else 30
    gate1_sources = (g1.payload.get("tier1_sources") or []) if g1 else []

    track_a: list[str] = []
    track_b: list[str] = []

    # Existing Track A checks
    track_a.extend(_scan_open_signal_leakage(report))
    track_a.extend(_scan_osint_only_citations(report))
    track_a.extend(_scan_uncited_findings(report))
    track_a.extend(f"Coverage Gap omitted from report: {g}" for g in _scan_gap_omissions(report, gate4_gaps))
    
    # NEW: Narrative cohesion checks (Track A - blocking)
    track_a.extend(_scan_narrative_cohesion(report, gate2_iocs))

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
    
    # NEW: Industry incidents completeness check (Track B - quality)
    track_b.extend(_scan_industry_incidents_completeness(report))

    # LLM adversary pass
    user_prompt = GATE_6_PROMPT_TEMPLATE.format(gate5_output=draft_text or str(report))
    llm_text = llm_client.complete(SYSTEM_PROMPT_GATE_6, user_prompt)

    llm_a, llm_b = _parse_llm_findings(llm_text)
    track_a.extend(f"[LLM] {item}" for item in llm_a)
    track_b.extend(f"[LLM] {item}" for item in llm_b)

    detect_gate_bleed(llm_text, expected_gate_id="6")

    status = "PASS" if not track_a else "BLOCK"

    return GateResult(
        gate_id="6",
        status=status,
        payload={
            "track_a": track_a,
            "track_b": track_b,
            "review_text": llm_text,
        },
        awaiting_clearance=True,
    )
