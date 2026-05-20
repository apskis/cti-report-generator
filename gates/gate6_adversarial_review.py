"""Gate 6: Adversarial review of the Gate 5 draft.

Two layers:
1. Deterministic checks: scan the Gate 5 report payload for known fence
   violations (filler phrases, em dashes, Open Signal values inside
   Threat Findings, OSINT-only citations, omitted Coverage Gaps).
2. LLM adversary: ask GPT-4.1 to act as adversary and surface anything the
   deterministic pass missed.

Track A findings block publish. Track B findings can be corrected in place.
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


def _scan_narrative_cohesion(report: dict, gate2_iocs: list) -> list[str]:
    """
    Check for narrative cohesion issues between executive summary and detailed sections.
    
    Track A violations:
    - CVEs mentioned in executive summary but not in threat findings
    - CVEs in threat findings not mentioned anywhere in narrative
    - Statistics that don't match the actual data
    """
    violations: list[str] = []
    
    # Extract CVEs from executive summary
    exec_summary = report.get("executive_summary", "")
    # Regex to find CVE IDs in text
    import re
    summary_cves = set(re.findall(r'CVE-\d{4}-\d{4,}', exec_summary, re.IGNORECASE))
    
    # Extract CVEs from threat findings
    finding_cves = set()
    for finding in report.get("threat_findings", []):
        value = finding.get("value", "")
        if value.startswith("CVE-"):
            finding_cves.add(value.upper())
    
    # Extract CVEs from Gate 2 IOCs (actual detected CVEs)
    detected_cves = set()
    for ioc in gate2_iocs:
        if ioc.get("ioc_type") == "CVE":
            detected_cves.add(ioc.get("value", "").upper())
    
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
    
    exec_summary = report.get("executive_summary", "")
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
    g2 = input.prior_results.get("2")
    g4 = input.prior_results.get("4")
    g5 = input.prior_results.get("5")
    if g5 is None:
        raise RuntimeError("Gate 6 requires Gate 5 GateResult in input.prior_results['5']")

    report = g5.payload.get("report", {})
    draft_text = g5.payload.get("draft_text", "")
    gate4_gaps = (g4.payload.get("assembly", {}).get("coverage_gaps") or []) if g4 else []
    gate2_iocs = (g2.payload.get("iocs") or []) if g2 else []

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
