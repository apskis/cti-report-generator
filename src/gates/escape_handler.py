"""Escape pattern detection and ESC recovery prompt lookup.

These detectors run against the raw LLM response text (and, for OSINT promotion,
against the assembled payload structure) to catch fence breaches before they
contaminate downstream gates. When a detector fires, the orchestrator stops
and the analyst pastes the corresponding ESC prompt cold.
"""

from __future__ import annotations

import re
from enum import Enum

from .models import OpenSignal


class EscapeType(Enum):
    GATE_BLEED = "GATE_BLEED"
    INFERENCE_ESCAPE = "INFERENCE_ESCAPE"
    SOURCE_CONTAMINATION = "SOURCE_CONTAMINATION"
    PROSE_LEAKAGE = "PROSE_LEAKAGE"
    LOOP_DETECTED = "LOOP_DETECTED"
    SCOPE_CREEP = "SCOPE_CREEP"
    OSINT_PROMOTION = "OSINT_PROMOTION"


class EscapeDetectedError(Exception):
    """Raised when an escape pattern is detected in model output."""

    def __init__(self, escape_type: EscapeType, gate_id: str, offending_text: str):
        self.escape_type = escape_type
        self.gate_id = gate_id
        self.offending_text = offending_text
        super().__init__(f"Gate {gate_id} ESCAPE ({escape_type.value}): {offending_text[:200]}")


_GATE_COMPLETE_RE = re.compile(r"GATE\s+([0-9]+B?)\s+COMPLETE", re.IGNORECASE)
_NON_NARRATIVE_GATES = {"1", "1B", "2", "3"}


def detect_gate_bleed(response_text: str, expected_gate_id: str) -> None:
    """Raise EscapeDetectedError(GATE_BLEED) if response contains more than one GATE N COMPLETE marker."""
    matches = _GATE_COMPLETE_RE.findall(response_text)
    unique = {m.upper() for m in matches}
    if len(unique) > 1:
        raise EscapeDetectedError(
            escape_type=EscapeType.GATE_BLEED,
            gate_id=expected_gate_id,
            offending_text=f"Multiple gate completion markers found: {sorted(unique)}",
        )


def detect_prose_leakage(response_text: str, gate_id: str) -> None:
    """Raise EscapeDetectedError(PROSE_LEAKAGE) for gates 1, 1B, 2, 3 if 3+ narrative sentences are present.

    Heuristic: a "narrative sentence" is a line that is not inside a table row
    (no leading pipe), not a bullet or numbered list item, not a labeled field
    (Key: value), ends with a period or similar terminator, and contains at
    least 5 words. Lines that are pure markers like 'GATE 1 COMPLETE.' do not
    count.
    """
    if gate_id.upper() not in _NON_NARRATIVE_GATES:
        return

    sentence_count = 0
    offending: list[str] = []
    for raw_line in response_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("|") or line.startswith("-") or line.startswith("*"):
            continue
        if re.match(r"^\d+[.)]\s", line):
            continue
        if re.match(r"^[A-Z][A-Za-z0-9 _]{0,40}:\s", line):
            continue
        if _GATE_COMPLETE_RE.search(line):
            continue
        if not re.search(r"[.!?]\s*$", line):
            continue
        if len(line.split()) < 5:
            continue
        sentence_count += 1
        offending.append(line)
        if sentence_count >= 3:
            raise EscapeDetectedError(
                escape_type=EscapeType.PROSE_LEAKAGE,
                gate_id=gate_id,
                offending_text=" | ".join(offending),
            )


def detect_osint_promotion(assembly: dict, open_signals: list[OpenSignal]) -> None:
    """Raise EscapeDetectedError(OSINT_PROMOTION) if an OpenSignal value appears in the threat_findings block.

    Threat findings (Tier 1 evidence) must never contain an OSINT-only value
    unless it is also backed by a Tier 1 citation. If an OpenSignal value
    appears in threat_findings without a Tier 1 source alongside it, the
    OSINT signal was promoted, which is a Tier 2 -> Tier 1 contamination.
    """
    threat_findings = assembly.get("threat_findings") or assembly.get("top_iocs") or []
    if not threat_findings:
        return

    open_values = {s.value for s in open_signals}
    if not open_values:
        return

    for finding in threat_findings:
        if isinstance(finding, dict):
            value = finding.get("value") or finding.get("ioc_value") or finding.get("actor_name") or ""
            sources = finding.get("sources") or []
            tier1_sources = [s for s in sources if s and not str(s).startswith("OSINT")]
            if value in open_values and not tier1_sources:
                raise EscapeDetectedError(
                    escape_type=EscapeType.OSINT_PROMOTION,
                    gate_id="4",
                    offending_text=f"OSINT-only value '{value}' appears in threat_findings without Tier 1 citation",
                )


def detect_missing_clearance_marker(response_text: str, gate_id: str) -> None:
    """Raise EscapeDetectedError(GATE_BLEED) if the response does not end with the expected marker."""
    expected = f"GATE {gate_id.upper()} COMPLETE. AWAITING CLEARANCE."
    if expected not in response_text.upper().replace("\n", " "):
        raise EscapeDetectedError(
            escape_type=EscapeType.GATE_BLEED,
            gate_id=gate_id,
            offending_text=f"Response did not end with '{expected}'",
        )


_RECOVERY_PROMPTS: dict[EscapeType, str] = {
    EscapeType.GATE_BLEED: (
        "Stop. You combined gates or wrote narrative before Gate 5. Discard your last response entirely.\n\n"
        "Return to Gate {gate_id}. Complete only Gate {gate_id}. Follow the gate prompt exactly.\n"
        "End with: GATE {gate_id} COMPLETE. AWAITING CLEARANCE.\n"
        "Do not proceed further until I give clearance."
    ),
    EscapeType.PROSE_LEAKAGE: (
        "Stop. You combined gates or wrote narrative before Gate 5. Discard your last response entirely.\n\n"
        "Return to Gate {gate_id}. Complete only Gate {gate_id}. Follow the gate prompt exactly.\n"
        "End with: GATE {gate_id} COMPLETE. AWAITING CLEARANCE.\n"
        "Do not proceed further until I give clearance."
    ),
    EscapeType.INFERENCE_ESCAPE: (
        "Stop. Your last response contained inference or out-of-scope content not found in the source data.\n\n"
        "Remove the following: {offending_text}\n\n"
        "Re-run Gate {gate_id} with that content excluded. Extract only.\n"
        "If a topic has no source coverage, write [NOT IN PROVIDED SOURCES] and move on.\n"
        "End with: GATE {gate_id} COMPLETE. AWAITING CLEARANCE."
    ),
    EscapeType.SCOPE_CREEP: (
        "Stop. Your last response contained inference or out-of-scope content not found in the source data.\n\n"
        "Remove the following: {offending_text}\n\n"
        "Re-run Gate {gate_id} with that content excluded. Extract only.\n"
        "If a topic has no source coverage, write [NOT IN PROVIDED SOURCES] and move on.\n"
        "End with: GATE {gate_id} COMPLETE. AWAITING CLEARANCE."
    ),
    EscapeType.SOURCE_CONTAMINATION: (
        "Stop. You introduced a fact not in any provided source document: {offending_text}\n\n"
        "Do not restate this claim in any form, even paraphrased.\n\n"
        "If in Gates 1 through 4: I am restarting this session. Do not carry forward any output from this session.\n\n"
        "If in Gate 5 or 6: Remove this claim and every sentence depending on it. Re-output only the affected "
        "paragraph with the claim removed. If the paragraph becomes empty, write [CLAIM REMOVED: SOURCE CONTAMINATION]."
    ),
    EscapeType.LOOP_DETECTED: (
        "Stop. You ran the same step twice without flagging it.\n\n"
        "Do not run this step again. Instead:\n"
        "1. State what you attempted to do.\n"
        "2. State exactly what failed or repeated.\n"
        "3. State what information you are missing that caused the loop.\n"
        "4. Wait for my instruction.\n\n"
        "Write this as a diagnostic note, not as a gate output."
    ),
    EscapeType.OSINT_PROMOTION: (
        "Stop. You used an OSINT article as a primary source for a Threat Findings claim, or you moved an Open "
        "Signal into the Threat Findings section.\n\n"
        "OSINT articles are Tier 2. They corroborate. They do not prove.\n\n"
        "Locate the specific claim: {offending_text}\n\n"
        "If this claim has a Tier 1 source to support it: keep the claim, remove the OSINT article as the primary "
        "citation, add it as a parenthetical corroboration note only.\n\n"
        "If this claim has NO Tier 1 source: remove it from Threat Findings entirely and move it to the Open "
        "Signals Appendix labeled [OSINT ONLY: NOT VERIFIED BY TIER 1].\n\n"
        "Re-output only the affected section. Do not rewrite the full report."
    ),
}


def get_recovery_prompt(escape_type: EscapeType, gate_id: str, offending_text: str = "") -> str:
    """Return the paste-ready ESC recovery prompt string for the given escape type."""
    template = _RECOVERY_PROMPTS[escape_type]
    return template.format(gate_id=gate_id, offending_text=offending_text)
