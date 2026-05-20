"""LLM client adapters for the gate framework.

The gate modules expect an injected client with a `.complete(system_prompt,
user_prompt) -> str` method. This module provides:

- StructuralLLMClient: a deterministic stub that returns well-formed gate
  completion markers without calling any external API. Used by the automated
  pipeline path so the Python structural fences run end-to-end without an
  Azure OpenAI round-trip. Real GPT-4.1 inference is intended for the
  interactive analyst workflow described in CURSOR_CTI_REPORTING.md.

A real Azure OpenAI adapter can be added here later; it must expose the same
`.complete` interface and is responsible for synchronizing its async client
behind a synchronous facade if the orchestrator is invoked from sync code.
"""
from __future__ import annotations

import re


_GATE_MARKER_RE = re.compile(r"GATE\s+([0-9]+B?)\s+", re.IGNORECASE)


def _detect_gate_from_prompt(user_prompt: str) -> str:
    match = _GATE_MARKER_RE.search(user_prompt)
    return match.group(1).upper() if match else "1"


class StructuralLLMClient:
    """Deterministic stub: returns a minimal structured response per gate.

    The response is shaped to satisfy gate escape detectors:
    - ends with `GATE {n} COMPLETE. AWAITING CLEARANCE.`
    - uses table-style rows so detect_prose_leakage does not fire
    - contains no narrative sentences during Gates 1, 1B, 2, 3
    """

    _STUBS: dict[str, str] = {
        "1": (
            "| Source | Records | Window | Status |\n"
            "|---|---|---|---|\n"
            "| [generated structurally from collector output] |\n"
        ),
        "1B": (
            "| Article ID | Source | Title | Published | URL |\n"
            "|---|---|---|---|---|\n"
            "| [generated structurally from RSS collector output] |\n"
        ),
        "2": (
            "| Type | Value | Source(s) | Source Severity | Cross-Source Hit |\n"
            "|---|---|---|---|---|\n"
            "| [generated structurally from Gate 1 records] |\n"
        ),
        "3": (
            "| IOC | Actor | Source | Campaign | Confidence |\n"
            "|---|---|---|---|---|\n"
            "| [generated structurally from Gate 2 IOCs] |\n"
        ),
        "4": (
            "- Executive Signal: [from Gate 1-3 top-severity Tier 1 finding]\n"
            "- Top IOCs: [list]\n"
            "- Actor Summary: [from Gate 3 Tier 1 attribution]\n"
            "- OSINT Corroboration: [matched pairs]\n"
            "- Open Signals: [labeled OSINT ONLY]\n"
            "- Coverage Gaps: [from Gate 1-3]\n"
        ),
        "5": "Report draft generated structurally from Gate 4 assembly.\n",
        "6": "Track A findings:\n- NONE\nTrack B findings:\n- NONE\nOverall: PASS\n",
    }

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        gate_id = _detect_gate_from_prompt(user_prompt)
        body = self._STUBS.get(gate_id, "")
        return f"{body}\nGATE {gate_id} COMPLETE. AWAITING CLEARANCE."
