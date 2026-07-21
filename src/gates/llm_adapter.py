"""LLM client adapters for the gate framework.

The gate modules expect an injected client with a `.complete(system_prompt,
user_prompt) -> str` method. This module provides two implementations:

- StructuralLLMClient (default): a deterministic stub that returns well-formed
  gate completion markers without calling any external API. IMPORTANT: with the
  stub, the gate framework's value is its **deterministic Python checks**
  (statistics/timestamp validation, IOC extraction, source audit, structural
  escape detection). The LLM `.complete()` steps are placeholders that return
  canned, already-valid structure — they do not perform real AI validation.

- AzureOpenAILLMClient (opt-in, EXPERIMENTAL): a real Azure OpenAI adapter
  exposing the same synchronous `.complete` interface. Selected by setting the
  GATE_LLM_MODE=azure environment variable (default is "structural"). It is
  marked experimental because the gate prompts were tuned for the structural
  stub's exact marker/table output; a real model's responses will likely need
  prompt-tuning and live end-to-end validation before they reliably pass the
  escape detectors. Default behavior is unchanged.

Use `build_gate_llm_client(credentials)` to construct the configured client.
"""

from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)

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


class AzureOpenAILLMClient:
    """Opt-in real Azure OpenAI adapter with a synchronous `.complete` interface.

    EXPERIMENTAL: the gate prompts were designed for StructuralLLMClient's exact
    output; expect to tune prompts and validate end-to-end before relying on this
    for gating decisions. Uses the synchronous ``openai.AzureOpenAI`` client
    (imported lazily so this module loads without the SDK installed).
    """

    def __init__(self, endpoint: str, api_key: str, deployment: str, api_version: str = "2024-06-01"):
        from openai import AzureOpenAI  # lazy import; only needed when opted in

        self._deployment = deployment
        self._client = AzureOpenAI(azure_endpoint=endpoint, api_key=api_key, api_version=api_version)

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self._deployment,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
        )
        return response.choices[0].message.content or ""


class FakeLLMClientTier2:
    """Fake LLM client that returns canned structured JSON for Tier 2 testing.

    This allows unit tests to verify Tier 2 logic (structured review, quote-back,
    multi-sampling) without requiring a live Azure OpenAI connection. Tests inject
    the JSON responses they want to validate against.
    """

    def __init__(self, canned_responses: dict[str, str] | None = None):
        """Initialize with a dict of {gate_id: json_response_string}.

        If no canned response for a gate, falls back to StructuralLLMClient.
        """
        self._canned = canned_responses or {}
        self._fallback = StructuralLLMClient()

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        gate_id = _detect_gate_from_prompt(user_prompt)
        if gate_id in self._canned:
            return self._canned[gate_id]
        return self._fallback.complete(system_prompt, user_prompt)


def build_gate_llm_client(credentials: dict | None = None):
    """Return the configured gate LLM client.

    Defaults to the deterministic StructuralLLMClient. If GATE_LLM_MODE=azure and
    OpenAI credentials are available, returns the experimental AzureOpenAILLMClient;
    on any construction failure it logs and falls back to the stub so the pipeline
    still runs.
    """
    mode = os.environ.get("GATE_LLM_MODE", "structural").strip().lower()
    if mode == "azure" and credentials and credentials.get("openai_endpoint") and credentials.get("openai_key"):
        from src.core.config import analysis_config

        try:
            return AzureOpenAILLMClient(
                endpoint=credentials["openai_endpoint"],
                api_key=credentials["openai_key"],
                deployment=analysis_config.deployment_name,
            )
        except Exception as e:  # noqa: BLE001 - fall back to stub on any setup error
            logger.warning(f"GATE_LLM_MODE=azure but AzureOpenAILLMClient init failed; using structural stub: {e}")
    return StructuralLLMClient()
