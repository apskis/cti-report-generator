# Tier 2 Implementation Brief — verifiable LLM self-critique

_Follow-on to `docs/audits/GATE_FRAMEWORK_AUDIT.md`. Tier 1 (deterministic grounding) and
Tier 3 (structural fixes) are already implemented; see that doc's "Implementation status"
section. This brief specifies **Tier 2 only** (audit items #5–#7)._

## Objective

Wire a **real** LLM into the adversarial review and make its self-critique **verifiable** —
so the framework's "the AI questions itself" layer is genuinely active, without ever trusting
the model's unverified word.

## Core principle (do not violate)

The LLM's output is **never** trusted on its word. Every claim the model makes must be
**deterministically re-validated in Python** against the source data before it can affect the
pass/block decision. Reuse the existing `src/gates/grounding.py` `SourceIndex` /
`build_source_index()` as the single source-of-truth index — do **not** build a second one.

Anti-pattern to avoid: asking the model "is this report grounded?" and trusting its yes/no.
The point is to force the model to produce **checkable artifacts** (a source-record id, an
exact quote) and then check them ourselves.

## Scope — implement items #5, #6, #7 from the audit

### #5 — Structured adversarial review (Gate 6 with the real adapter)
- In `src/gates/gate6_adversarial_review.py`, when `llm_client` is the real adapter
  (`GATE_LLM_MODE=azure`, see `src/gates/llm_adapter.py`), require the model to return **JSON**,
  not prose: for each report claim, `{claim, verdict, source_record_id, quote}`.
- Parse it, then for each entry **re-check `source_record_id` and `quote` against the
  `SourceIndex` in Python**. If the cited record doesn't exist or doesn't contain the entity →
  Track A finding (BLOCK). The model must not be able to launder a fabrication by citing a
  record that doesn't support it.
- Add **stable ids** to source records in `build_source_index()` so claims can reference them.

### #6 — Quote-back challenge
- For each Threat Finding, prompt the model to "quote the exact source sentence that supports
  this claim." **String-match the quote back** into the source corpus
  (`SourceIndex.text_blob`, normalized whitespace/case). Unverifiable quote → Track A.

### #7 — Self-consistency / multi-sample voting
- Run the adversarial pass **N times** (N configurable, default 3) and **majority-vote** each
  finding. Flag disagreements. Keep the design deterministic-friendly for tests (inject the
  sample results rather than relying on real sampling in unit tests).

## Constraints

- Keep the default `StructuralLLMClient` path working **unchanged** — Tier 2 activates only
  with the real adapter. Update the Gate 6 prompt in `src/gates/prompts.py`.
- **Tests must not require live Azure.** Add a fake LLM client that returns canned structured
  JSON, and unit-test that:
  1. a model citing a nonexistent `source_record_id` still BLOCKS,
  2. a fabricated (non-matching) quote BLOCKS,
  3. majority voting resolves split verdicts correctly,
  4. the `StructuralLLMClient` default path is unaffected.
  Mirror the style of `tests/test_gate6.py` and `tests/test_grounding.py`.
- Run `ruff check` + `ruff format` and the full `pytest` suite before finishing.

## What still needs a human / live model (not code-testable here)

Getting the model to **reliably emit the JSON schema** requires iterating the prompt wording
against real Azure OpenAI. The logic above is fully unit-testable offline with a fake client,
but the prompt tuning is a live-model task — budget for it.
