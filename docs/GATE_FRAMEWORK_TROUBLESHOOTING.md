# Gate Framework Troubleshooting Brief — Mock Run Did Not Invoke Gates

## Symptom

Running `python test_local.py weekly --local --mock` with
`ENABLE_GATE_FRAMEWORK=1` produces a weekly `.docx` report identical to the
behavior before the gate framework was added. No gate-related log lines
appear in the output. The orchestrator never runs.

## Confirmed Root Cause

The gate framework wire-in was added to `function_app.py` in the
`generate_weekly_report` and `generate_quarterly_report` HTTP handlers. Those
handlers are invoked by the Azure Functions runtime over HTTP, not by the
local CLI.

`test_local.py` has its own report generation path that bypasses
`function_app.py` entirely:

- Entry point: `test_local.py:main()` (line 630)
- Calls `generate_report_local()` (line 353)
- Which calls `collect_and_analyze()` (line 483)
- Which calls the collectors and `ThreatAnalystAgent` directly
- Then calls a report generator (weekly or quarterly) directly
- Never imports `gates.orchestrator` or checks `ENABLE_GATE_FRAMEWORK`

So the feature flag works, but only inside the HTTP function entrypoint. The
CLI is a separate code path that does not call the gates.

## What I Want You To Do

Wire the gate framework into `test_local.py` so that
`ENABLE_GATE_FRAMEWORK=1 python test_local.py weekly --local --mock` runs
the orchestrator over the (mock or real) collected data, prints a summary
of each gate's status, and blocks the `.docx` write if Gate 6 returns BLOCK
(or if any gate raises a halt or escape).

### Constraints

1. **Do not duplicate code.** Factor the gate framework call out of
   `function_app.py` into a reusable helper, e.g.
   `gates/pipeline_hook.py:run_gate_framework_over_collected_data(...)`,
   and call it from both `function_app.py` and `test_local.py`.
2. **Do not change the existing behavior when the feature flag is off.**
   Without `ENABLE_GATE_FRAMEWORK=1`, both code paths must behave exactly
   as they did before. The gate code path is purely additive.
3. **Mock-data path must produce a Gate 6 PASS or a clearly-explained
   BLOCK.** If the mock data triggers a Gate 1 HALT (two or more Tier 1
   sources empty), tell me which sources are empty in the mock data and
   propose a fix:
     - Option A: enrich the mock data so all five Tier 1 sources have
       at least one record.
     - Option B: treat a mock-data HALT as a warning rather than a hard
       block, gated behind a `--mock` detection or a separate
       `GATE_FRAMEWORK_STRICT` env var.
   Recommend the option you think is best and apply it.
4. **Add a clear summary print at the end of the gate run.** Use the
   project's existing `print_section`/`print_status` helpers from
   `test_local.py` so the output style matches the rest of the CLI.
   Suggested format:
   ```
   ── Gate Framework Summary ──────────────────────────────
   Gate 1  (Tier 1 Source Inventory):     COMPLETE
   Gate 1B (OSINT Article Triage):        COMPLETE
   Gate 2  (IOC Extraction):              COMPLETE
   Gate 3  (Actor Linkage):               COMPLETE
   Gate 4  (Structured Assembly):         COMPLETE
   Gate 5  (Report Draft):                COMPLETE
   Gate 6  (Adversarial Review):          PASS
   Track A findings: 0
   Track B findings: 2
   ```
5. **Keep the existing report generation as the source of the `.docx`.**
   The gate framework's Gate 5 draft is structural and intentionally
   stubby. The real `.docx` continues to come from `weekly_report.py`
   or `quarterly_report.py`. The gate framework's role is validation,
   not document generation. So the flow is:
     1. Collect data (existing)
     2. Run AI analysis (existing)
     3. **Run gate framework over the collected data (new)**
     4. If Gate 6 BLOCK or any halt/escape: stop before writing the
        `.docx`, print the diagnostic, return non-zero exit code.
     5. Otherwise: write the `.docx` as today.

### Files To Touch

- `function_app.py` — replace the inline `_run_gate_framework` helper
  with a call to the new shared helper. Keep the feature-flag check.
- `test_local.py` — after `collect_and_analyze` returns and before
  `generate_report_local` writes the `.docx`, call the same helper.
- `gates/pipeline_hook.py` — NEW file. Exposes
  `run_gate_framework_over_collected_data(report_type, data_by_source,
  osint_articles, period_days) -> (publish_ok: bool, info: dict,
  session: dict)`. The `session` return is the orchestrator's
  `session` dict so the caller can print the per-gate summary.

### Constraints On The Shared Helper

- Sync function (matches `function_app.py`'s current expectations and
  is safe to call from within `asyncio.run`-wrapped code in
  `test_local.py`).
- Catches `GateHaltError` and `EscapeDetectedError` internally and
  returns them as fields in `info`. Never raises.
- Returns the orchestrator's session dict so the caller can iterate
  `session.items()` and print each gate's status.
- Uses `StructuralLLMClient` from `gates/llm_adapter.py` for now. Do
  not introduce an Azure OpenAI dependency in this commit.

## How To Verify Your Fix

After your changes, all of the following must hold:

1. **Feature flag off, mock data — behaves as before:**
   ```
   python test_local.py weekly --local --mock
   ```
   Expected: weekly `.docx` written, no gate framework log lines.

2. **Feature flag on, mock data — gates run end-to-end:**
   ```
   $env:ENABLE_GATE_FRAMEWORK="1"
   python test_local.py weekly --local --mock
   ```
   Expected: gate framework summary printed; if Gate 6 PASS, the
   `.docx` is written; if BLOCK, the `.docx` is NOT written and a
   non-zero exit code is returned. Quarterly variant must behave the
   same.

3. **Quarterly mock with feature flag on:**
   ```
   python test_local.py quarterly --local --mock
   ```
   Expected: same as above, plus the Gate 4 assembly contains a
   `geopolitical_context_signals` field.

4. **Existing tests still pass:**
   ```
   python -m pytest tests/ -v
   ```
   Expected: 25 gate framework tests pass plus any pre-existing tests
   that were passing before.

5. **No prompts defined outside `gates/prompts.py`:**
   ```
   grep -rn "SYSTEM_PROMPT\s*=\|GATE_._PROMPT_TEMPLATE\s*=" gates/ | grep -v "^gates/prompts.py:"
   ```
   Expected: empty output.

6. **No gate module imports another gate module directly:**
   ```
   grep -n "from gates.gate\|from .gate" gates/gate*.py
   ```
   Expected: empty output. (Imports of `models`, `prompts`, `halt`,
   `escape_handler` from `gates` are fine; cross-gate imports are not.)

## What To Report Back

After your changes:

1. The exact `git diff` of the files you touched.
2. The console output from running `python test_local.py weekly --local
   --mock` with the feature flag on. I want to see the gate summary.
3. The console output from `python test_local.py quarterly --local
   --mock` with the feature flag on.
4. If you chose Option B in Constraint 3 (mock-data HALT softening),
   tell me which env var or flag controls it and how to flip back to
   strict mode.

## Commit Granularity

Same atomic-commit rule as the original implementation:

- One commit for the new `gates/pipeline_hook.py` helper.
- One commit for the `function_app.py` refactor to use the helper.
- One commit for the `test_local.py` wire-in.
- One commit for any mock-data fixes if you chose Option A.

Do not squash these into a single commit.

## Branch

Develop on `claude/create-feature-branch-Fkxhp` (the same branch the
gate framework was implemented on, now merged into `main` locally). Push
to the same branch on `origin` when done. Do not open a pull request.
