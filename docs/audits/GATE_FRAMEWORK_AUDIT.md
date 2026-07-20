# Gate Framework Audit — logic soundness & autonomous self-checking

_Audit date: 2026-07-20 · Branch: `claude/gate-framework-audit` · Scope: `src/gates/`_

**Question asked:** does the gate framework's logic make sense (its stated purpose is to
prevent hallucinations and enforce checks), and can it be made to let the AI question and
verify itself **without a human in the loop**?

**Bottom line:**
1. The framework has a **coherent, well-intentioned design** and a **genuinely sound
   deterministic spine** (Gates 1–4 extract/attribute/tier data straight from source records).
2. But the "**AI checks itself**" half is **currently inert**: the default LLM client is a
   deterministic **stub**, so every self-critique/adversarial prompt is a no-op; the one gate
   that runs a real model (Gate 5) has **zero verification** of its output; and Gate 1A's
   consistency checks are **mis-ordered** into always-fire warnings or dead code.
3. **No gate ever verifies a report claim against the raw source data.** Checks compare
   report-fields to other report-fields (internal consistency) or to keyword blocklists. An
   **internally-consistent fabrication passes the entire framework.**

The good news: the fix is well-defined and mostly **deterministic** (no dependence on LLM
honesty), which is exactly what "self-check without a human" needs.

---

## How the framework is wired (two layers)

The pipeline (`orchestrator.py:40-56`) runs, per report type:
- weekly: `1 → 1A → 1B → 2 → 3 → 4 → 5 → 6`
- quarterly: `1 → 1A → 1B → 2 → 3 → 4 → 5 → 1F → 1E → 1C → 1D → 6`

Each gate does some **deterministic Python** and (in gates 1/1B/2/3/4/6) calls
`llm_client.complete(system_prompt, user_prompt)`. There are two layers:

- **Layer A — deterministic Python** (always runs): source-shape validation, IOC/actor
  extraction, tiering, statistics/timestamp checks, blocklist scans, escape detectors.
- **Layer B — LLM reasoning** (the actual "AI questions itself"): the prompts in `prompts.py`
  instruct the model to never infer, flag `[NOT IN PROVIDED SOURCES]`, cite every claim,
  emit a Gate 5 **self-check**, and run a Gate 6 **adversarial self-review**.

**Layer B does not run by default.** `build_gate_llm_client()` (`llm_adapter.py:123`)
defaults to `StructuralLLMClient` (`GATE_LLM_MODE` unset), whose `.complete()`
(`llm_adapter.py:82`) ignores the input and returns a canned, already-valid string per gate
(e.g. Gate 6 always returns `Overall: PASS`). So every anti-inference instruction in
`prompts.py` is a no-op, and Gate 6's adversary contributes zero findings. The opt-in real
adapter (`GATE_LLM_MODE=azure`) is documented EXPERIMENTAL and untuned.

---

## Part 1 — Does the logic make sense?

### What genuinely works (keep this — it's the real value)

| Gate | Mechanism | Why it's sound |
|---|---|---|
| **Gate 2** IOC extraction (`gate2:85-123`) | IOCs + severities copied **verbatim from source records**; nothing invented | Strongest guard — structurally impossible to emit an IOC not in the source |
| **Gate 3** actor linkage (`gate3:58-96`) | Actor names pulled **only** from the record matching the IOC; else `[UNATTRIBUTED]` | Can't inject `APT29`/`Lazarus`; **fails safe** (under-attributes rather than fabricates) |
| **Gate 1** GAP classification (`gate1:42-53`) | Classifies each collector payload OK/GAP (None/error/empty/wrong-type) | Real source-shape validation |
| **Gate 4** tiering (`gate4:148-224`) | Tier-1 vs Tier-2/OSINT kept in separate lanes; Open Signals labeled; coverage gaps collected | Structural discipline enforced in Python, not by convention (`models.py`) |
| **Gate 1A** weekly window (`gate1a:89-177`) | Parses record timestamps and checks them against the reporting window | Actually reads `tier1_data`; sound (but samples only first 5 records/source) |

This deterministic extraction/attribution/tiering backbone is legitimately anti-hallucination
and worth preserving.

### What's broken, dead, or theater

1. **Gate 5 output is never verified (the #1 gap).** Gate 5 (`gate5:24-233`) runs the real
   `ThreatAnalystAgent` and returns its output as the report with **no reconciliation against
   source** — no check that its CVEs/actors/victims/statistics exist in `tier1_data`, Gate 2
   IOCs, or Gate 3 links. Its only "check", `detect_gate_bleed(str(analysis), "5")`
   (`gate5:219`), is wrapped in a log-only try/except and is semantically vacuous on a JSON
   analysis dict. **This is the exact point where hallucination enters, and it is unguarded.**

2. **Gate 1A is mis-ordered → always-fire or dead.** 1A runs at position 2 but its
   cross-gate checks read gates that haven't run: `tier1_data_to_cve_mapping` (reads Gate 2,
   `gate1a:183`), `osint_data_present` (reads Gate 1B, `:235`), quarterly
   `geopolitical_context_present` (reads Gate 4, `:334`) **always warn**;
   `non_zero_data_collected` (`:201`) is unreachable. Worst: the **breach-count-vs-Intel471**
   and QoQ-sign checks (`:352-418`) — the *only* checks in 1A that compare report numbers to
   **raw source data** — are guarded on `gate5_result.status == COMPLETE`, but Gate 5 runs at
   position 7, so they are **dead code** in the real pipeline.

3. **No per-claim source grounding anywhere.** Every "grounding" check is either count
   reconciliation (summary integer vs the AI's own array length — `gate1d:229,239`;
   `gate6:195,210,218`) or a keyword blocklist (`gate1e:24`; `gate1f:25`; `gate6:284`). The
   **only** check that compares a report number to a count derived from raw `tier1_data` is
   Gate 1F's total-incident variance (`gate1f:203-224`) — ±5 tolerance and **non-blocking**.
   `_scan_uncited_findings` (`gate6:456`) checks that a `citation` **field exists**, never that
   it **resolves** to a real record — a fabricated citation string passes.

4. **Two gates declaw themselves.** Gate 1F labels findings "critical/BLOCKING" then returns
   `status=COMPLETE, halt_reason=None` regardless (`gate1f:259-269`). Gate 1E downgrades its
   most concrete fabrication check (generic/fake victim names) to a warning
   (`gate1e:420-432`). Their strongest checks cannot stop a report.

5. **Gate 1C (the best anti-hallucination idea) is under-wired.** It checks technologies
   mentioned vs. detected (`gate1c:200-204`) but: is **excluded from weekly**
   (`orchestrator.py:41`); inspects **only the executive summary** (`gate1c:159`); uses fuzzy
   substring matching that both over- and under-matches (`:170`); computes keywords then
   **discards them** (`:156`); and **never blocks** (`:246`) — deferring to Gate 6, which is
   the stub.

6. **Escape/promotion fences guard impossible or absent states.** `detect_osint_promotion`
   (`escape_handler.py:93-119`) scans sets that are provably disjoint by construction
   (`gate4:99-101`), so it can never fire on the deterministic assembly; its Tier-1 test
   `not str(s).startswith("OSINT")` (`:113`) is defeated by any non-`OSINT` source label.
   `detect_prose_leakage`/`detect_gate_bleed` only fire on real model text, so against the
   stub they never fire. `detect_missing_clearance_marker` is **never called**.

7. **OSINT actor paths are dead.** Gate 1B hardcodes `actor_names=[]` (`gate1b:63`, deferred
   to the LLM), so Gate 4's OSINT actor corroboration/open-signals (`gate4:74,119-128`) never
   match.

8. **Halt weakened vs. documented.** `check_tier1_halt` now halts only if **all** Tier-1
   sources gap (`halt.py:38`), not "2+" as the docstring advertises (`gate1:4`). A report can
   be built from a single surviving feed with no halt.

**Verdict:** the *design* makes sense and the deterministic spine is sound, but everything
framed as "the AI self-checks" is currently inert, and the framework never actually grounds a
report claim in a source record.

---

## Part 2 — Can the AI check itself without a human? (today: no)

An **internally-consistent fabrication** defeats the whole framework. Concretely: the AI
invents actor "APT-Fabricated", lists it in `apt_activity`, sets `statistics.threat_actors`
to match, gives the finding a `citation` field and a source string that doesn't start with
"OSINT", and uses a real-looking domain. Then:
- every count reconciliation passes (summary matches array length),
- `_scan_uncited_findings` passes (a citation field is present),
- `detect_osint_promotion` passes (source label isn't `OSINT`-prefixed),
- the blocklists pass (the name isn't a known generic term),
- and the Gate 6 adversary that is *supposed* to notice "this actor isn't in the source" is
  the **stub returning PASS**.

Result: `Overall: PASS`, report publishes. The only things that can stop a report today are
deterministic **structural** failures (zero IOCs, all sources gap, a stat that contradicts the
AI's own table) — not fabrications.

---

## Part 3 — A design for autonomous self-verification

The reliable way to have the system "question and check itself without a human" is to make
**verification deterministic wherever possible** (so it doesn't depend on the model being
honest), and to use the LLM only in a **structured, re-checkable** way. Three tiers:

### Tier 1 — Deterministic grounding (highest reliability, build first)

This is the missing primitive and the biggest win. It needs no LLM.

1. **Source index with stable IDs.** Build one index over `tier1_data` + `osint_articles`
   keyed by the entities that appear in reports: CVE ids, actor names, IOC values, victim/org
   names, source ids/URLs, and every raw number (counts, exposures, percentages). Each source
   record gets a stable id the report can reference.

2. **Per-claim resolver (new gate, runs right after Gate 5).** For every claim in the report —
   each `cve_analysis` entry, `apt_activity` actor, `industry_incidents` victim, and every
   statistic — verify the referenced entity **resolves to a real source record**. If a CVE id,
   actor name, org name, or URL does not appear in any source record → **Track A block**.
   Upgrade `_scan_uncited_findings` from "citation field exists" to "citation **resolves**".

3. **Numeric re-derivation from source (not sibling fields).** Recompute every statistic
   (CVE count, actor count, incident count, exposure totals, `change_pct`) directly from the
   source data and compare to the report. Generalize Gate 1F's variance idea to all metrics,
   tighten tolerance to ~0, and make it **blocking**.

4. **Replace blocklists with grounding.** The generic-name/vague-org blocklists
   (`gate1e:24`, `gate1f:25`, `gate6:284`) can't catch invented *specific* names. "Does this
   organization appear in a source record?" does — and generalizes across customers.

### Tier 2 — LLM self-critique, but verifiable (this is the real "AI questions itself")

Wire a real model into the adversary pass, and **never trust its prose** — force structured,
machine-checkable output:

5. **Structured adversarial review (Gate 6 with the real adapter).** Require the model, for
   **each claim**, to emit the specific **source-record id** it verified the claim against.
   Then deterministically re-validate those ids against the source index (so the model can't
   launder a fabrication by citing a record that doesn't support it). Findings feed Track A.

6. **Quote-back challenge.** For each Threat Finding, prompt the model to "quote the exact
   source sentence that supports this claim," then **string-match the quote back** into the
   source corpus. Unverifiable quotes → Track A. This catches fabrication that survives
   structure checks.

7. **Self-consistency / multi-sample voting.** Re-derive the key findings in a fresh context
   (independent sample, seed) and **diff**; disagreements are flagged. Run the adversary N times
   and majority-vote (LLM-as-judge on itself) to damp single-sample noise.

### Tier 3 — Make the existing logic sound (structural/process fixes)

8. **Reorder/split Gate 1A** so its cross-gate checks run **after** Gates 2–5 (or move them to
   a dedicated post-Gate-5 reconciliation gate). Today they're always-fire or dead.
9. **Make Gate 1C run for weekly**, scan the **whole report** (not just the exec summary),
   replace fuzzy substring with tokenized matching, and **block**.
10. **Make Gate 1E/1F "critical" findings actually block** (remove the downgrade-to-warning).
11. **Fix the escape fences:** `detect_osint_promotion` should key on tier via a real tier
    field, not a `startswith("OSINT")` string test; call `detect_missing_clearance_marker`
    where intended or delete it.
12. **Revisit the halt threshold** (`halt.py:38`) — make "how many Tier-1 gaps halt"
    explicit/config-driven rather than silently "all".
13. **Populate or remove the dead paths** (Gate 1B `actor_names`, Gate 4 corroboration) so the
    code reflects reality.

### Suggested build order

1. Tier 1 (#1–#3): the deterministic source index + per-claim resolver + numeric
   re-derivation, as a new **grounding gate right after Gate 5**. This alone closes the #1 gap
   (unverified Gate 5 output) and gives real, human-free hallucination catching. **Fully
   unit-testable.**
2. Tier 3 (#8–#10): reorder Gate 1A, fix Gate 1C, un-declaw 1E/1F — cheap soundness wins.
3. Tier 2 (#5–#7): wire the real adapter and the structured/quote-back adversary — the genuine
   AI-self-questioning layer. Needs live Azure OpenAI + prompt-tuning to validate.

The key principle: **let deterministic grounding be the hard gate, and the LLM self-critique
be an additional (verifiable) soft layer** — never rely on the model's unverified word that
its own output is grounded.
