# Quarterly Report Review — August 2026 (pre-real-run pass)

_Review date: 2026-08-18 · Method: three parallel read-only code reviews (audit-regression check,
breach-landscape layer, report generator + strategic path), cross-checked against source._

This is a follow-up to `QUARTERLY_AUDIT.md` (July 2026). That audit's Q1–Q26 remediation **held**:
**22 of 26 confirmed fixed, 0 regressed**, 3 partial (Q8, Q12, Q20). The remaining risk is in three
places the July audit did not cover:

1. **Sibling crash guards** — the null/type hardening was applied per-symptom, so several
   adjacent AI-field accesses were missed (they crash on the same malformed input the audited
   fields were fixed against).
2. **The breach-landscape layer** (VCDB/HHS/HIBP + `breach_metrics`) — built *after* the July
   audit, never reviewed. Two blockers: the deployed Function never feeds it into the report, and
   HHS fails silently to zero.
3. **Grounding token-OR** — the anti-hallucination guard now runs for quarterly, but accepts a
   name if any one of its words appears in the corpus, so a plausible multi-word fake victim
   ("Acme Genomics") can still publish.

Legend: ☐ open · ◐ in progress · ☑ done

---

## Tier 1 — Blockers (a real run either crashes, or silently proves nothing)

- ☑ **T1.1 · HIGH · Production Function never wires the breach datasets.** _(done 2026-08-18)_
  Shared `merge_breach_dataset()`/`BREACH_DATASET_SOURCES` in `reporting_period.py`;
  `create_and_upload_report` + `_upload_report` thread `breach_dataset`/`reporting_period`;
  `function_app` quarterly pins the previous complete quarter and feeds the merged dataset.
  `set_breach_dataset()` / `set_reporting_period()` are called only in `scripts/run_local.py`
  (~1397); the deployed `function_app.py` quarterly path collects VCDB/HHS/HIBP then discards
  them, so the four breach stat cards fall back to AI guesses. Local `--real` masks it.
  _Fix:_ mirror the run_local wiring in `function_app.generate_quarterly_report` /
  `create_and_upload_report`.

- ☑ **T1.2 · HIGH · Three unguarded crash vectors abort the `.docx`.** _(done 2026-08-18)_
  `isinstance(_, dict)` filter on `incidents_by_type`; recommendations accepts a bare list and
  normalizes each item to a dict; geo `exposure` uses `str(... or "MEDIUM").upper()`. Regression
  cases added to `TestQuarterlyRobustness`.
  Siblings of the fixed Q2/Q3/Q4:
  - `incidents_by_type` loop reads `incident.get(...)` with no `isinstance(_, dict)` filter
    (geopolitical loop has one) → crashes on a list-of-strings.
  - `recommendations` `items` loop assumes each item is a dict (`.get`, `" " in title`,
    `title.isalpha()`, `add_run`) → crashes on list-of-strings.
  - Geo `exposure = country_data.get("exposure", "MEDIUM").upper()` → `None.upper()` on a present
    `null` (adjacent `threat_level` was hardened; `exposure` was not).
  _Fix:_ `isinstance(_, dict)` filters + `str(... or default).upper()`.

- ☑ **T1.3 · HIGH · HHS fails silently to zero.** _(done 2026-08-18)_
  No-CSV now returns `success=False` with a clear error (distinct from a valid CSV that parses to
  zero in-window rows, still `success=True`); `hhs_breach_csv_url` reads `HHS_BREACH_CSV_URL` so
  a deployed env can pin a direct/local CSV. Tests assert both branches. _Still worth doing:_
  verify the live portal export via `scripts/diagnose_hhs.py` on a real-network host.
  With no pinned CSV URL, the JSF export omits PrimeFaces ajax params (rarely yields CSV) and the
  Playwright fallback needs Chromium; all misses return `success=True, data=[]` —
  indistinguishable from "no healthcare breaches this quarter." Healthcare is the most relevant
  sector for a life-sciences customer.
  _Fix:_ return a distinct failure signal when no HHS source resolves; support a pinned direct/
  local CSV source for deployed environments.

---

## Tier 2 — Correctness & trust

- ☑ **T2.1 · HIGH · Stat-card `change_pct` is always red.** _(done 2026-08-18)_ New
  `_change_pct_color()` — red +, green −, gray 0%/N/A/unparseable — applied at the render site
  (was hardcoded red). Gray when there's no change value to signal on.
- ☑ **T2.2 · HIGH · Grounding token-OR hole (Q8/Q12).** _(done 2026-08-18)_ Added
  `SourceIndex.mentions_entity()` — whole name OR **all** distinctive tokens (AND, not any) — and
  used it for quarterly victims + geo actors. `mentions()` is unchanged for other callers (its
  token tolerance is needed for actor normalization). _Residual:_ a single common-word actor name
  ("China") is still grounded by its lone token — rare, low-risk.
- ☑ **T2.3 · HIGH · Empty-dataset stat cards render ungrounded AI numbers.** _(done 2026-08-18)_
  Ungrounded paths (no dataset, or mode `none`) stamp an honest "NOT grounded in a breach dataset"
  methodology marker; `enrich` mode forces **Records Exposed** to N/A (it was left as the AI's
  value). Non-destructive: a compliant model's N/As stand. _(If you'd rather force all ungrounded
  counts to N/A rather than mark them, it's a one-line change.)_
- ☑ **T2.4 · MED · No backstop against a fabricated QoQ %.** _(done 2026-08-18)_
  `_apply_prior_quarter_stats` now forces `prior_value`/`change_pct` to N/A when there is no stored
  baseline AND no real prior value behind the delta — a legitimate delta (real prior_value) is
  kept.
- ☑ **T2.5 · MED · gate1a reconciles the grounded card against the wrong source.** _(done
  2026-08-18)_ The Intel471 breach-count reconciliation is skipped when the card is dataset-grounded
  (detected via the generator's methodology stamp), since VCDB/HHS aren't in the gate's tier1_data;
  the legacy check still runs for ungrounded cards.

---

## Tier 3 — Breach-data accuracy

- ☑ **T3.1 · MED · Dedup collapses distinct anonymized victims sharing a date.** _(done
  2026-08-18)_ Placeholder orgs (`Undisclosed entity`, `Unknown`, …) are treated as identity-less
  and never merged; named orgs dedup on a normalized key (lowercased, punctuation- and
  legal-suffix-stripped) so `Acme Health, Inc.` and `acme health inc` collide across sources.
- ☑ **T3.2 · MED · VCDB year-only / month-only dates default to Jan-01.** _(done 2026-08-18)_
  `_veris_date` now requires a real month; a year-only incident returns `""` (excluded from quarter
  bucketing) instead of being mis-attributed to Q1. Day still defaults to 1 (doesn't affect the
  quarter).
- ☑ **T3.3 · LOW-MED · Enrich-mode impact sample floor.** _(done 2026-08-18)_ The sector-weighted
  per-breach average is trusted only at ≥ 5 incidents (`_MIN_SAMPLE_FOR_SECTOR_AVG`); below that the
  enrich rescale falls back to the flat default so 3 incidents can't set the average for a much
  larger live count.

---

## Tier 4 — Lower-severity render / robustness / tests _(done 2026-08-18)_

- ☑ Render crash-class type-guards (T4.1): risk-levels via `str(... or default).upper()`;
  watch-item `subject` via `str(...)`; `display_name` via `or country_name`; `executive_summary`
  coerced (list joined / non-str stringified); geo bullets normalized with `_as_bullets` (a string
  no longer slices to one char per bullet); `common_factors` coerced to str.
- ☑ Recommendations as a bare list now renders (fixed in T1.2).
- ☑ Ungrounded narrative percentages: a short italic caveat is appended to `common_factors` when it
  cites a percentage, so an AI estimate isn't read as a measured statistic (T4.3).
- ☑ `records_exposed` sum now excludes `bool` and negatives; `_parse_date` drops the fragile
  `s[:len(fmt)+4]` truncation for a date-part split (T4.2).
- ☑ **Test gaps closed:** anonymized/cross-suffix dedup, VCDB year-only bucketing, HHS
  failure-vs-quiet-quarter, and a `create_and_upload_report` wiring test (the surrogate for the
  `function_app` grounding integration that would have caught T1.1).
  ◐ _Remaining (accepted):_ a full `fetch_hhs_breach_csv` POST-flow test (the JSF export
  orchestration) is left uncovered — heavy to mock; the pure parsers, decode, and collector
  failure-signal paths are tested, and the live flow is best verified with `scripts/diagnose_hhs.py`.

---

## Bottom line / sequencing

**Status: Tiers 1–4 all complete (2026-08-18).** A `quarterly --real` run now survives malformed
AI output, grounds its breach stat cards in the deployed path, colors QoQ deltas by direction,
refuses a fabricated multi-word victim, counts breaches accurately (no anonymized-collapse, no
Q1 inflation), and labels ungrounded estimates instead of presenting them as fact. 523 tests pass
(excluding the 2 `semantic_kernel`-gated modules).

**Remaining / accepted:**
- The full `fetch_hhs_breach_csv` JSF POST-flow test is uncovered (heavy to mock) — verify the live
  flow with `scripts/diagnose_hhs.py` on a real-network host.
- T2.2 residual: a single common-word actor name (e.g. an actor literally "China") is still
  grounded by its lone token — rare, low-risk.
- T2.3 is non-destructive (marks ungrounded cards rather than forcing every count to N/A); flip to
  hard-N/A if preferred.

**Next once verified live:** the strategic enhancements discussed separately — a persisted
quarter ledger for exact QoQ, and new sources (ransomware.live, SEC 8-K Item 1.05, Maine AG,
CISA KEV quarterly additions).
