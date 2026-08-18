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

- ☐ **T3.1 · MED · Dedup collapses distinct anonymized victims sharing a date.** Key is
  `(organization.lower(), date)`; collectors emit `"Undisclosed entity"`, so N unnamed same-date
  VCDB breaches dedupe to one. Cross-source dedup is also largely ineffective (different names /
  date semantics → double-counts). `breach_metrics.py:119-135`.
- ☐ **T3.2 · MED · VCDB year-only / month-only dates default to Jan-01** → imprecise incidents all
  land in Q1, inflating it. `vcdb_collector.py:66-77`.
- ☐ **T3.3 · LOW-MED · Enrich-mode impact** multiplies a live count by a sector average derived
  from as few as 3 incidents — needs a sample-size floor before trusting the weighting.

---

## Tier 4 — Lower-severity render / robustness / tests

- ☐ Render crash-class (low probability): risk-level on int (`:711-714`), watch-item `subject`
  raw `add_run` (`:1969`), `display_name` `len()` on null (`:1472`), `executive_summary` assumed
  str (`:603`).
- ☐ Recommendations as a bare list (not `{"items":[…]}`) silently dropped to "unavailable".
- ☐ Geo bullet as a string renders one character per bullet.
- ☐ Ungrounded narrative percentages ("34% of incidents…") read as hard stats — label or ground.
- ☐ `records_exposed` sum counts `bool` (int subclass) and negatives; `_parse_date` truncation
  heuristic fragile.
- ☐ **Test gaps:** breach-layer dedup edge cases, VCDB year-only bucketing, the HHS POST flow, and
  a `function_app` grounding integration test (its absence let T1.1 ship).

---

## Bottom line / sequencing

Every Tier-A crash from July (Q1–Q7) is fixed; a `quarterly --real` run should survive the
previously-audited failures. The work here is: **T1** (make a real run both survivable and
meaningful), then **T2.1 / T2.2** (the most visible defect and the trust-critical grounding hole),
then Tier 3–4 batched. HHS (T1.3) is best verified against the live portal —
`scripts/diagnose_hhs.py` exists for exactly that.
