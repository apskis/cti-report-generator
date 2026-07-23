# Quarterly Report Audit — code review of the quarterly path

_Audit date: 2026-07-23 · Branch: `claude/repo-audit-suggestions-c8q7o7` · Scope: the QUARTERLY
report generator, its gate path (Gates 1A/1F/1E/1C/1D + Gate 6 quarterly branches), and the
strategic AI analysis + data flow._

**Method:** three parallel code-review passes (report generator, gate framework, AI/data flow),
findings cross-checked against source. This mirrors the weekly remediation done earlier.

## Bottom line

The quarterly path is **substantially more fragile than weekly** and has **never been run against
real data** in this session. Three classes of problem:

1. **Pipeline-aborting crashes** — several code paths raise uncaught exceptions on ordinary
   AI output (integer counts, null fields, a list of country strings, a malformed `change_pct`,
   and Gate 1D returning `HALT` which the orchestrator turns into a bare `RuntimeError`). A real
   quarterly run will very likely crash before producing a `.docx`.
2. **Anti-hallucination guard is effectively off for quarterly** — Gate 6's deterministic
   grounding and most Track A scanners were written against the *weekly* report shape and
   silently no-op on quarterly's `breach_landscape`/`geopolitical_threats` shape. Meanwhile the
   strategic prompt **demands fabricated quarter-over-quarter numbers** that no source supplies.
3. **Parity gaps with the weekly fixes** — no subscript citations, no white-page styling, a
   silent templated-fallback with no "AI unavailable" marker, and OSINT full-text never reaches
   the strategic analyzer.

Good news: the specific `.get()`-on-dataclass crash we fixed in weekly does **not** recur in the
quarterly Gate 1A, and the quarterly path already uses the config-driven temperature/seed omission,
so it is gpt-5.6-compatible with no change.

---

## Part 1 — Crashes / pipeline-aborting bugs (fix first)

| ID | Severity | Location | Bug | Trigger |
|---|---|---|---|---|
| **Q1** | High | `gate1d_source_attribution.py:49-51,287-300` | Gate 1D **returns** `status="HALT"` on any issue instead of raising `GateHaltError`; `run_full_sequence` (`orchestrator.py:211-217`) turns a non-`{COMPLETE,PASS,BLOCK}` status into a bare `RuntimeError`, which `pipeline_hook` doesn't catch → **whole run crashes before Gate 6**. | One `stat_cards.change_pct="45%"` (missing `+`). |
| **Q2** | High | `quarterly_report.py:840,849` | `add_run(incident.get("current_count"))` passes an **int** to python-docx → `TypeError: 'int' object is not iterable`. Same risk on `stat_cards` values (`714,724,731-733`). | AI emits counts as integers (it naturally does). |
| **Q3** | High | `quarterly_report.py:1187-1189,1290` | `geopolitical_threats` loop calls `entry.get(...)` with no `isinstance(entry, dict)` guard — the **exact twin** of the weekly "IOC has no attribute get" crash. | `geopolitical_threats: ["China","Russia"]` (list of strings). |
| **Q4** | High | `quarterly_report.py:404,415-418` | `risk_assessment` present-but-`null`, or any risk value `null`, → `AttributeError` (`.get`/`.upper` on `None`). `.get(k, default)` doesn't protect a present-but-null value. | `{"risk_assessment": null}` or `{"nation_state": null}`. |
| **Q5** | Med | `gate1e_ai_quality.py:333` (also `321-324`, `gate1a:424`, `gate1d:125`) | `int(change_pct[1:-1])` / `.startswith` assume `"+NN%"` string; `"+high%"`, `"+40"` (no `%`), or a numeric value → `ValueError`/`AttributeError`, unhandled → run aborts. | Model emits a non-canonical `change_pct`. |
| **Q6** | Med | `pipeline_hook.py:79` | Interactive mode hardcodes the **weekly** sequence for all report types; a quarterly interactive run skips 1F/1E/1D then hits an uncaught `RuntimeError` at clearance (`_previous_gate("1C","quarterly")=="1E"`, uncleared). | Quarterly report run with `interactive_mode=True`. |
| **Q7** | Med | `quarterly_report.py:1698-1701` | `looking_ahead` present-but-`null` → `.get` on `None` before its own guard runs. | `{"looking_ahead": null}`. |

All of Q2–Q4, Q7 are the same "present-but-null / wrong-type from the AI" class the weekly report
already hardened against; the strategic path just never got that treatment.

---

## Part 2 — Anti-hallucination guard is off for quarterly

| ID | Severity | Location | Problem |
|---|---|---|---|
| **Q8** | High | `grounding.py:171-218` via `gate6:742-743` | `verify_report_grounding` only checks `cve_analysis[].cve_id`, `apt_activity[].actor_name`, `industry_incidents[].organization`; `rederive_statistics` only fires on `report["statistics"]`. **None of these keys exist in a quarterly report** → the framework's only real grounding produces **zero** findings. A fabricated `incidents_by_type[].notable_example` victim ("Acme Genomics Inc") or invented `geopolitical_threats[].name` passes straight to publish. |
| **Q9** | High | `threat_analyst.py:1853-1905,2123-2136` | The strategic schema **demands** `stat_cards.prior_value`/`change_pct` and `incidents_by_type.prior_count`, and instructs "calculate the percentage change from prior quarter" — but **no prior-quarter data is ever supplied to the model**. Every QoQ number is invented, then rendered prominently in red. Directly contradicts the prompt's own "you are NOT provided historical data / do not use percentage increases" rule (`1836`). |
| **Q10** | High | `gate6:404-416` (`_scan_narrative_cohesion` quarterly branch) | Compares exec-summary CVEs against `report["threat_findings"]`, which is **always empty** for quarterly → every CVE cited in the strategic summary becomes a Track A `BLOCK` ("missing from threat findings table" — a table quarterly doesn't have). **A well-grounded quarterly report that names any CVE is falsely blocked.** |
| **Q11** | High | `threat_analyst.py:1369-1374,2307,2323-2329` | On any AI error, `analyze_strategic` silently returns a fully-templated China/Russia/NK brief with **no "AI unavailable" marker** (weekly's fallback has one at `1234`). It swallows all exceptions, so the re-raise guard in `gate5:141-143` is dead. A polished board brief can publish with the model never having run and nobody knowing. |
| **Q12** | Med | `threat_analyst.py:2144-2187`, `validation/quarterly_validation.py:19-135` | `notable_example` victim validation only rejects a fixed generic-phrase blocklist and checks for a `:` separator — it **never verifies the named company appears in the source breach data**. "Regeneron: ransomware…" (a real, plausible, absent company) passes and renders as fact. |
| **Q13** | Med | `function_app.py:298-299` | `get_previous_context("quarterly", lookback_weeks=52)` is fetched then **discarded** (never passed to `analyze_strategic`). The one source of real prior-quarter grounding is thrown away — forcing the fabrication in Q9. |
| **Q14** | Med | `gate5:83-90`, `threat_analyst.py:1745` | `analyze_strategic` has **no `osint_data` parameter**; Gate 5 builds OSINT but passes it only on the weekly branch. So the OSINT full-text work benefits weekly only, and the schema's `osint_sources_used` / `[5]+` citations are mostly unusable in quarterly. (Intel471 `full_text` *does* reach the model.) |

**Net:** for quarterly, publish-blocking rests almost entirely on Gates 1E/1F's narrow generic-name
blocklists. Grounded fabrication of breach victims and geopolitical actors is uncaught (Q8), the AI
is actively asked to fabricate numbers (Q9/Q13), and the one active grounding-ish check falsely
blocks legitimate content (Q10).

---

## Part 3 — Always-fire / dead / wrong-key logic

| ID | Severity | Location | Problem |
|---|---|---|---|
| **Q15** | Med | `gate1a_statistics.py:356-357` | Reads Gate 4 payload key `"structured_assembly"`; Gate 4 actually stores `"assembly"` (`gate4:317`, and `gate6:719` reads it correctly). So `has_geopolitical` is **always False** → the quarterly geopolitical check always warns. (Secondary: Gate 4 sets that field to a **string** placeholder when empty, so even fixed, `len()>0` misreads the absence marker as "present".) |
| **Q16** | High | `gate6:492` (`_collect_prior_gate_findings`) | Gate 1D's output is consumed by **nothing** (folder reads only 1C/1E/1F). Combined with Q1, 1D is all-or-nothing broken: issues → crash; warnings → ignored. |
| **Q17** | Med | `quarterly_report.py:1306` | Threat-level badge reads `country_data.get("threat_level","MEDIUM")` but the AI emits `"level"` (schema `1910`, all fallbacks `1645-1668`,`2380-2405`). Pre-render filter tolerates both keys but never writes it back → **every geopolitical card shows "MEDIUM"** regardless of the real assessment. |
| **Q18** | Med | `quarterly_report.py:607-610` | Trend display maps **both** `↑`/INCREASED and `↓`/DECREASED to the literal "Unchanged" → risk cards never show direction. |
| **Q19** | Med | `quarterly_report.py:752,840,849` | `incidents_by_type` is read from **inside** `breach_landscape`, but the docstring/tests put it at the **top level**; and the code reads `prior_count` while the schema uses `prev_count`. Result today: the table is silently skipped (which is the only reason Q2's int-crash isn't already firing in tests). |
| **Q20** | Low | `pipeline_hook.py:55-59`; `gate1d:133`,`gate1e:125`,`gate1f:164` | Company-OSINT (`customer_profile.osint_source_name`) is never placed in `tier1_data`, so all three gates' "Illumina context used?" checks are permanently "no data" — can never pass or meaningfully fail. |
| **Q21** | Low | `gate1d:155-284` | Gate 1D's entire **weekly branch is dead code** (1D only runs in quarterly), misleadingly implying it validates weekly. |
| **Q22** | Low | `gate1a:295-458` | Quarterly 1A does **no lookback-window/timestamp validation** (weekly does the 90-day-equivalent 7-day check) — stale out-of-window records go unflagged. |

---

## Part 4 — Report-generator parity & polish

| ID | Severity | Location | Problem |
|---|---|---|---|
| **Q23** | Med | quarterly `generate()` (no `_subscript_all_citations()`) | **Subscript-citation pass is entirely absent** from quarterly (weekly got it). The helpers in `weekly_report.py` are module-level and reusable — cleanest fix is to move them into `base.py` and call from both generators. |
| **Q24** | Low | quarterly `generate()` vs `weekly:159-162` | Quarterly never sets the **white page background** / `Normal` font color to dark, so it can render on a dark canvas in dark-mode editors. |
| **Q25** | Low | `quarterly_report.py` | Side effect: every `generate()` writes `data/historical/quarterly_risk_history.json` (unmocked in tests → hits real filesystem). Dead methods `_create_metric_cards`/`_create_breach_metric_cards` unused; redundant double `run.font.color.rgb` assignments in several places. |
| **Q26** | Low | `quarterly_report.py:677` | `stat_cards` render only when `len==4` exactly; 3 or 5 render nothing, silently. |

---

## Part 5 — Test coverage gaps

`tests/test_reports.py` quarterly coverage exercises only **missing** keys (`{}`), never **present-but-null**
or wrong-type values, so Q2/Q3/Q4/Q7 crashes are all uncaught. No test renders `incidents_by_type` at
the location the code reads, asserts trend direction (Q18), threat-level badge (Q17), or citation
subscripts (Q23). No gate test exercises the quarterly sequence end-to-end (would surface Q1/Q10/Q15).

**Add:** a parametrized "malformed strategic analysis" test (null risk_assessment, null risk values,
geo list-of-strings, integer counts, null looking_ahead, bad change_pct) asserting `generate()` and the
quarterly gate sequence degrade without raising.

---

## Suggested build order (mirrors the weekly remediation)

**Tier A — stop the crashes (highest value, lowest risk):** Q1 (1D halt semantics), Q2/Q3/Q4/Q7
(report-generator null/int/type guards), Q5 (`change_pct` parsing), Q6 (interactive sequence). Without
these a real quarterly run likely crashes.

**Tier B — restore the anti-hallucination guard:** Q8 (quarterly-aware grounding for
`notable_example`/geo names + stat re-derivation), Q10 (fix the false-blocking narrative check), Q11
(mark the templated fallback), Q12 (validate victims against source), Q9/Q13 (either feed real prior
data or stop demanding QoQ numbers), Q16 (consume or remove 1D).

**Tier C — correctness & parity:** Q15/Q17/Q18/Q19 (wrong-key / display bugs), Q23/Q24 (subscript
citations + white page), Q14 (OSINT full-text into strategic), plus the Part-5 tests.

**Tier D — cleanup:** Q20/Q21/Q22/Q25/Q26.

Every finding above is verified against source with a concrete failure scenario. Recommended first
step: Tier A, because it's what makes a real quarterly `--real` run survive to produce a `.docx` at all.
