# Code Review & Suggestions

> Review conducted on 2026-03-13 against the current `main` branch.

---

## Summary

The CTI Report Generator is a well-architected, enterprise-grade Azure Functions application with clean modular design, strong security practices (Key Vault, managed identity), and solid async patterns. The separation into collectors, agents, and reports is effective and extensible.

That said, there are several areas where the codebase could be improved — ranging from bugs that will break production imports to dead code, missing tests, and opportunities to reduce duplication.

---

## Critical Issues

### 1. Broken Import Paths in `src/core/keyvault.py` and `src/agents/threat_analyst.py`

Four imports use bare module names instead of the `src.core.` package path. These will fail at runtime when called from `function_app.py`:

| File | Line | Broken Import | Should Be |
|------|------|--------------|-----------|
| `src/core/keyvault.py` | 17 | `from config import azure_config` | `from src.core.config import azure_config` |
| `src/core/keyvault.py` | 18 | `from models import APICredentials` | `from src.core.models import APICredentials` |
| `src/core/keyvault.py` | 100 | `from config import get_enabled_collectors` | `from src.core.config import get_enabled_collectors` |
| `src/agents/threat_analyst.py` | 504 | `from config import industry_filter_config` | `from src.core.config import industry_filter_config` |

These likely work locally because of `sys.path` manipulation or the working directory, but are fragile and non-standard.

### 2. Hardcoded Key Vault URL Fallback

`src/core/config.py:117` defaults to a specific Key Vault URL:
```python
return os.environ.get("KEY_VAULT_URL", "https://kv-cti-reporting.vault.azure.net/")
```

If `KEY_VAULT_URL` is missing in a new environment, the app silently connects to the wrong vault. This should raise an error when the env var is absent to fail fast.

---

## High-Priority Improvements

### 3. Prompt Injection Risk in AI Analysis

`src/agents/threat_analyst.py` injects raw collector JSON directly into LLM prompts (lines ~237-304 and ~524-530):
```python
return f"""... {json.dumps(intel471_data[:50], indent=2)} ..."""
```

If any threat intelligence API returns data containing prompt-manipulation strings, the AI could produce misleading analysis. Consider:
- Sanitizing or escaping external data before prompt inclusion
- Using structured message parameters instead of string interpolation
- Adding length/content validation on collector outputs

### 4. Dead Code: IOC Correlator

`ioc_correlator.py` (514 lines) and `ioc_correlation_integration.py` (322 lines) are **never called** from `function_app.py` or any other module. This is ~836 lines of unmaintained code. Either integrate it into the pipeline or remove it to reduce maintenance burden.

### 5. No Tests for Critical Paths

The test suite covers collectors and report formatting but has **zero tests** for:
- `function_app.py` — the Azure Functions entry point and orchestration logic
- `src/agents/threat_analyst.py` — the AI analysis pipeline
- `src/core/keyvault.py` — credential retrieval
- IOC correlation logic

These are the highest-risk components (external API calls, secret management, AI orchestration) and should be tested with mocks.

### 6. Broad Exception Handling

Multiple files catch `Exception` generically, which masks distinct failure modes:
- `src/core/keyvault.py:82, 178`
- `src/reports/base.py:203, 588`
- `src/reports/blob_storage.py:56, 75, 166`

Prefer catching specific exceptions (`AzureError`, `ValueError`, `OSError`) so that unexpected errors propagate rather than being silently logged.

---

## Medium-Priority Improvements

### 7. DRY Violation: Duplicate Merge Functions

`function_app.py` has two near-identical functions:
- `_merge_rapid7_exposure_into_analysis()` (lines 20-39)
- `_merge_crowdstrike_exposure_into_analysis()` (lines 42-67)

Both extract CVE-to-count mappings and apply them to `cve_analysis`. A single parameterized helper would eliminate ~25 lines of duplication:

```python
def _merge_exposure_into_analysis(analysis, source_data, extract_fn, *, overwrite=False):
    """Generic exposure merger. extract_fn(item) -> list of (cve_id, count) tuples."""
    ...
```

### 8. Incomplete Data Model for Quarterly Reports

`ThreatAnalysisResult` in `src/core/models.py` only captures weekly analysis fields. Quarterly AI responses include `risk_assessment`, `breach_landscape`, `geopolitical_threats`, and `looking_ahead` — all returned as untyped `Dict[str, Any]`. Adding typed dataclasses for quarterly analysis would improve IDE support and catch schema mismatches early.

### 9. Unused Import

`src/collectors/http_utils.py:9` imports `from functools import wraps` but never uses it. Remove to keep imports clean.

### 10. Missing Null Guard in `http_utils.py`

`HTTPClient.get()` and `get_raw_response()` access `self._session` without verifying it was initialized via the async context manager. If called outside a `async with HTTPClient(...) as client:` block, this will produce a confusing `AttributeError` on `None`. A guard or assertion would make the error message clear.

### 11. `get_raw_response()` Lacks Retry Logic

`src/collectors/http_utils.py:248` — `get_raw_response()` makes a single HTTP call with no retry, unlike `get()` which uses `retry_with_backoff`. If this is intentional, document why; otherwise, add retry logic for consistency.

---

## Low-Priority / Housekeeping

### 12. ThreatQ Disabled via Code Comment

`src/core/config.py:137-138`:
```python
# ThreatQ disabled - secrets not configured yet
return ["nvd", "intel471", "crowdstrike", "rapid7"]
```

This should be driven by the `ENABLED_COLLECTORS` env var or a documented feature flag rather than a code comment. The comment will become stale.

### 13. `test_local.py` is Very Large (23,638 lines)

This file appears to contain hardcoded mock data alongside test logic. Consider:
- Moving mock data to JSON fixture files in `tests/fixtures/`
- Splitting test scenarios into separate modules
- This would make the file navigable and the fixtures reusable

### 14. Inconsistent Collector Result Access in `function_app.py`

Lines 307-313 use `hasattr()` checks on collector results:
```python
collector_results.get('Intel471', {}).success if hasattr(collector_results.get('Intel471', {}), 'success') else False
```

This pattern is brittle. Since `collect_all()` returns `Dict[str, CollectorResult]`, accessing `.success` directly (as done elsewhere in the file) is sufficient. The `hasattr` check suggests uncertainty about the return type — a type annotation or assertion would be cleaner.

### 15. Consider Adding a Linter/Formatter Configuration

The project has `.vscode/settings.json` with basic type checking but no `pyproject.toml`, `ruff.toml`, or similar linter/formatter config. Adding `ruff` or `flake8` configuration would catch issues like unused imports automatically and enforce consistent style.

---

## Architecture Strengths (Keep Doing These)

- **Registry pattern** for collectors and reports — easy to add new sources
- **Async parallel collection** via `asyncio.gather()` — good performance
- **Frozen dataclasses** for configuration — immutable, type-safe
- **Azure Key Vault** for all secrets — no hardcoded credentials
- **Exponential backoff** in HTTP client — resilient to transient failures
- **Clear separation** of collect → analyze → generate → upload
- **Comprehensive documentation** (README, CHANGES, system flow diagrams)
