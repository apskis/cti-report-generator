# Report Quality Validation System

This system ensures quarterly reports meet quality standards before being delivered.

## What It Does

The validation system automatically checks:

✅ **OSINT Citations** - All OSINT sources are cited with [5], [6], [7] in report content  
✅ **Company Names** - Notable examples include actual company names, not generic terms  
✅ **Illumina Context** - Illumina OSINT is used and cited in relevance bullets  
✅ **Executive Summary** - Proper length (3-4 paragraphs) covering all required sections  
✅ **Citation Consistency** - Numbers are sequential and all sources are referenced

## How To Use

### Automatic Validation (Built-In)

Validation runs automatically every time you generate a quarterly report:

```bash
python scripts/run_local.py quarterly --local --real --output test_output
```

The validation results appear in the log output after "AI-Powered Analysis".

### Manual Testing

Run quality checks on mock data without generating a full report:

```bash
python scripts/smoke_report_quality.py
```

This quickly validates report structure without calling APIs or generating the Word document.

## What Gets Checked

### 1. OSINT Citation Check
- **FAIL**: OSINT sources listed but no inline citations [N] in executive summary or relevance bullets
- **PASS**: All listed sources are cited at least once in report content

### 2. Notable Example Check
- **FAIL**: Uses generic terms like "Pharma manufacturer", "Genomics institute", "Biotech company"
- **PASS**: Includes actual company names like "Covenant Health: ransomware attack disrupted..."

### 3. Illumina Context Usage Check
- **WARNING**: Illumina context provided but no Illumina-specific OSINT sources cited
- **PASS**: Illumina articles are included in osint_sources_used when context is referenced

### 4. Executive Summary Length Check
- **WARNING**: Executive summary has fewer than 3 paragraphs
- **PASS**: 3-4 paragraphs covering threat landscape, geopolitical threats, breaches, and impact

### 5. Citation Consistency Check
- **WARNING**: Citation numbers don't start at 5 or aren't sequential
- **PASS**: Citations follow proper numbering (5, 6, 7, ...)

## AI Pre-Flight Checklist

When Illumina context is available, the system logs what the AI should do:

```
PRE-FLIGHT CHECKLIST - AI Should:
  ✓ Use Illumina context for geopolitical relevance bullets
  ✓ Cite Illumina sources with [5], [6], [7] in relevance bullets
  ✓ Add inline citations in executive summary
  ✓ Include actual company names in notable_example fields
  ✓ List cited sources in osint_sources_used array
```

## AI Verification Checklist

The AI prompt includes a final checklist it must verify before returning JSON:

- [ ] Every source in osint_sources_used is cited with [N]
- [ ] Every notable_example includes actual company name
- [ ] Illumina context referenced in relevance bullets with citations
- [ ] Executive summary is 3-4 paragraphs
- [ ] Citation numbers sequential (5, 6, 7, ...)
- [ ] Each incident type has specific company in notable_example
- [ ] Relevance bullets mention Illumina products/platforms

## For Developers

### Adding New Validation Checks

Edit `src/validation/quarterly_validation.py`:

```python
def _check_new_requirement(self, analysis_result: Dict[str, Any]) -> None:
    """Check for new requirement."""
    if not meets_requirement:
        self.issues.append("Description of problem")
```

### Running Tests Before Commit

```bash
# Quick quality check
python scripts/smoke_report_quality.py

# Full generation test
python scripts/run_local.py quarterly --local --mock --output test_output
```

### Integration Points

1. **`src/agents/threat_analyst.py`** - Validation runs after AI parsing
2. **`src/validation/quarterly_validation.py`** - Validation logic
3. **`scripts/smoke_report_quality.py`** - Standalone testing script

## Benefits

✅ **Catch issues before delivery** - Validation happens during generation  
✅ **Clear error messages** - Know exactly what's wrong and where  
✅ **Prevent regressions** - Automated checks catch quality degradation  
✅ **Faster iteration** - Test mock data without waiting for APIs  
✅ **Better prompts** - Pre-flight checklist and verification guide the AI
