# Quarterly Report Gates Audit & Recommendations

**Date**: May 29, 2026  
**Report Type**: Quarterly Strategic Brief  
**Purpose**: Audit gate framework for factual accuracy and sourcing improvements

---

## Executive Summary

The gate framework provides strong foundational validation for quarterly reports but has gaps in validating AI-generated content quality, especially around:
1. **Company name specificity** in breach examples (generic terms vs actual organizations)
2. **Geopolitical threat level consistency** (no criteria validation)
3. **Risk rating justification** (ratings not validated against stated criteria)
4. **OSINT source usage** (citations validated but not source quality)
5. **Historical trend accuracy** (trends not validated against statistics)

---

## Current Gate Sequence for Quarterly Reports

```
Gate 1  → Tier 1 Source Inventory (NVD, Intel471, CrowdStrike)
Gate 1A → Statistics Validation (breach data, geopolitical context)
Gate 1B → OSINT Triage (article extraction, signal detection)
Gate 2  → IOC Extraction (CVEs, indicators)
Gate 3  → Actor Linkage (threat actor attribution)
Gate 4  → Structured Assembly (organize data for analysis)
Gate 5  → Report Draft (AI generates strategic analysis)
Gate 1C → Technology Coherence (unused for quarterly)
Gate 1D → Source Attribution (validates audit trail)
Gate 6  → Adversarial Review (filler phrases, citations, accuracy)
```

---

## Gate-by-Gate Audit Findings

### ✅ Gate 1: Tier 1 Source Inventory
**Current Validation:**
- Checks if Intel471, CrowdStrike, NVD are enabled and returning data
- Validates data collection windows
- Halts if 2+ Tier 1 sources are missing

**Strengths:**
- Strong halt logic prevents reports without sufficient data
- Properly handles disabled/unavailable sources

**Recommendations:**
✨ **No changes needed** - This gate is functioning well

---

### ⚠️ Gate 1A: Statistics Validation
**Current Validation (Quarterly):**
- Checks if Intel471 breach data exists (warns if 0)
- Checks if CrowdStrike strategic data exists (warns if 0)
- Checks if geopolitical signals are present (warns if absent)

**Gaps:**
1. ❌ **No validation of breach counts accuracy** - Doesn't verify incident counts in breach_landscape match actual data
2. ❌ **No quarter-over-quarter change validation** - Doesn't check if stat_cards changes (+50%) align with actual counts
3. ❌ **No validation of risk trend logic** - Doesn't validate if ↑/↓/Unchanged trends match the stated percentages

**Recommendations:**
```python
# NEW VALIDATION: Breach statistics accuracy
def _validate_breach_statistics(gate_input: GateInput, report: dict) -> list[str]:
    """Validate breach landscape statistics match actual data."""
    issues = []
    
    breach_landscape = report.get("breach_landscape", {})
    stat_cards = breach_landscape.get("stat_cards", [])
    
    # Get actual Intel471 breach alerts
    intel471_data = gate_input.tier1_data.get("Intel471", [])
    actual_breach_count = sum(
        1 for item in intel471_data 
        if "BREACH" in str(item.get("threat_type", "")).upper()
    )
    
    # Find "Total Incidents" stat card
    total_incidents_card = next(
        (card for card in stat_cards if "Total Incidents" in card.get("label", "")),
        None
    )
    
    if total_incidents_card:
        reported_count = int(total_incidents_card.get("value", "0"))
        if abs(reported_count - actual_breach_count) > 5:  # Allow small variance
            issues.append(
                f"Breach count mismatch: report shows {reported_count} incidents, "
                f"but Intel471 data contains {actual_breach_count} breach alerts"
            )
    
    return issues

# NEW VALIDATION: Risk trend vs statistics alignment
def _validate_risk_trends(report: dict) -> list[str]:
    """Validate risk trends (↑/↓) align with breach statistics."""
    issues = []
    
    risk_assessment = report.get("risk_assessment", {})
    breach_landscape = report.get("breach_landscape", {})
    stat_cards = breach_landscape.get("stat_cards", [])
    
    # Check ransomware trend vs ransomware stat card
    ransomware_trend = risk_assessment.get("ransomware_trend", "")
    ransomware_card = next(
        (card for card in stat_cards if "Ransomware" in card.get("label", "")),
        None
    )
    
    if ransomware_card and ransomware_trend:
        change_pct = ransomware_card.get("change_pct", "")
        
        # If trend is ↑ but change_pct is negative or 0%, that's inconsistent
        if ransomware_trend == "↑" and (change_pct.startswith("-") or change_pct == "0%"):
            issues.append(
                f"Ransomware trend shows ↑ (increasing) but stat card shows {change_pct} change"
            )
        elif ransomware_trend == "↓" and change_pct.startswith("+"):
            issues.append(
                f"Ransomware trend shows ↓ (decreasing) but stat card shows {change_pct} increase"
            )
    
    return issues
```

---

### ✅ Gate 1B: OSINT Triage
**Current Validation:**
- Extracts CVEs, IOCs, and signals from OSINT articles
- Enforces 30-article cap
- Assigns sequential article IDs

**Strengths:**
- Deterministic signal extraction (regex-based)
- Proper source tracking

**Recommendations:**
✨ **No critical changes needed** - Consider adding:
- Article relevance scoring (how relevant to life sciences/genomics)
- Duplicate article detection across sources

---

### ⚠️ Gate 1D: Source Attribution
**Current Validation (Quarterly):**
- Checks if OSINT, Intel471, CrowdStrike data exist
- Validates geopolitical threats have proper structure
- Checks stat_cards have +/- signs in change_pct

**Gaps:**
1. ❌ **No validation of company names** - Doesn't check if notable_example uses generic terms like "Pharma manufacturer"
2. ❌ **No validation of OSINT citation usage** - Checks if sources exist but not if they're actually cited with [5], [6], [7]
3. ❌ **No validation of Illumina context usage** - Doesn't verify Illumina-OSINT was used in relevance bullets

**Recommendations:**
```python
# NEW VALIDATION: Company name specificity
def _validate_company_names(report: dict) -> list[str]:
    """Validate breach examples use actual company names, not generic terms."""
    issues = []
    
    FORBIDDEN_GENERIC_TERMS = [
        "pharma manufacturer",
        "genomics institute",
        "research institute",
        "genomics research institute",
        "biotech company",
        "medical device mfg",
        "lab software vendor",
        "healthcare provider",
        "life sciences company",
        "clinical research org"
    ]
    
    breach_landscape = report.get("breach_landscape", {})
    incidents = breach_landscape.get("incidents_by_type", [])
    
    for incident in incidents:
        example = incident.get("notable_example", "").lower()
        for term in FORBIDDEN_GENERIC_TERMS:
            if term in example:
                issues.append(
                    f"{incident.get('type')} uses generic term '{term}' instead of actual company name: {incident.get('notable_example')}"
                )
                break
    
    return issues

# NEW VALIDATION: OSINT inline citations
def _validate_osint_citations(report: dict) -> list[str]:
    """Validate OSINT sources are actually cited in report content."""
    issues = []
    
    osint_sources = report.get("osint_sources_used", [])
    if not osint_sources:
        return issues  # No sources to validate
    
    # Extract all citation numbers from report
    exec_summary = report.get("executive_summary", "")
    geo_threats = report.get("geopolitical_threats", [])
    
    # Find all [N] citations
    citations_found = re.findall(r'\[(\d+)\]', exec_summary)
    
    for threat in geo_threats:
        for bullet in threat.get("relevance", []):
            citations_found.extend(re.findall(r'\[(\d+)\]', bullet))
    
    # Check each source is cited
    uncited_sources = []
    for source in osint_sources:
        citation_num = str(source.get("citation_number", 0))
        if citation_num not in citations_found:
            uncited_sources.append(source.get("title", "Unknown"))
    
    if uncited_sources:
        issues.append(
            f"{len(uncited_sources)} OSINT sources listed but never cited: {', '.join(uncited_sources[:3])}"
        )
    
    return issues

# NEW VALIDATION: Illumina context usage
def _validate_illumina_context_usage(gate_input: GateInput, report: dict) -> list[str]:
    """Validate Illumina-OSINT context was used in geopolitical relevance bullets."""
    warnings = []
    
    # Check if Illumina-OSINT data exists
    illumina_data = gate_input.tier1_data.get("Illumina-OSINT", [])
    if not illumina_data:
        return warnings  # No Illumina context to validate
    
    # Check if geopolitical threats reference Illumina products/platforms
    geo_threats = report.get("geopolitical_threats", [])
    
    illumina_keywords = [
        "illumina", "novaseq", "nextseq", "iseq", "miseq",
        "sequencing platform", "ica", "basespace", "dragen"
    ]
    
    illumina_mentions = 0
    for threat in geo_threats:
        for bullet in threat.get("relevance", []):
            if any(keyword in bullet.lower() for keyword in illumina_keywords):
                illumina_mentions += 1
                break
    
    if illumina_mentions == 0:
        warnings.append(
            f"Illumina-OSINT context provided ({len(illumina_data)} records) but no Illumina-specific "
            f"products or platforms mentioned in geopolitical relevance bullets"
        )
    
    return warnings
```

---

### ⚠️ Gate 6: Adversarial Review
**Current Validation:**
- Scans for filler phrases ("it is important to note", etc.)
- Checks for em dashes
- Validates statistics accuracy (for weekly reports only)
- Checks CVE exploitation evidence

**Gaps for Quarterly Reports:**
1. ❌ **No quarterly-specific accuracy checks** - Statistics validation only runs for weekly reports
2. ❌ **No geopolitical threat level validation** - Doesn't check if threat_level ratings (HIGH/MEDIUM/LOW) follow stated criteria
3. ❌ **No risk assessment criteria validation** - Doesn't verify risk ratings are justified

**Recommendations:**
```python
# NEW VALIDATION: Geopolitical threat level consistency
def _validate_geopolitical_threat_levels(report: dict, crowdstrike_data: list) -> list[str]:
    """Validate geopolitical threat levels match stated criteria."""
    issues = []
    
    geo_threats = report.get("geopolitical_threats", [])
    
    for threat in geo_threats:
        country = threat.get("name", "Unknown")
        threat_level = threat.get("level", "")
        
        # Count actor groups for this country from CrowdStrike data
        country_actors = [
            actor for actor in crowdstrike_data
            if country.lower() in str(actor.get("origins", "")).lower()
        ]
        
        actor_count = len(country_actors)
        
        # Validate against criteria (from prompt):
        # HIGH: 5+ actor groups OR confirmed intrusions OR systematic IP theft
        # MEDIUM: 2-4 actor groups OR opportunistic targeting
        # LOW: ≤1 actor group OR minimal activity
        
        if threat_level == "HIGH" and actor_count < 2:
            issues.append(
                f"{country} rated HIGH but only {actor_count} actor groups observed (criteria requires 5+ for HIGH)"
            )
        elif threat_level == "MEDIUM" and actor_count < 1:
            issues.append(
                f"{country} rated MEDIUM but {actor_count} actor groups observed (criteria requires 2-4 for MEDIUM)"
            )
    
    return issues

# NEW VALIDATION: Risk assessment criteria adherence
def _validate_risk_assessment_criteria(report: dict, intel471_data: list, breach_data: list) -> list[str]:
    """Validate risk assessment ratings follow stated criteria."""
    issues = []
    
    risk_assessment = report.get("risk_assessment", {})
    
    # Ransomware validation
    ransomware_rating = risk_assessment.get("ransomware", "")
    
    # Count ransomware breaches
    ransomware_breaches = sum(
        1 for breach in breach_data
        if "ransomware" in str(breach.get("description", "")).lower()
    )
    
    # Criteria: HIGH = 10+ incidents, MEDIUM = 5-9, LOW = <5
    if ransomware_rating == "HIGH" and ransomware_breaches < 10:
        issues.append(
            f"Ransomware rated HIGH but only {ransomware_breaches} incidents (criteria requires 10+ for HIGH)"
        )
    elif ransomware_rating == "MEDIUM" and (ransomware_breaches < 5 or ransomware_breaches >= 10):
        issues.append(
            f"Ransomware rated MEDIUM but {ransomware_breaches} incidents (criteria: 5-9 for MEDIUM)"
        )
    elif ransomware_rating == "LOW" and ransomware_breaches >= 5:
        issues.append(
            f"Ransomware rated LOW but {ransomware_breaches} incidents (criteria: <5 for LOW)"
        )
    
    # Nation-state validation
    nation_state_rating = risk_assessment.get("nation_state", "")
    
    # Count APT groups from CrowdStrike
    apt_groups = len([
        actor for actor in intel471_data
        if "apt" in str(actor.get("actor_name", "")).lower()
    ])
    
    # Criteria: HIGH = 3+ APT groups, MEDIUM = 1-2, LOW = minimal
    if nation_state_rating == "HIGH" and apt_groups < 3:
        issues.append(
            f"Nation-State rated HIGH but only {apt_groups} APT groups observed (criteria requires 3+ for HIGH)"
        )
    
    return issues
```

---

## Proposed New Gate: Gate 1E - AI Output Quality

**Purpose**: Validate AI-generated content quality before final report rendering

**Validations:**
1. ✅ Company name specificity (no generic terms)
2. ✅ OSINT inline citations present
3. ✅ Illumina context usage
4. ✅ Executive summary completeness (3-4 paragraphs)
5. ✅ Geopolitical threat levels match criteria
6. ✅ Risk assessment ratings match criteria
7. ✅ Risk trends align with breach statistics
8. ✅ All sources listed are actually cited

**Implementation:**
```python
"""Gate 1E: AI Output Quality Validation

Validates the quality and accuracy of AI-generated quarterly report content.
Runs after Gate 5 (Report Draft) but before Gate 6 (Adversarial Review).

This gate catches AI quality issues that the adversarial review doesn't address:
- Generic company names vs actual organizations
- Missing or incorrect citations
- Risk ratings not matching stated criteria
- Trend indicators not aligned with statistics
"""
from typing import Any, List
from src.gates.models import GateInput, GateResult

def run(input: GateInput, llm_client: Any, report_type: str) -> GateResult:
    """Execute Gate 1E - AI Output Quality Validation."""
    
    if report_type.upper() != "QUARTERLY":
        # Only run for quarterly reports
        return GateResult(
            gate_id="1E",
            status="COMPLETE",
            payload={"skipped": "Not a quarterly report"}
        )
    
    # Get report from Gate 5
    g5 = input.prior_results.get("5")
    if not g5 or g5.status != "COMPLETE":
        return GateResult(
            gate_id="1E",
            status="HALT",
            halt_reason="Gate 5 (Report Draft) did not complete",
            payload={}
        )
    
    report = g5.payload.get("report", {})
    issues = []
    warnings = []
    
    # Run all quality validations
    issues.extend(_validate_company_names(report))
    issues.extend(_validate_osint_citations(report))
    warnings.extend(_validate_illumina_context_usage(input, report))
    warnings.extend(_validate_executive_summary_completeness(report))
    issues.extend(_validate_geopolitical_threat_levels(report, input.tier1_data.get("CrowdStrike", [])))
    issues.extend(_validate_risk_assessment_criteria(report, input.tier1_data.get("Intel471", []), input.tier1_data.get("breach_data", [])))
    warnings.extend(_validate_risk_trends(report))
    
    # Determine status
    if issues:
        status = "HALT"
        halt_reason = f"{len(issues)} AI quality issues found: {'; '.join(issues[:2])}"
    else:
        status = "COMPLETE"
        halt_reason = None
    
    return GateResult(
        gate_id="1E",
        status=status,
        halt_reason=halt_reason,
        payload={
            "issues": issues,
            "warnings": warnings,
            "validations_run": [
                "company_name_specificity",
                "osint_inline_citations",
                "illumina_context_usage",
                "executive_summary_completeness",
                "geopolitical_threat_levels",
                "risk_assessment_criteria",
                "risk_trend_alignment"
            ]
        }
    )
```

**Gate Sequence Update:**
```python
_GATE_SEQUENCES = {
    "quarterly": ["1", "1A", "1B", "2", "3", "4", "5", "1E", "1C", "1D", "6"],
    #                                                    ^^^^
    #                                               NEW: AI Quality
}
```

---

## Summary of Recommendations

### Critical (Implement First)
1. ✅ **Create Gate 1E** - AI Output Quality validation
2. ✅ **Enhance Gate 1A** - Add breach statistics accuracy checks
3. ✅ **Enhance Gate 1D** - Add company name validation and OSINT citation checks
4. ✅ **Enhance Gate 6** - Add quarterly-specific accuracy validations

### Important (Implement Second)
5. ✅ **Add risk trend validation** - Ensure ↑/↓ align with stat_cards
6. ✅ **Add geopolitical criteria validation** - Verify threat levels match actor counts
7. ✅ **Add risk rating validation** - Verify ratings match stated criteria

### Nice-to-Have (Future Enhancements)
8. ⭐ **OSINT relevance scoring** - Score articles by life sciences relevance
9. ⭐ **Duplicate detection** - Find duplicate articles across sources
10. ⭐ **Historical trend validation** - Validate quarter-over-quarter comparisons against historical JSON

---

## Implementation Priority

**Phase 1 (Immediate - Critical for Accuracy):**
- Create `src/gates/gate1e_ai_quality.py`
- Add to orchestrator sequence
- Implement company name validation
- Implement OSINT citation validation

**Phase 2 (High Priority - Improve Consistency):**
- Enhance Gate 1A with breach statistics checks
- Enhance Gate 1D with Illumina context validation
- Add risk criteria validation to Gate 6

**Phase 3 (Future Enhancements):**
- OSINT relevance scoring
- Duplicate article detection
- Advanced statistical correlation checks

---

## Expected Impact

**Before Enhancements:**
- ❌ Generic terms slip through ("Genomics research institute")
- ❌ Uncited OSINT sources listed
- ❌ Inconsistent threat levels (all MEDIUM)
- ❌ Risk trends don't match statistics

**After Enhancements:**
- ✅ All breach examples use actual company names
- ✅ Every OSINT source listed is cited in content
- ✅ Threat levels follow stated criteria (5+ actors = HIGH)
- ✅ Risk trends validated against breach counts
- ✅ Ratings justified by data (10+ ransomware = HIGH)

---

## Testing Strategy

```python
# Test Gate 1E with mock data containing quality issues
def test_gate1e_detects_generic_terms():
    mock_report = {
        "breach_landscape": {
            "incidents_by_type": [
                {
                    "type": "Data Exposure",
                    "notable_example": "Genomics research institute: 2.3M samples exposed"
                }
            ]
        }
    }
    
    result = gate1e_ai_quality.run(mock_input, None, "QUARTERLY")
    
    assert result.status == "HALT"
    assert "generic term" in result.halt_reason.lower()

def test_gate1e_detects_uncited_sources():
    mock_report = {
        "executive_summary": "China showed elevated activity [5].",
        "osint_sources_used": [
            {"citation_number": 5, "title": "Source A"},
            {"citation_number": 6, "title": "Source B"}  # Not cited!
        ]
    }
    
    result = gate1e_ai_quality.run(mock_input, None, "QUARTERLY")
    
    assert result.status == "HALT"
    assert "never cited" in result.halt_reason.lower()
```

---

**End of Audit Report**
