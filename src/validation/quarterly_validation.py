"""
Validation checks for quarterly report AI output.

Ensures the AI response meets quality requirements before rendering the report.
"""
import logging
import re
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class QuarterlyReportValidator:
    """Validates AI-generated quarterly report data."""
    
    GENERIC_TERMS = [
        "pharma manufacturer",
        "genomics institute",
        "biotech company",
        "medical device mfg",
        "lab software vendor",
        "healthcare provider",
        "research institute",
        "genomics research institute",  # Caught in real report
        "life sciences company",
        "clinical research org"
    ]
    
    def __init__(self):
        self.issues = []
        self.warnings = []
    
    def validate(self, analysis_result: Dict[str, Any], illumina_context: str = "") -> bool:
        """
        Validate quarterly report AI output.
        
        Args:
            analysis_result: The AI's analysis dictionary
            illumina_context: The Illumina OSINT context that was provided to the AI
            
        Returns:
            True if validation passes (no critical issues), False otherwise
        """
        self.issues = []
        self.warnings = []
        
        logger.info("Running quarterly report validation checks")
        
        # Run all validation checks
        self._check_osint_citations(analysis_result)
        self._check_notable_examples(analysis_result)
        self._check_illumina_context_usage(analysis_result, illumina_context)
        self._check_executive_summary_length(analysis_result)
        self._check_citation_consistency(analysis_result)
        
        # Log results
        if self.issues:
            logger.error(f"Validation FAILED with {len(self.issues)} critical issues:")
            for issue in self.issues:
                logger.error(f"  ❌ {issue}")
        
        if self.warnings:
            logger.warning(f"Validation found {len(self.warnings)} warnings:")
            for warning in self.warnings:
                logger.warning(f"  ⚠️  {warning}")
        
        if not self.issues and not self.warnings:
            logger.info("✓ Validation PASSED - no issues found")
        
        return len(self.issues) == 0
    
    def _check_osint_citations(self, analysis_result: Dict[str, Any]) -> None:
        """Check that OSINT sources are cited in the report."""
        osint_sources = analysis_result.get("osint_sources_used", [])
        
        if not osint_sources:
            self.warnings.append("No OSINT sources included (osint_sources_used is empty)")
            return
        
        # Check executive summary for citations
        exec_summary = analysis_result.get("executive_summary", "")
        
        # Look for citation patterns [5], [6], [7], etc.
        citations_found = re.findall(r'\[(\d+)\]', exec_summary)
        
        # Also check geopolitical threats relevance bullets
        geo_threats = analysis_result.get("geopolitical_threats", [])
        for threat in geo_threats:
            relevance_bullets = threat.get("relevance", [])
            for bullet in relevance_bullets:
                citations_found.extend(re.findall(r'\[(\d+)\]', bullet))
        
        if not citations_found:
            self.issues.append(
                f"OSINT sources listed ({len(osint_sources)} sources) but NO inline citations [N] found in executive summary or relevance bullets"
            )
        else:
            # Verify each source is cited
            source_numbers = {str(s.get("citation_number", 0)) for s in osint_sources}
            cited_numbers = set(citations_found)
            
            uncited = source_numbers - cited_numbers
            if uncited:
                self.warnings.append(
                    f"OSINT sources {uncited} are listed but never cited in report content"
                )
    
    def _check_notable_examples(self, analysis_result: Dict[str, Any]) -> None:
        """Check that notable examples include actual company names."""
        breach_landscape = analysis_result.get("breach_landscape", {})
        incidents = breach_landscape.get("incidents_by_type", [])
        
        for incident in incidents:
            incident_type = incident.get("type", "Unknown")
            example = incident.get("notable_example", "")
            
            if not example:
                self.warnings.append(f"{incident_type}: Missing notable_example")
                continue
            
            # Check for generic terms
            example_lower = example.lower()
            for generic_term in self.GENERIC_TERMS:
                if generic_term in example_lower:
                    self.issues.append(
                        f"{incident_type} notable_example uses generic term '{generic_term}': \"{example}\""
                    )
                    break
            
            # Check for proper format (should have company name followed by colon or hyphen)
            if ':' not in example and ' - ' not in example:
                self.warnings.append(
                    f"{incident_type} notable_example may not follow 'CompanyName: description' format: \"{example}\""
                )
    
    def _check_illumina_context_usage(self, analysis_result: Dict[str, Any], illumina_context: str) -> None:
        """Check that Illumina context was used if provided."""
        if not illumina_context or len(illumina_context) < 100:
            # No meaningful Illumina context provided, skip check
            return
        
        # Check if any OSINT sources reference Illumina
        osint_sources = analysis_result.get("osint_sources_used", [])
        has_illumina_source = any(
            "illumina" in s.get("title", "").lower() or 
            "illumina" in s.get("description", "").lower() or
            "precision medicine" in s.get("description", "").lower()
            for s in osint_sources
        )
        
        if not has_illumina_source:
            self.warnings.append(
                f"Illumina context provided ({len(illumina_context)} chars) but no Illumina-specific OSINT source cited"
            )
        
        # Check if relevance bullets mention Illumina-specific information
        geo_threats = analysis_result.get("geopolitical_threats", [])
        illumina_mentions = 0
        
        for threat in geo_threats:
            relevance_bullets = threat.get("relevance", [])
            for bullet in relevance_bullets:
                bullet_lower = bullet.lower()
                if any(term in bullet_lower for term in ["illumina", "novaseq", "sequencing platform", "ica", "basespace"]):
                    illumina_mentions += 1
        
        if illumina_mentions == 0:
            self.warnings.append(
                "Illumina context provided but no Illumina-specific products/platforms mentioned in relevance bullets"
            )
    
    def _check_executive_summary_length(self, analysis_result: Dict[str, Any]) -> None:
        """Check that executive summary is appropriate length."""
        exec_summary = analysis_result.get("executive_summary", "")
        
        if not exec_summary:
            self.issues.append("Executive summary is empty")
            return
        
        # Count paragraphs (split by double newline)
        paragraphs = [p.strip() for p in exec_summary.split('\n\n') if p.strip()]
        
        if len(paragraphs) < 3:
            self.warnings.append(
                f"Executive summary has only {len(paragraphs)} paragraph(s), expected 3-4"
            )
        
        # Check if it's unreasonably short (might be the concise 3-sentence format)
        sentences = re.split(r'[.!?]+', exec_summary)
        sentences = [s.strip() for s in sentences if s.strip()]
        
        if len(sentences) <= 3 and len(exec_summary) < 500:
            self.warnings.append(
                f"Executive summary appears too concise ({len(sentences)} sentences, {len(exec_summary)} chars) - may not cover all required sections"
            )
    
    def _check_citation_consistency(self, analysis_result: Dict[str, Any]) -> None:
        """Check that citation numbers are consistent and sequential."""
        osint_sources = analysis_result.get("osint_sources_used", [])
        
        if not osint_sources:
            return
        
        # Check citation numbers are sequential starting from 5
        citation_numbers = [s.get("citation_number", 0) for s in osint_sources]
        
        if citation_numbers:
            if min(citation_numbers) < 5:
                self.warnings.append(
                    f"Citation numbers should start from 5 (found: {min(citation_numbers)})"
                )
            
            # Check for gaps
            expected = list(range(5, 5 + len(osint_sources)))
            if sorted(citation_numbers) != expected:
                self.warnings.append(
                    f"Citation numbers not sequential: {sorted(citation_numbers)} (expected: {expected})"
                )
    
    def get_summary(self) -> str:
        """Get a summary of validation results."""
        if not self.issues and not self.warnings:
            return "✓ All validation checks passed"
        
        summary_parts = []
        if self.issues:
            summary_parts.append(f"❌ {len(self.issues)} critical issue(s)")
        if self.warnings:
            summary_parts.append(f"⚠️  {len(self.warnings)} warning(s)")
        
        return " | ".join(summary_parts)
