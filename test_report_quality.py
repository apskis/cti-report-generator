"""
Quality test for quarterly report generation.

Run this before committing changes to verify report quality.
"""

import asyncio
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from src.validation import QuarterlyReportValidator


async def test_report_quality():
    """Generate a report and validate its quality."""
    print("\n" + "=" * 60)
    print("QUARTERLY REPORT QUALITY TEST")
    print("=" * 60 + "\n")

    # Import here to avoid early initialization
    from test_local import get_mock_quarterly_analysis

    print("→ Generating report with mock data...")
    analysis = get_mock_quarterly_analysis()

    print("→ Running validation checks...\n")
    validator = QuarterlyReportValidator()

    # Simulate Illumina context (empty for mock)
    illumina_context = ""
    is_valid = validator.validate(analysis, illumina_context)

    print("\n" + "=" * 60)
    print(f"RESULT: {validator.get_summary()}")
    print("=" * 60 + "\n")

    if not is_valid:
        print("❌ QUALITY TEST FAILED")
        print("\nCritical Issues:")
        for issue in validator.issues:
            print(f"  • {issue}")

        if validator.warnings:
            print("\nWarnings:")
            for warning in validator.warnings:
                print(f"  • {warning}")

        return False
    else:
        if validator.warnings:
            print("⚠️  QUALITY TEST PASSED WITH WARNINGS")
            print("\nWarnings:")
            for warning in validator.warnings:
                print(f"  • {warning}")
        else:
            print("✅ QUALITY TEST PASSED")

        return True


if __name__ == "__main__":
    success = asyncio.run(test_report_quality())
    sys.exit(0 if success else 1)
