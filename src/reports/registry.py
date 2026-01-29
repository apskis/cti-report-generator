"""
Report generator registry.

Provides dynamic registration and lookup of report generators.
"""
import logging
from typing import Dict, Type

from src.reports.base import BaseReportGenerator

logger = logging.getLogger(__name__)

# Registry mapping report type names to generator classes
REPORT_REGISTRY: Dict[str, Type[BaseReportGenerator]] = {}


def register_report_generator(report_type: str):
    """
    Decorator to register a report generator class.

    Usage:
        @register_report_generator("weekly")
        class WeeklyReportGenerator(BaseReportGenerator):
            ...
    """
    def decorator(cls: Type[BaseReportGenerator]):
        if report_type in REPORT_REGISTRY:
            logger.warning(f"Overwriting existing report generator: {report_type}")
        REPORT_REGISTRY[report_type] = cls
        logger.debug(f"Registered report generator: {report_type}")
        return cls
    return decorator


def get_report_generator(report_type: str) -> BaseReportGenerator | None:
    """
    Get a report generator instance by type name.

    Args:
        report_type: The report type identifier (e.g., "weekly", "monthly")

    Returns:
        Instantiated report generator, or None if not found
    """
    generator_class = REPORT_REGISTRY.get(report_type.lower())
    if generator_class is None:
        logger.error(f"Unknown report type: {report_type}. Available: {list(REPORT_REGISTRY.keys())}")
        return None

    return generator_class()


def list_report_types() -> list[str]:
    """Return list of available report type names."""
    return list(REPORT_REGISTRY.keys())
