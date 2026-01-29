"""
Reports package.

Modular report generation for different report types (weekly, quarterly, etc.).
"""
from src.reports.base import BaseReportGenerator
from src.reports.registry import get_report_generator, register_report_generator, REPORT_REGISTRY
from src.reports.blob_storage import upload_to_blob, generate_sas_url
from src.reports.weekly_report import WeeklyReportGenerator
from src.reports.quarterly_report import QuarterlyReportGenerator

__all__ = [
    "BaseReportGenerator",
    "get_report_generator",
    "register_report_generator",
    "REPORT_REGISTRY",
    "upload_to_blob",
    "generate_sas_url",
    "WeeklyReportGenerator",
    "QuarterlyReportGenerator",
]
