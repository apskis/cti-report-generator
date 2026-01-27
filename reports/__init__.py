"""
Reports package.

Modular report generation for different report types (weekly, monthly, bulletin, etc.).
"""
from reports.base import BaseReportGenerator
from reports.registry import get_report_generator, register_report_generator, REPORT_REGISTRY
from reports.blob_storage import upload_to_blob, generate_sas_url
from reports.weekly_report import WeeklyReportGenerator

__all__ = [
    "BaseReportGenerator",
    "get_report_generator",
    "register_report_generator",
    "REPORT_REGISTRY",
    "upload_to_blob",
    "generate_sas_url",
    "WeeklyReportGenerator",
]
