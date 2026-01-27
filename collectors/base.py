"""
Base collector class for threat intelligence data sources.

All collectors should inherit from BaseCollector and implement the collect() method.
"""
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import List, Dict, Any

from config import collector_config
from models import CollectorResult


class BaseCollector(ABC):
    """
    Abstract base class for all threat intelligence collectors.

    Each collector represents a single data source (e.g., NVD, Intel471).
    Collectors are responsible for:
    - Authenticating with their API
    - Fetching relevant data
    - Normalizing data to standard formats
    - Handling errors gracefully

    Subclasses must implement:
    - source_name (property): Unique identifier for this source
    - collect(): Main data collection method
    """

    def __init__(self, credentials: Dict[str, str], report_type: str = "weekly"):
        """
        Initialize collector with credentials.

        Args:
            credentials: Dictionary containing API credentials
            report_type: Type of report being generated ("weekly" or "quarterly")
        """
        self.credentials = credentials
        self.report_type = report_type
        self.logger = logging.getLogger(f"{__name__}.{self.source_name}")

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Unique identifier for this data source."""
        pass

    @property
    def enabled(self) -> bool:
        """Whether this collector is enabled. Override to add custom logic."""
        return True

    @property
    def lookback_days(self) -> int:
        """Default lookback period in days. Override per collector as needed."""
        return 7

    def get_date_range(self, days: int | None = None) -> tuple:
        """
        Calculate start and end dates for data collection.

        Args:
            days: Number of days to look back (defaults to self.lookback_days)

        Returns:
            Tuple of (start_date, end_date) as datetime objects
        """
        days = days or self.lookback_days
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        return start_date, end_date

    def format_date_iso(self, dt: datetime) -> str:
        """Format datetime as ISO 8601 string."""
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000")

    def format_date_timestamp_ms(self, dt: datetime) -> int:
        """Format datetime as Unix timestamp in milliseconds."""
        return int(dt.timestamp() * 1000)

    def format_date_timestamp_sec(self, dt: datetime) -> int:
        """Format datetime as Unix timestamp in seconds."""
        return int(dt.timestamp())

    @abstractmethod
    async def collect(self, report_type: str = "weekly") -> CollectorResult:
        """
        Collect threat intelligence data from this source.

        Returns:
            CollectorResult containing success status and collected data

        Implementation notes:
        - Should handle all exceptions internally
        - Should return CollectorResult even on failure
        - Should log meaningful error messages
        """
        pass

    async def safe_collect(self, report_type: str = "weekly") -> CollectorResult:
        """
        Wrapper around collect() that catches all exceptions.

        Returns:
            CollectorResult (never raises)
        """
        try:
            if not self.enabled:
                self.logger.info(f"{self.source_name} collector is disabled, skipping")
                return CollectorResult(
                    source=self.source_name,
                    success=True,
                    data=[],
                    record_count=0
                )
            return await self.collect(report_type=report_type)
        except Exception as e:
            self.logger.error(f"Unexpected error in {self.source_name} collector: {e}", exc_info=True)
            return CollectorResult(
                source=self.source_name,
                success=False,
                data=[],
                error=str(e),
                record_count=0
            )

    def _is_relevant_biotech(self, text: str, tags: List[str] | None = None) -> bool:
        """
        Check if content is relevant to biotech/healthcare sector.

        Args:
            text: Text to check (title, description, etc.)
            tags: List of tags to check

        Returns:
            True if content is relevant
        """
        from config import industry_filter_config

        text_lower = text.lower()
        keywords = industry_filter_config.biotech_keywords

        # Check text
        if any(kw in text_lower for kw in keywords):
            return True

        # Check tags
        if tags:
            tags_lower = [t.lower() for t in tags]
            if any(kw in tag for tag in tags_lower for kw in keywords):
                return True

        return False

    def _is_relevant_industry(self, industries: List[str]) -> bool:
        """
        Check if target industries are relevant.

        Args:
            industries: List of industry names

        Returns:
            True if any industry is relevant
        """
        from config import industry_filter_config

        target = set(industry_filter_config.target_industries)
        return bool(set(industries) & target)
