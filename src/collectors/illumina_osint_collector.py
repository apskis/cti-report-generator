"""
Illumina OSINT Collector for Quarterly Reports.

Fetches current public information about Illumina's products, market position,
regulatory status, and partnerships from official sources.
"""
import logging
import re
import ssl
from typing import Dict, Any, List
from datetime import datetime

import aiohttp
import certifi
from bs4 import BeautifulSoup

from src.collectors.base import BaseCollector, CollectorResult

logger = logging.getLogger(__name__)


class IlluminaOSINTCollector(BaseCollector):
    """
    Collector for Illumina public information.
    
    Fetches from:
    1. SEC EDGAR submissions API
    2. Illumina news center
    3. Illumina investor relations press releases
    4. Web search fallback (if available)
    
    Returns a consolidated context string for AI analysis.
    
    NOTE: This collector only runs for quarterly reports.
    """

    def __init__(self, credentials: Dict[str, str] = None, report_type: str = "weekly"):
        super().__init__(credentials or {}, report_type)
    
    @property
    def source_name(self) -> str:
        """Unique identifier for this data source."""
        return "Illumina-OSINT"
    
    @property
    def enabled(self) -> bool:
        """Only enable for quarterly reports."""
        return self.report_type == "quarterly"

    async def collect(
        self,
        lookback_days: int = 90,
        report_type: str = "quarterly",
        **kwargs
    ) -> CollectorResult:
        """
        Collect Illumina public information for quarterly context.

        Args:
            credentials: API credentials (not needed for public sources)
            lookback_days: Time window (not used - we get latest info)
            **kwargs: Additional parameters

        Returns:
            CollectorResult with illumina_context string
        """
        try:
            logger.info("Starting Illumina OSINT collection for quarterly report")
            
            context_parts = []
            
            # SOURCE 1: SEC EDGAR submissions
            try:
                sec_data = await self._fetch_sec_edgar()
                if sec_data:
                    context_parts.append(f"## SEC Filings (Recent)\n{sec_data}\n")
            except Exception as e:
                logger.warning(f"Failed to fetch SEC EDGAR data: {e}")
            
            # SOURCE 2: Illumina news center
            try:
                news_data = await self._fetch_news_center()
                if news_data:
                    context_parts.append(f"## Illumina News Center\n{news_data}\n")
            except Exception as e:
                logger.warning(f"Failed to fetch Illumina news center: {e}")
            
            # SOURCE 3: Investor relations press releases
            try:
                ir_data = await self._fetch_investor_relations()
                if ir_data:
                    context_parts.append(f"## Investor Relations Press Releases\n{ir_data}\n")
            except Exception as e:
                logger.warning(f"Failed to fetch investor relations data: {e}")
            
            # SOURCE 4: Web search fallback
            # TODO: Add web search utility integration when available
            # For now, log and skip
            logger.info("Web search source not implemented yet - skipping")
            
            # Combine all context parts
            illumina_context = "\n".join(context_parts)
            
            # Truncate to ~2000 tokens (roughly 8000 chars)
            if len(illumina_context) > 8000:
                illumina_context = illumina_context[:8000] + "\n\n[truncated for length]"
            
            logger.info(f"Illumina OSINT collection complete: {len(illumina_context)} chars")
            
            return CollectorResult(
                success=True,
                source=self.source_name,
                data=[{"illumina_context": illumina_context}],
                record_count=1,
                error=None
            )
            
        except Exception as e:
            logger.error(f"Error in Illumina OSINT collection: {e}", exc_info=True)
            return CollectorResult(
                success=False,
                source=self.source_name,
                data=[],
                record_count=0,
                error=str(e)
            )

    async def _fetch_sec_edgar(self) -> str:
        """
        Fetch recent SEC filings from EDGAR API.
        
        Returns:
            Formatted string of recent filing descriptions
        """
        url = "https://data.sec.gov/submissions/CIK0001110803.json"
        headers = {
            "User-Agent": "Illumina-CTI-Pipeline cti@illumina.com"
        }
        
        # Create SSL context with certifi certificates
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    logger.warning(f"SEC EDGAR API returned status {response.status}")
                    return ""
                
                data = await response.json()
                
                # Extract recent filings
                filings = data.get("filings", {}).get("recent", {})
                forms = filings.get("form", [])
                descriptions = filings.get("primaryDocument", [])
                dates = filings.get("filingDate", [])
                
                # Get first 5 filings
                recent_filings = []
                for i in range(min(5, len(forms))):
                    filing_form = forms[i]
                    filing_desc = descriptions[i] if i < len(descriptions) else "N/A"
                    filing_date = dates[i] if i < len(dates) else "N/A"
                    recent_filings.append(f"- {filing_date}: {filing_form} - {filing_desc}")
                
                return "\n".join(recent_filings) if recent_filings else "No recent filings found"

    async def _fetch_news_center(self) -> str:
        """
        Fetch headlines from Illumina news center.
        
        Returns:
            Formatted string of news headlines
        """
        url = "https://www.illumina.com/company/news-center.html"
        
        # Create SSL context with certifi certificates
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url) as response:
                if response.status != 200:
                    logger.warning(f"Illumina news center returned status {response.status}")
                    return ""
                
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Try to find news items - structure may vary
                # Common patterns: article tags, news-item classes, etc.
                headlines = []
                
                # Try various selectors
                selectors = [
                    'article h3',
                    '.news-item h3',
                    '.press-release h3',
                    'h3.title',
                    '.headline'
                ]
                
                for selector in selectors:
                    items = soup.select(selector)
                    if items:
                        headlines = [self._clean_text(item.get_text()) for item in items[:10]]
                        break
                
                if not headlines:
                    # Fallback: get any h3 tags as potential headlines
                    h3_tags = soup.find_all('h3')
                    headlines = [self._clean_text(tag.get_text()) for tag in h3_tags[:10]]
                
                if not headlines:
                    logger.warning("Could not parse Illumina news center - page structure may have changed")
                    return "Unable to parse news center (page structure changed)"
                
                return "\n".join([f"- {headline}" for headline in headlines if headline])

    async def _fetch_investor_relations(self) -> str:
        """
        Fetch press releases from Illumina investor relations.
        
        Returns:
            Formatted string of press release headlines
        """
        # Try the main investor page which should have press releases
        url = "https://investor.illumina.com/investors/default.aspx"
        
        # Create SSL context with certifi certificates
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url) as response:
                if response.status != 200:
                    logger.warning(f"Illumina IR page returned status {response.status}")
                    return ""
                
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Try to find press release items
                press_releases = []
                
                # Common patterns for IR pages
                selectors = [
                    '.press-release-item',
                    '.module_pressrelease',
                    'article.press-release',
                    '.pressrelease',
                    '.news-list-item'
                ]
                
                for selector in selectors:
                    items = soup.select(selector)
                    if items:
                        for item in items[:8]:
                            # Try to extract headline and date
                            headline_elem = item.find(['h3', 'h2', 'a'])
                            date_elem = item.find(['time', 'span', 'div'], class_=re.compile(r'date|time'))
                            
                            headline = self._clean_text(headline_elem.get_text()) if headline_elem else "No title"
                            date = self._clean_text(date_elem.get_text()) if date_elem else ""
                            
                            if headline and headline != "No title":
                                press_releases.append(f"- {date + ': ' if date else ''}{headline}")
                        break
                
                if not press_releases:
                    # Fallback: try to find any links that look like press releases
                    links = soup.find_all('a', href=re.compile(r'press-release|news'))
                    for link in links[:8]:
                        text = self._clean_text(link.get_text())
                        if text and len(text) > 10:  # Skip short navigation links
                            press_releases.append(f"- {text}")
                
                if not press_releases:
                    logger.warning("Could not parse Illumina IR page - page structure may have changed")
                    return "Unable to parse investor relations page (page structure changed)"
                
                return "\n".join(press_releases)

    @staticmethod
    def _clean_text(text: str) -> str:
        """
        Clean extracted text by removing extra whitespace, HTML artifacts, and navigation text.
        
        Args:
            text: Raw text to clean
            
        Returns:
            Cleaned text string
        """
        if not text:
            return ""
        
        # Remove extra whitespace and normalize
        text = re.sub(r'\s+', ' ', text)
        text = text.strip()
        
        # Remove common navigation/boilerplate phrases
        skip_phrases = [
            'skip to main content',
            'cookie policy',
            'privacy policy',
            'all rights reserved',
            'read more',
            'learn more',
            'click here'
        ]
        
        text_lower = text.lower()
        for phrase in skip_phrases:
            if phrase in text_lower:
                return ""
        
        # Remove very short strings (likely not useful content)
        if len(text) < 10:
            return ""
        
        return text
