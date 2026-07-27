"""Browser-driven CSV export from the HHS OCR breach portal.

The portal is a JavaScript-rendered PrimeFaces app — the data grid and its CSV export only
exist after client-side JS runs, so raw HTTP can't reach them. This drives a headless
Chromium (Playwright) to open the portal, navigate to the HIPAA breach reports grid, click
the CSV export, and capture the downloaded file.

Playwright is an OPTIONAL dependency (guarded import). If it isn't installed, this returns
``None`` and the collector degrades gracefully. Install with::

    pip install playwright
    playwright install chromium
"""

from __future__ import annotations

import logging
from pathlib import Path

from src.collectors.hhs_fetch import looks_like_hhs_csv

logger = logging.getLogger(__name__)

# Try in order to reach the breach-reports data grid from the landing page.
_GRID_LINKS = (
    'a:has-text("View HIPAA Breach Reports")',
    'text=View HIPAA Breach Reports',
    'a:has-text("Breach Report")',
)

# Try in order to find the CSV export control on the grid.
_EXPORT_CONTROLS = (
    'a:has-text("CSV")',
    'button:has-text("CSV")',
    '[title*="csv" i]',
    '[aria-label*="csv" i]',
    'a[href$=".csv"]',
    'a:has-text("Export")',
    'button:has-text("Export")',
)


async def _open_report_grid(page) -> None:
    """Click through to the HIPAA breach reports grid if we're on the landing page."""
    for sel in _GRID_LINKS:
        try:
            el = await page.query_selector(sel)
        except Exception:
            el = None
        if el:
            try:
                await el.click()
                await page.wait_for_load_state("networkidle", timeout=30000)
                logger.info(f"HHS browser: navigated to grid via {sel!r}")
                return
            except Exception as e:
                logger.info(f"HHS browser: grid link {sel!r} click failed: {e}")
    logger.info("HHS browser: no grid-nav link found (may already be on the grid)")


async def _click_export_and_capture(page, timeout_ms: int) -> str | None:
    """Click a CSV export control and return the downloaded file's text (if it's CSV)."""
    for sel in _EXPORT_CONTROLS:
        try:
            el = await page.query_selector(sel)
        except Exception:
            el = None
        if not el:
            continue
        try:
            async with page.expect_download(timeout=timeout_ms) as dl_info:
                await el.click()
            download = await dl_info.value
            path = await download.path()
            if not path:
                continue
            text = Path(path).read_text(encoding="utf-8", errors="replace")
            if looks_like_hhs_csv(text):
                logger.info(f"HHS browser: CSV captured via {sel!r} ({len(text)} bytes)")
                return text
            logger.info(f"HHS browser: {sel!r} downloaded a non-CSV file; trying next")
        except Exception as e:
            logger.info(f"HHS browser: export via {sel!r} failed: {e}")
    return None


async def fetch_hhs_csv_via_browser(portal_url: str, *, headless: bool = True, timeout_ms: int = 60000) -> str | None:
    """Drive a headless browser to export the HHS breach report as CSV. Returns CSV or None."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.info(
            "playwright not installed; skipping browser-based HHS export "
            "(pip install playwright && playwright install chromium)"
        )
        return None

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=headless)
            try:
                context = await browser.new_context(accept_downloads=True)
                page = await context.new_page()
                await page.goto(portal_url, wait_until="networkidle", timeout=timeout_ms)
                await _open_report_grid(page)
                return await _click_export_and_capture(page, timeout_ms)
            finally:
                await browser.close()
    except Exception as e:
        logger.info(f"HHS browser export failed: {e}")
        return None
