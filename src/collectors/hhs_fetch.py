"""Automated CSV export from the HHS OCR "Wall of Shame" breach portal.

The portal (``breach_report.jsf``) is a JSF/PrimeFaces app — there is no clean CSV API.
Its "export to CSV" control submits the page form (carrying the ``javax.faces.ViewState``)
and the server streams a CSV. This module replicates that flow:

    GET the portal page  ->  extract ViewState + hidden fields + the export control
    POST the form with the export control set  ->  receive CSV

Everything is best-effort: any failure returns ``None`` and the collector degrades to an
empty result (or a configured direct-URL / local-file source). The HTML-parsing helpers are
pure and unit-tested; the orchestrator does the I/O.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urljoin

import aiohttp

logger = logging.getLogger(__name__)

# A row of the HHS export always carries this column — used to confirm we got CSV, not the
# HTML page (the silent failure mode: HTML parsed as CSV yields zero rows, no error).
_CSV_HINT = "name of covered entity"

_INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
_FORM_RE = re.compile(r"<form\b[^>]*>", re.I)
_CONTROL_RE = re.compile(r"<(?:button|a|input|span)\b[^>]*>", re.I)


def _attr(tag: str, name: str) -> str | None:
    m = re.search(rf'{name}\s*=\s*"([^"]*)"', tag, re.I)
    return m.group(1) if m else None


def looks_like_hhs_csv(text: str) -> bool:
    """True if the text looks like the HHS breach CSV (not the HTML portal page)."""
    head = (text or "")[:2000].lower()
    return _CSV_HINT in head


def extract_viewstate(html: str) -> str | None:
    """Extract the ``javax.faces.ViewState`` value (attribute order agnostic)."""
    for tag in _INPUT_RE.findall(html):
        if (_attr(tag, "name") or "") == "javax.faces.ViewState":
            return _attr(tag, "value")
    return None


def extract_hidden_fields(html: str) -> dict[str, str]:
    """Collect all hidden ``<input>`` name/value pairs from the page."""
    fields: dict[str, str] = {}
    for tag in _INPUT_RE.findall(html):
        if (_attr(tag, "type") or "").lower() == "hidden":
            name = _attr(tag, "name")
            if name:
                fields[name] = _attr(tag, "value") or ""
    return fields


def extract_form_action(html: str, base_url: str) -> str:
    """Resolve the first form's action URL against the portal URL."""
    for tag in _FORM_RE.findall(html):
        action = _attr(tag, "action")
        if action:
            return urljoin(base_url, action)
    return base_url


def find_export_controls(html: str) -> list[str]:
    """Return candidate JSF control identifiers whose id/name/label mentions csv/export."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _CONTROL_RE.finditer(html):
        tag = m.group(0)
        ident = _attr(tag, "name") or _attr(tag, "id")
        blob = f"{ident or ''} {_attr(tag, 'value') or ''} {_attr(tag, 'onclick') or ''}"
        if ident and ident not in seen and re.search(r"csv|export", blob, re.I):
            seen.add(ident)
            out.append(ident)
    return out


async def fetch_hhs_breach_csv(portal_url: str, headers: dict, timeout_total: int = 60) -> str | None:
    """Drive the JSF portal to export the breach report as CSV. Returns CSV text or None."""
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout_total), headers=headers
        ) as session:
            async with session.get(portal_url) as resp:
                if resp.status != 200:
                    logger.info(f"HHS portal returned HTTP {resp.status}; cannot auto-export CSV")
                    return None
                html = await resp.text()

            # Some deployments serve CSV directly from the GET.
            if looks_like_hhs_csv(html):
                return html

            viewstate = extract_viewstate(html)
            if not viewstate:
                logger.info("HHS portal: no JSF ViewState found; cannot auto-export CSV")
                return None
            action = extract_form_action(html, portal_url)
            hidden = extract_hidden_fields(html)
            controls = find_export_controls(html)
            if not controls:
                logger.info("HHS portal: no CSV export control found on page")
                return None

            for control in controls:
                data = dict(hidden)
                data["javax.faces.ViewState"] = viewstate
                data[control] = control
                try:
                    async with session.post(action, data=data) as post_resp:
                        text = await post_resp.text()
                except Exception as e:
                    logger.info(f"HHS export POST failed for control {control!r}: {e}")
                    continue
                if looks_like_hhs_csv(text):
                    logger.info(f"HHS: CSV export succeeded via control {control!r} ({len(text)} bytes)")
                    return text

            logger.info("HHS portal: export attempts did not yield CSV")
            return None
    except Exception as e:
        logger.info(f"HHS portal auto-export failed: {e}")
        return None
