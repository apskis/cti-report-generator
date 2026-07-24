"""Shared loader for breach-dataset sources (VCDB / HHS / HIBP).

A source can be either a URL or a local file path. Public dataset endpoints are often
unstable (VCDB has no single stable combined-JSON URL; the HHS portal is a JSF app, not a
clean CSV API), so the most reliable operation is to download the dataset once and pin a
local path in config. This helper accepts either transparently.
"""

from __future__ import annotations

import logging
import os

import aiohttp

logger = logging.getLogger(__name__)


def _local_path(source: str) -> str | None:
    """Return a local filesystem path if ``source`` refers to one, else ``None``."""
    if not source:
        return None
    path = source[7:] if source.startswith("file://") else source
    # Only treat as local when it clearly is not an http(s) URL and the file exists.
    if source.startswith(("http://", "https://")):
        return None
    return path if os.path.isfile(path) else None


async def fetch_dataset_text(source: str, *, headers: dict, timeout_total: int = 45) -> str | None:
    """Load a dataset source's text from a local file or over HTTP.

    Returns the text on success, or ``None`` on any failure (missing file, non-200, network
    error) — callers treat ``None`` as "no data this run" and degrade gracefully.
    """
    local = _local_path(source)
    if local is not None:
        try:
            with open(local, encoding="utf-8") as f:
                text = f.read()
            logger.info(f"Loaded dataset from local file: {local}")
            return text
        except OSError as e:
            logger.warning(f"Could not read local dataset file {local}: {e}")
            return None

    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout_total), headers=headers
        ) as session:
            async with session.get(source) as resp:
                if resp.status != 200:
                    logger.info(f"Dataset source returned HTTP {resp.status}: {source} (skipping this run)")
                    return None
                return await resp.text()
    except Exception as e:
        logger.info(f"Dataset source unreachable ({source}): {e} (skipping this run)")
        return None
