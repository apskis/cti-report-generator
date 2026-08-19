"""Durable backing for the quarter ledger.

The quarterly report records each quarter's grounded metrics (see ``src.core.quarter_ledger``)
so the next quarter reads a real prior value. By default the generator persists that ledger to a
local JSON file — fine for local runs, but the deployed Azure Function's container is ephemeral,
so the file (and therefore all quarter-over-quarter history) is lost between runs.

A *history store* abstracts load/save so the deployed path can persist to durable Azure Blob
storage instead. Any object with ``load() -> dict`` and ``save(dict) -> None`` works; the
generator delegates to it when one is set (``set_history_store``) and otherwise keeps the local
file. ``BlobQuarterHistoryStore`` is the durable implementation.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class HistoryStore(Protocol):
    """Minimal interface the generator needs to persist the quarter ledger."""

    def load(self) -> dict[str, Any]: ...

    def save(self, history: dict[str, Any]) -> None: ...


class BlobQuarterHistoryStore:
    """Persist the quarter ledger to a single JSON blob (durable across Function runs).

    Read/write failures are non-fatal: ``load`` returns ``{}`` (a missing/failed blob just means
    "no prior history yet"), and ``save`` logs and swallows, so a storage hiccup never aborts a
    report — it only forfeits that quarter's QoQ persistence.
    """

    def __init__(
        self,
        storage_account_name: str,
        storage_account_key: str,
        container_name: str = "cti-history",
        blob_name: str = "quarterly_risk_history.json",
    ) -> None:
        self._account = storage_account_name
        self._key = storage_account_key
        self._container = container_name
        self._blob = blob_name

    def _blob_client(self):
        from azure.core.credentials import AzureNamedKeyCredential
        from azure.storage.blob import BlobServiceClient

        account_url = f"https://{self._account}.blob.core.windows.net"
        service = BlobServiceClient(
            account_url=account_url,
            credential=AzureNamedKeyCredential(self._account, self._key),
        )
        container = service.get_container_client(self._container)
        try:
            container.create_container()
        except Exception:
            pass  # already exists (the common case)
        return service.get_blob_client(container=self._container, blob=self._blob)

    def load(self) -> dict[str, Any]:
        try:
            data = self._blob_client().download_blob().readall()
            history = json.loads(data)
            return history if isinstance(history, dict) else {}
        except Exception as e:
            logger.info(f"Quarter ledger blob not loaded ({type(e).__name__}); starting empty")
            return {}

    def save(self, history: dict[str, Any]) -> None:
        try:
            payload = json.dumps(history, indent=2).encode("utf-8")
            self._blob_client().upload_blob(payload, overwrite=True)
            logger.info(
                f"Saved quarter ledger to blob {self._container}/{self._blob} ({len(history)} quarters)"
            )
        except Exception as e:
            logger.warning(f"Failed to save quarter ledger to blob (non-fatal): {e}")
