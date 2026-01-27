"""
HTTP utilities with retry logic for API collectors.

Provides exponential backoff retry mechanism for transient failures.
"""
import asyncio
import logging
from typing import Dict, Any, Callable
from functools import wraps

import aiohttp  # type: ignore

from config import collector_config

logger = logging.getLogger(__name__)


class RetryableHTTPError(Exception):
    """Exception for HTTP errors that should be retried."""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"HTTP {status_code}: {message}")


class NonRetryableHTTPError(Exception):
    """Exception for HTTP errors that should NOT be retried."""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"HTTP {status_code}: {message}")


# HTTP status codes that should trigger a retry
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def is_retryable_status(status_code: int) -> bool:
    """Check if an HTTP status code should trigger a retry."""
    return status_code in RETRYABLE_STATUS_CODES


async def retry_with_backoff(
    func: Callable,
    max_retries: int | None = None,
    base_delay: float | None = None,
    max_delay: float | None = None,
    retryable_exceptions: tuple = (RetryableHTTPError, aiohttp.ClientError, asyncio.TimeoutError)
):
    """
    Execute an async function with exponential backoff retry.

    Args:
        func: Async callable to execute
        max_retries: Maximum number of retry attempts
        base_delay: Base delay in seconds (doubles each retry)
        max_delay: Maximum delay cap in seconds
        retryable_exceptions: Tuple of exception types that should trigger retry

    Returns:
        Result from the function

    Raises:
        The last exception if all retries fail
    """
    max_retries = max_retries or collector_config.max_retries
    base_delay = base_delay or collector_config.retry_base_delay_seconds
    max_delay = max_delay or collector_config.retry_max_delay_seconds

    last_exception = None

    for attempt in range(max_retries + 1):
        try:
            return await func()
        except retryable_exceptions as e:
            last_exception = e

            if attempt < max_retries:
                # Calculate delay with exponential backoff
                delay = min(base_delay * (2 ** attempt), max_delay)
                logger.warning(
                    f"Attempt {attempt + 1}/{max_retries + 1} failed: {e}. "
                    f"Retrying in {delay:.1f}s..."
                )
                await asyncio.sleep(delay)
            else:
                logger.error(f"All {max_retries + 1} attempts failed. Last error: {e}")
        except NonRetryableHTTPError as e:
            # Don't retry non-retryable errors
            logger.error(f"Non-retryable error: {e}")
            raise

    raise last_exception


class HTTPClient:
    """
    Reusable HTTP client with retry logic.

    Usage:
        async with HTTPClient() as client:
            data = await client.get("https://api.example.com/data", headers={...})
    """

    def __init__(
        self,
        timeout: int | None = None,
        max_retries: int | None = None
    ):
        """
        Initialize HTTP client.

        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts for transient failures
        """
        self.timeout = aiohttp.ClientTimeout(
            total=timeout or collector_config.http_timeout_seconds
        )
        self.max_retries = max_retries or collector_config.max_retries
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self):
        """Enter async context, create session."""
        self._session = aiohttp.ClientSession(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context, close session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def _handle_response(
        self,
        response: aiohttp.ClientResponse,
        expected_status: tuple = (200,)
    ) -> Dict[str, Any]:
        """
        Handle HTTP response and return JSON data.

        Args:
            response: aiohttp response object
            expected_status: Tuple of acceptable status codes

        Returns:
            Parsed JSON response

        Raises:
            RetryableHTTPError: For transient errors (429, 5xx)
            NonRetryableHTTPError: For client errors (4xx except 429)
        """
        if response.status in expected_status:
            return await response.json()

        # Get error details
        try:
            error_text = await response.text()
            error_text = error_text[:500]  # Truncate for logging
        except Exception:
            error_text = "Unable to read response body"

        if is_retryable_status(response.status):
            raise RetryableHTTPError(response.status, error_text)
        else:
            raise NonRetryableHTTPError(response.status, error_text)

    async def get(
        self,
        url: str,
        headers: Dict[str, str] | None = None,
        params: Dict[str, Any] | None = None,
        auth: aiohttp.BasicAuth | None = None,
        expected_status: tuple = (200,)
    ) -> Dict[str, Any]:
        """
        Perform GET request with retry logic.

        Args:
            url: Request URL
            headers: Request headers
            params: Query parameters
            auth: Basic authentication
            expected_status: Acceptable status codes

        Returns:
            Parsed JSON response
        """
        async def _do_request():
            async with self._session.get(
                url, headers=headers, params=params, auth=auth
            ) as response:
                return await self._handle_response(response, expected_status)

        return await retry_with_backoff(_do_request, max_retries=self.max_retries)

    async def post(
        self,
        url: str,
        headers: Dict[str, str] | None = None,
        data: Dict[str, Any] | None = None,
        json_data: Dict[str, Any] | None = None,
        params: Dict[str, Any] | None = None,
        expected_status: tuple = (200, 201)
    ) -> Dict[str, Any]:
        """
        Perform POST request with retry logic.

        Args:
            url: Request URL
            headers: Request headers
            data: Form data
            json_data: JSON body
            params: Query parameters
            expected_status: Acceptable status codes

        Returns:
            Parsed JSON response
        """
        async def _do_request():
            async with self._session.post(
                url, headers=headers, data=data, json=json_data, params=params
            ) as response:
                return await self._handle_response(response, expected_status)

        return await retry_with_backoff(_do_request, max_retries=self.max_retries)

    async def get_raw_response(
        self,
        url: str,
        headers: Dict[str, str] | None = None,
        params: Dict[str, Any] | None = None,
        auth: aiohttp.BasicAuth | None = None
    ) -> aiohttp.ClientResponse:
        """
        Perform GET request and return raw response (for custom handling).
        Caller is responsible for handling the response.

        Args:
            url: Request URL
            headers: Request headers
            params: Query parameters
            auth: Basic authentication

        Returns:
            Raw aiohttp response
        """
        return await self._session.get(url, headers=headers, params=params, auth=auth)

    async def post_raw_response(
        self,
        url: str,
        headers: Dict[str, str] | None = None,
        data: Dict[str, Any] | None = None,
        json_data: Dict[str, Any] | None = None,
        params: Dict[str, Any] | None = None
    ) -> aiohttp.ClientResponse:
        """
        Perform POST request and return raw response (for custom handling).

        Args:
            url: Request URL
            headers: Request headers
            data: Form data
            json_data: JSON body
            params: Query parameters

        Returns:
            Raw aiohttp response
        """
        return await self._session.post(
            url, headers=headers, data=data, json=json_data, params=params
        )


def validate_url(url: str) -> str:
    """
    Validate and sanitize a URL.

    Args:
        url: URL to validate

    Returns:
        Sanitized URL

    Raises:
        ValueError: If URL is invalid
    """
    if not url:
        raise ValueError("URL cannot be empty")

    # Ensure URL has scheme
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    # Basic validation - check for suspicious patterns
    suspicious_patterns = ["<", ">", '"', "'", ";", "(", ")", "{", "}"]
    for pattern in suspicious_patterns:
        if pattern in url:
            raise ValueError(f"URL contains suspicious character: {pattern}")

    return url.rstrip("/")
