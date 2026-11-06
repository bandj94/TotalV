"""A thin async client for the VirusTotal v3 API, and the URL, file, and hash scan flows.

Every request goes through the shared RateLimiter. Every failure (network error,
HTTP error, timeout, quota) becomes an UNKNOWN result and never CLEAN.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Any
from urllib.parse import urlsplit

import aiohttp

from totalv.cache import TTLCache
from totalv.config import Settings
from totalv.rate_limiter import DailyQuotaExceeded, RateLimiter
from totalv.verdict import ScanResult, Verdict, evaluate, unknown

log = logging.getLogger(__name__)

API_BASE = "https://www.virustotal.com/api/v3"
GUI_BASE = "https://www.virustotal.com/gui"

# POST /files accepts at most 32 MB. Bigger files would need /files/upload_url.
MAX_UPLOAD_BYTES = 32 * 1024 * 1024

# Network timeout for a single request. Uploading 32 MB can take a while on a
# slow connection; the overall scan timeout still applies on top of this.
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=120, sock_connect=15)

RETRY_AFTER_429_SECONDS = 60
MAX_429_RETRIES = 2

# Polling a running analysis starts POLL_INTERVAL_SECONDS apart and slows down
# by POLL_BACKOFF after each check, up to MAX_POLL_INTERVAL_SECONDS. New files
# often take several minutes on the free API, and every check costs a request.
POLL_INTERVAL_SECONDS = 10
MAX_POLL_INTERVAL_SECONDS = 60
POLL_BACKOFF = 1.5

STILL_ANALYZING = (
    "VirusTotal is still analyzing this. The analysis keeps running, so run the "
    "same scan again in a few minutes to get the result."
)

# Uploaded files are sent under this neutral name, because VirusTotal shares
# file names with its community and the original name may be private.
UPLOAD_FILENAME = "sample"

JsonDict = dict[str, Any]


class VTError(Exception):
    """A VirusTotal request failed. The message is safe to show to users."""


def url_identifier(url: str) -> str:
    """VirusTotal's URL identifier: URL-safe base64 of the URL without '=' padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def file_report_link(sha256: str) -> str:
    return f"{GUI_BASE}/file/{sha256}"


def url_report_link(url_object_id: str) -> str:
    return f"{GUI_BASE}/url/{url_object_id}"


def is_never_submit(url: str, domains: frozenset[str]) -> bool:
    """True if the URL's host is one of ``domains`` or a subdomain of one."""
    host = (urlsplit(url).hostname or "").rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def next_poll_delay(delay: float) -> float:
    """The pause before the next poll: a little longer each time, up to the maximum."""
    return min(delay * POLL_BACKOFF, MAX_POLL_INTERVAL_SECONDS)


@dataclass
class _ScanState:
    """What a scan flow has done so far, so a timeout can report it accurately."""

    submitted: bool = False
    report_link: str | None = None


ScanFlow = Callable[[_ScanState], Awaitable[ScanResult]]


def _timestamp(value: Any) -> datetime | None:
    """Convert a VirusTotal Unix timestamp to a datetime, or None if absent."""
    if not isinstance(value, int | float) or value <= 0:
        return None
    return datetime.fromtimestamp(value, UTC)


class VirusTotalClient:
    """Runs scans against VirusTotal, with rate limiting and caching built in.

    Use it as an async context manager, or call ``start()`` and ``close()``.
    """

    def __init__(
        self,
        api_key: str,
        *,
        limiter: RateLimiter,
        cache: TTLCache[ScanResult],
        malicious_threshold: int = 3,
        scan_timeout_seconds: float = 180,
        max_report_age_days: int = 7,
        never_submit_domains: frozenset[str] = frozenset(),
        poll_interval_seconds: float = POLL_INTERVAL_SECONDS,
        retry_after_429_seconds: float = RETRY_AFTER_429_SECONDS,
    ) -> None:
        self._api_key = api_key
        self._limiter = limiter
        self._cache = cache
        self._malicious_threshold = malicious_threshold
        self._scan_timeout = scan_timeout_seconds
        self._max_report_age = timedelta(days=max_report_age_days)
        self._never_submit = never_submit_domains
        self._poll_interval = poll_interval_seconds
        self._retry_delay = retry_after_429_seconds
        self._session: aiohttp.ClientSession | None = None

    @classmethod
    def from_settings(cls, settings: Settings) -> VirusTotalClient:
        """Build a client with its limiter and cache from validated settings."""
        return cls(
            settings.vt_api_key,
            limiter=RateLimiter(settings.vt_requests_per_minute, settings.vt_daily_limit),
            cache=TTLCache(settings.cache_ttl_minutes * 60),
            malicious_threshold=settings.malicious_threshold,
            scan_timeout_seconds=settings.scan_timeout_seconds,
            max_report_age_days=settings.max_report_age_days,
            never_submit_domains=settings.never_submit_domains,
        )

    @property
    def limiter(self) -> RateLimiter:
        return self._limiter

    @property
    def cached_results(self) -> int:
        """Number of results currently held in the cache."""
        return len(self._cache)

    async def start(self) -> None:
        """Open the HTTP session. The API key is sent as a header on every request.

        This is async because aiohttp sessions must be created inside a running event loop.
        """
        if self._session is None:
            self._session = aiohttp.ClientSession(
                headers={"x-apikey": self._api_key}, timeout=REQUEST_TIMEOUT
            )

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def __aenter__(self) -> VirusTotalClient:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.close()

    # Public scan flows. Each one is cached and never raises.

    async def scan_url(self, url: str) -> ScanResult:
        """Use a recent existing report if there is one, otherwise submit the URL."""
        key = f"url:{url_identifier(url)}"
        return await self._cached(key, lambda state: self._scan_url(url, state))

    async def scan_file(self, content: bytes) -> ScanResult:
        """Look the file up by SHA-256, and upload it only if VirusTotal has never seen it."""
        sha256 = hashlib.sha256(content).hexdigest()
        key = f"file:{sha256}"
        return await self._cached(key, lambda state: self._scan_file(content, sha256, state))

    async def lookup_hash(self, file_hash: str) -> ScanResult:
        """Look up an MD5, SHA-1, or SHA-256. Never uploads anything."""
        file_hash = file_hash.strip().lower()
        return await self._cached(f"file:{file_hash}", lambda _state: self._lookup_hash(file_hash))

    async def _cached(self, key: str, flow: ScanFlow) -> ScanResult:
        result, from_cache = await self._cache.get_or_compute(
            key,
            lambda: self._fail_closed(flow),
            # UNKNOWN comes from errors, timeouts, quota, or missing data. Caching
            # it would hide a real answer that a retry could get.
            should_cache=lambda r: r.verdict is not Verdict.UNKNOWN,
        )
        return replace(result, from_cache=True) if from_cache else result

    async def _fail_closed(self, flow: ScanFlow) -> ScanResult:
        """Run a scan flow within the time limit, turning every failure into UNKNOWN."""
        state = _ScanState()
        try:
            async with asyncio.timeout(self._scan_timeout):
                return await flow(state)
        except TimeoutError:
            if state.submitted:
                # VirusTotal keeps working after we stop waiting, so a later
                # scan of the same item will find the finished report.
                log.warning(
                    "Stopped waiting after %s seconds; VirusTotal is still analyzing.",
                    self._scan_timeout,
                )
                return unknown(STILL_ANALYZING, report_url=state.report_link)
            return unknown("The scan took too long and was stopped. Try again later.")
        except DailyQuotaExceeded:
            return unknown("Today's VirusTotal quota is used up. It resets at 00:00 UTC.")
        except VTError as error:
            return unknown(str(error))
        except Exception:
            log.exception("Unexpected error during a VirusTotal scan")
            return unknown("Something went wrong while talking to VirusTotal.")

    async def _scan_url(self, url: str, state: _ScanState) -> ScanResult:
        report = await self._request("GET", f"/urls/{url_identifier(url)}")
        report_link = None
        if report is not None:
            data = report["data"]
            attributes = data["attributes"]
            # data.id is VirusTotal's own URL ID (SHA-256 of the canonical URL).
            report_link = url_report_link(data["id"])
            analysed_at = _timestamp(attributes.get("last_analysis_date"))
            if analysed_at is not None and self._is_recent(analysed_at):
                return self._evaluate(
                    attributes.get("last_analysis_stats"),
                    attributes.get("last_analysis_results"),
                    report_link,
                    analysed_at,
                )

        if is_never_submit(url, self._never_submit):
            return unknown(
                "Not submitted for privacy: this domain is on the never-submit list "
                "and VirusTotal has no recent report for this link.",
                report_url=report_link,
            )

        submission = await self._submit("/urls", data={"url": url})
        # The URL itself is not logged, because it may be private.
        log.info("Submitted a URL to VirusTotal for analysis.")
        state.submitted, state.report_link = True, report_link
        analysis = await self._wait_for_analysis(submission["data"]["id"])
        url_info = analysis.get("meta", {}).get("url_info", {})
        if url_info.get("id"):
            report_link = url_report_link(url_info["id"])
        return self._evaluate_analysis(analysis, report_link)

    async def _scan_file(self, content: bytes, sha256: str, state: _ScanState) -> ScanResult:
        report = await self._request("GET", f"/files/{sha256}")
        if report is not None:
            return self._evaluate_file_report(report)

        if len(content) > MAX_UPLOAD_BYTES:
            return unknown(
                "Too large: VirusTotal has no report for this file, and files over "
                "32 MB can't be uploaded by this bot."
            )

        submission = await self._submit("/files", form=lambda: _upload_form(content))
        log.info("Uploaded a file to VirusTotal for analysis (SHA-256 %s).", sha256)
        state.submitted, state.report_link = True, file_report_link(sha256)
        analysis = await self._wait_for_analysis(submission["data"]["id"])
        return self._evaluate_analysis(analysis, file_report_link(sha256))

    async def _lookup_hash(self, file_hash: str) -> ScanResult:
        report = await self._request("GET", f"/files/{file_hash}")
        if report is None:
            return unknown("VirusTotal has no report for this hash. Nothing was uploaded.")
        return self._evaluate_file_report(report)

    async def _wait_for_analysis(self, analysis_id: str) -> JsonDict:
        """Poll an analysis until it completes. The scan timeout bounds this loop."""
        delay = self._poll_interval
        loop = asyncio.get_running_loop()
        started = loop.time()
        while True:
            await asyncio.sleep(delay)
            analysis = await self._request("GET", f"/analyses/{analysis_id}")
            if analysis is None:
                raise VTError("VirusTotal could not find the analysis it just started.")
            status = analysis["data"]["attributes"].get("status")
            elapsed = loop.time() - started
            if status == "completed":
                log.info("VirusTotal analysis finished after %.0f seconds.", elapsed)
                return analysis
            log.info("VirusTotal analysis is %s after %.0f seconds.", status, elapsed)
            delay = next_poll_delay(delay)

    def _is_recent(self, analysed_at: datetime) -> bool:
        return datetime.now(UTC) - analysed_at <= self._max_report_age

    def _evaluate_file_report(self, report: JsonDict) -> ScanResult:
        data = report["data"]
        attributes = data["attributes"]
        # A file object's ID is its SHA-256, even when it was looked up by MD5 or SHA-1.
        sha256 = attributes.get("sha256") or data["id"]
        return self._evaluate(
            attributes.get("last_analysis_stats"),
            attributes.get("last_analysis_results"),
            file_report_link(sha256),
            _timestamp(attributes.get("last_analysis_date")),
        )

    def _evaluate_analysis(self, analysis: JsonDict, report_link: str | None) -> ScanResult:
        attributes = analysis["data"]["attributes"]
        return self._evaluate(
            attributes.get("stats"),
            attributes.get("results"),
            report_link,
            _timestamp(attributes.get("date")),
        )

    def _evaluate(
        self,
        stats: Mapping[str, Any] | None,
        results: Mapping[str, Any] | None,
        report_link: str | None,
        analysed_at: datetime | None,
    ) -> ScanResult:
        return evaluate(
            stats or {},
            results or {},
            malicious_threshold=self._malicious_threshold,
            report_url=report_link,
            analysis_date=analysed_at,
        )

    # HTTP layer.

    async def _submit(
        self,
        path: str,
        *,
        data: Mapping[str, str] | None = None,
        form: Callable[[], aiohttp.FormData] | None = None,
    ) -> JsonDict:
        """POST something for analysis and return the response with the analysis ID."""
        response = await self._request("POST", path, data=data, form=form)
        if response is None:
            raise VTError("VirusTotal did not accept the submission.")
        return response

    async def _request(
        self,
        method: str,
        path: str,
        *,
        data: Mapping[str, str] | None = None,
        form: Callable[[], aiohttp.FormData] | None = None,
    ) -> JsonDict | None:
        """Send one API request through the rate limiter. Returns None on HTTP 404.

        ``form`` builds a fresh multipart body for each attempt, because aiohttp
        can't send the same FormData twice.
        """
        if self._session is None:
            raise RuntimeError("VirusTotalClient.start() must be called before scanning.")

        for attempt in range(MAX_429_RETRIES + 1):
            await self._limiter.acquire()
            body = form() if form is not None else data
            try:
                async with self._session.request(method, API_BASE + path, data=body) as response:
                    if response.status == 404:
                        return None
                    if response.status != 429:
                        await _raise_for_status(response)
                        return await response.json()
            except (aiohttp.ClientError, TimeoutError) as error:
                log.warning("VirusTotal request %s %s failed: %r", method, path, error)
                raise VTError("Could not reach VirusTotal. Try again later.") from error

            if attempt < MAX_429_RETRIES:
                log.warning(
                    "VirusTotal returned HTTP 429 (quota exceeded). Retrying in %s seconds.",
                    self._retry_delay,
                )
                await asyncio.sleep(self._retry_delay)

        raise VTError("VirusTotal's request limit was reached. Try again in a few minutes.")


async def _raise_for_status(response: aiohttp.ClientResponse) -> None:
    """Raise VTError with a user-safe message for any error status other than 404/429."""
    if response.status < 400:
        return
    # VirusTotal error bodies hold an error code and message, never the API key.
    details = (await response.text())[:300]
    log.warning("VirusTotal returned HTTP %s: %s", response.status, details)
    if response.status == 401:
        raise VTError("VirusTotal rejected the bot's API key. The bot owner should check it.")
    if response.status == 403:
        raise VTError("VirusTotal refused this request (HTTP 403).")
    raise VTError(f"VirusTotal returned an error (HTTP {response.status}). Try again later.")


def _upload_form(content: bytes) -> aiohttp.FormData:
    form = aiohttp.FormData()
    form.add_field(
        "file", content, filename=UPLOAD_FILENAME, content_type="application/octet-stream"
    )
    return form
