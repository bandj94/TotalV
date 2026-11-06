"""Tests for the VirusTotal client. All HTTP traffic is mocked with aioresponses."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Iterator
from typing import Any

import aiohttp
import pytest
from aioresponses import aioresponses
from yarl import URL

from totalv import vt_client
from totalv.cache import TTLCache
from totalv.rate_limiter import RateLimiter
from totalv.verdict import Verdict
from totalv.vt_client import API_BASE, VirusTotalClient, url_identifier

API_KEY = "test-api-key-not-real"
TARGET_URL = "https://example.com/page"
URL_REPORT = f"{API_BASE}/urls/{url_identifier(TARGET_URL)}"
URL_SUBMIT = f"{API_BASE}/urls"
FILE_SUBMIT = f"{API_BASE}/files"
ANALYSIS_ID = "u-abc123-1700000000"
ANALYSIS = f"{API_BASE}/analyses/{ANALYSIS_ID}"
SHA256 = "a" * 64
DAY = 86_400


def make_client(**overrides: Any) -> VirusTotalClient:
    """A client with no real waiting: fast limiter, no poll pause, no 429 pause."""
    options: dict[str, Any] = {
        "limiter": RateLimiter(requests_per_minute=600_000, daily_limit=500),
        "cache": TTLCache(ttl_seconds=3600),
        "malicious_threshold": 3,
        "scan_timeout_seconds": 5,
        "max_report_age_days": 7,
        "never_submit_domains": frozenset({"docs.google.com"}),
        "poll_interval_seconds": 0,
        "retry_after_429_seconds": 0,
    }
    options.update(overrides)
    return VirusTotalClient(API_KEY, **options)


@pytest.fixture
async def client() -> AsyncIterator[VirusTotalClient]:
    async with make_client() as vt:
        yield vt


@pytest.fixture
def api() -> Iterator[aioresponses]:
    with aioresponses() as mocked:
        yield mocked


def request_count(api: aioresponses, method: str, url: str) -> int:
    return len(api.requests.get((method, URL(url)), []))


def stats(malicious: int = 0, suspicious: int = 0, harmless: int = 0, undetected: int = 0):
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": 0,
    }


def url_report(counts: dict[str, int], *, age_days: float = 0, results: dict | None = None):
    return {
        "data": {
            "type": "url",
            "id": "canonical-url-sha256",
            "attributes": {
                "last_analysis_date": int(time.time() - age_days * DAY),
                "last_analysis_stats": counts,
                "last_analysis_results": results or {},
            },
        }
    }


def file_report(counts: dict[str, int], sha256: str = SHA256):
    return {
        "data": {
            "type": "file",
            "id": sha256,
            "attributes": {
                "sha256": sha256,
                "last_analysis_date": int(time.time()),
                "last_analysis_stats": counts,
                "last_analysis_results": {},
            },
        }
    }


def analysis(status: str, counts: dict[str, int] | None = None, meta: dict | None = None):
    body: dict[str, Any] = {
        "data": {
            "type": "analysis",
            "id": ANALYSIS_ID,
            "attributes": {
                "status": status,
                "date": int(time.time()),
                "stats": counts or {},
                "results": {},
            },
        }
    }
    if meta is not None:
        body["meta"] = meta
    return body


SUBMITTED = {"data": {"type": "analysis", "id": ANALYSIS_ID}}


# URL scans


async def test_recent_url_report_is_used_with_one_request(client, api) -> None:
    results = {"Engine": {"category": "malicious", "engine_name": "Engine", "result": "phishing"}}
    api.get(URL_REPORT, payload=url_report(stats(malicious=5, undetected=60), results=results))

    result = await client.scan_url(TARGET_URL)

    assert result.verdict is Verdict.MALICIOUS
    assert result.flagged_by[0].label == "phishing"
    assert result.report_url == "https://www.virustotal.com/gui/url/canonical-url-sha256"
    assert request_count(api, "POST", URL_SUBMIT) == 0


@pytest.mark.parametrize(
    ("counts", "expected"),
    [
        (stats(harmless=60, undetected=10), Verdict.CLEAN),
        (stats(suspicious=1, harmless=60), Verdict.SUSPICIOUS),
        (stats(malicious=1, harmless=60), Verdict.SUSPICIOUS),
        (stats(), Verdict.UNKNOWN),
    ],
)
async def test_url_verdicts(client, api, counts, expected) -> None:
    api.get(URL_REPORT, payload=url_report(counts))
    assert (await client.scan_url(TARGET_URL)).verdict is expected


async def test_stale_url_report_triggers_a_new_scan(client, api) -> None:
    api.get(URL_REPORT, payload=url_report(stats(harmless=60), age_days=30))
    api.post(URL_SUBMIT, payload=SUBMITTED)
    api.get(ANALYSIS, payload=analysis("queued"))
    api.get(ANALYSIS, payload=analysis("in-progress"))
    api.get(
        ANALYSIS,
        payload=analysis(
            "completed",
            stats(malicious=4, harmless=50),
            meta={"url_info": {"id": "fresh-url-id", "url": TARGET_URL}},
        ),
    )

    result = await client.scan_url(TARGET_URL)

    assert result.verdict is Verdict.MALICIOUS
    assert result.report_url == "https://www.virustotal.com/gui/url/fresh-url-id"
    assert request_count(api, "GET", ANALYSIS) == 3


async def test_unknown_url_is_submitted(client, api) -> None:
    api.get(URL_REPORT, status=404, payload={"error": {"code": "NotFoundError"}})
    api.post(URL_SUBMIT, payload=SUBMITTED)
    api.get(ANALYSIS, payload=analysis("completed", stats(harmless=70)))

    result = await client.scan_url(TARGET_URL)

    assert result.verdict is Verdict.CLEAN
    assert request_count(api, "POST", URL_SUBMIT) == 1


async def test_never_submit_domain_is_not_submitted(client, api) -> None:
    private_url = "https://docs.google.com/document/d/secret/edit"
    api.get(f"{API_BASE}/urls/{url_identifier(private_url)}", status=404)

    result = await client.scan_url(private_url)

    assert result.verdict is Verdict.UNKNOWN
    assert "privacy" in (result.reason or "")
    assert request_count(api, "POST", URL_SUBMIT) == 0


def test_never_submit_matches_subdomains_only() -> None:
    domains = frozenset({"google.com"})
    assert vt_client.is_never_submit("https://docs.google.com/x", domains)
    assert vt_client.is_never_submit("https://GOOGLE.com./", domains)
    assert not vt_client.is_never_submit("https://notgoogle.com/", domains)


def test_url_identifier_is_unpadded_urlsafe_base64() -> None:
    # Plain base64 of this URL ends in "==", which VirusTotal expects removed.
    assert url_identifier("http://www.virustotal.com") == "aHR0cDovL3d3dy52aXJ1c3RvdGFsLmNvbQ"
    assert "=" not in url_identifier("https://a.b/?x=1")


# File and hash scans


async def test_known_file_is_not_uploaded(client, api) -> None:
    content = b"hello"
    sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    api.get(f"{API_BASE}/files/{sha256}", payload=file_report(stats(undetected=60), sha256))

    result = await client.scan_file(content)

    assert result.verdict is Verdict.CLEAN
    assert result.report_url == f"https://www.virustotal.com/gui/file/{sha256}"
    assert request_count(api, "POST", FILE_SUBMIT) == 0


async def test_new_file_is_uploaded_and_polled(client, api) -> None:
    content = b"hello"
    sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    api.get(f"{API_BASE}/files/{sha256}", status=404)
    api.post(FILE_SUBMIT, payload=SUBMITTED)
    api.get(ANALYSIS, payload=analysis("completed", stats(malicious=1, undetected=60)))

    result = await client.scan_file(content)

    assert result.verdict is Verdict.SUSPICIOUS
    assert result.report_url == f"https://www.virustotal.com/gui/file/{sha256}"
    assert request_count(api, "POST", FILE_SUBMIT) == 1


async def test_unknown_file_over_upload_limit_is_not_uploaded(client, api, monkeypatch) -> None:
    monkeypatch.setattr(vt_client, "MAX_UPLOAD_BYTES", 3)
    content = b"hello"
    sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    api.get(f"{API_BASE}/files/{sha256}", status=404)

    result = await client.scan_file(content)

    assert result.verdict is Verdict.UNKNOWN
    assert "Too large" in (result.reason or "")
    assert request_count(api, "POST", FILE_SUBMIT) == 0


async def test_hash_lookup_never_uploads(client, api) -> None:
    md5 = "44d88612fea8a8f36de82e1278abb02f"
    api.get(f"{API_BASE}/files/{md5}", status=404)

    result = await client.lookup_hash(md5.upper())

    assert result.verdict is Verdict.UNKNOWN
    assert request_count(api, "POST", FILE_SUBMIT) == 0


async def test_hash_lookup_links_to_the_sha256_report(client, api) -> None:
    md5 = "44d88612fea8a8f36de82e1278abb02f"
    api.get(f"{API_BASE}/files/{md5}", payload=file_report(stats(malicious=60), SHA256))

    result = await client.lookup_hash(md5)

    assert result.verdict is Verdict.MALICIOUS
    assert result.report_url == f"https://www.virustotal.com/gui/file/{SHA256}"


# Failures always produce UNKNOWN


async def test_429_is_retried_then_succeeds(client, api) -> None:
    api.get(URL_REPORT, status=429)
    api.get(URL_REPORT, status=429)
    api.get(URL_REPORT, payload=url_report(stats(harmless=60)))

    result = await client.scan_url(TARGET_URL)

    assert result.verdict is Verdict.CLEAN
    assert request_count(api, "GET", URL_REPORT) == 3


async def test_429_gives_up_after_two_retries(client, api) -> None:
    api.get(URL_REPORT, status=429, repeat=True)

    result = await client.scan_url(TARGET_URL)

    assert result.verdict is Verdict.UNKNOWN
    assert "limit" in (result.reason or "")
    assert request_count(api, "GET", URL_REPORT) == 3


async def test_polling_timeout_is_unknown(api) -> None:
    api.get(URL_REPORT, status=404)
    api.post(URL_SUBMIT, payload=SUBMITTED)
    api.get(ANALYSIS, payload=analysis("queued"), repeat=True)

    async with make_client(scan_timeout_seconds=0.2, poll_interval_seconds=0.01) as vt:
        result = await vt.scan_url(TARGET_URL)

    assert result.verdict is Verdict.UNKNOWN
    assert "still analyzing" in (result.reason or "")


async def test_file_upload_timeout_links_to_the_pending_report(api) -> None:
    sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    api.get(f"{API_BASE}/files/{sha256}", status=404)
    api.post(FILE_SUBMIT, payload=SUBMITTED)
    api.get(ANALYSIS, payload=analysis("queued"), repeat=True)

    async with make_client(scan_timeout_seconds=0.2, poll_interval_seconds=0.01) as vt:
        result = await vt.scan_file(b"hello")

    assert result.verdict is Verdict.UNKNOWN
    assert "again in a few minutes" in (result.reason or "")
    assert result.report_url == f"https://www.virustotal.com/gui/file/{sha256}"


async def test_timeout_while_queued_is_unknown(api) -> None:
    api.get(f"{API_BASE}/files/{SHA256}", payload=file_report(stats(undetected=60)))
    # One request per minute: the second scan has to wait far longer than its timeout.
    limiter = RateLimiter(requests_per_minute=1, daily_limit=500)

    async with make_client(limiter=limiter, scan_timeout_seconds=0.2) as vt:
        await vt.lookup_hash(SHA256)
        result = await vt.lookup_hash("b" * 64)

    assert result.verdict is Verdict.UNKNOWN
    assert "too long" in (result.reason or "")


def test_polling_slows_down_to_a_maximum() -> None:
    delay = vt_client.POLL_INTERVAL_SECONDS
    delays = []
    for _ in range(10):
        delays.append(delay)
        delay = vt_client.next_poll_delay(delay)
    assert delays == sorted(delays)
    assert delays[-1] == vt_client.MAX_POLL_INTERVAL_SECONDS


async def test_network_error_is_unknown(client, api) -> None:
    api.get(URL_REPORT, exception=aiohttp.ClientConnectionError("connection refused"))
    result = await client.scan_url(TARGET_URL)
    assert result.verdict is Verdict.UNKNOWN


async def test_bad_api_key_is_unknown_and_does_not_leak_the_key(client, api) -> None:
    api.get(URL_REPORT, status=401, payload={"error": {"code": "WrongCredentialsError"}})
    result = await client.scan_url(TARGET_URL)
    assert result.verdict is Verdict.UNKNOWN
    assert API_KEY not in (result.reason or "")


async def test_server_error_is_unknown(client, api) -> None:
    api.get(URL_REPORT, status=503)
    assert (await client.scan_url(TARGET_URL)).verdict is Verdict.UNKNOWN


async def test_malformed_response_is_unknown(client, api) -> None:
    api.get(URL_REPORT, payload={"unexpected": True})
    assert (await client.scan_url(TARGET_URL)).verdict is Verdict.UNKNOWN


async def test_daily_quota_returns_unknown_without_calling_the_api(api) -> None:
    api.get(f"{API_BASE}/files/{SHA256}", payload=file_report(stats(undetected=60)))
    limiter = RateLimiter(requests_per_minute=600_000, daily_limit=1)

    async with make_client(limiter=limiter) as vt:
        assert (await vt.lookup_hash(SHA256)).verdict is Verdict.CLEAN
        result = await vt.lookup_hash("b" * 64)

    assert result.verdict is Verdict.UNKNOWN
    assert "quota" in (result.reason or "")
    assert request_count(api, "GET", f"{API_BASE}/files/{'b' * 64}") == 0


# Caching


async def test_repeat_scan_comes_from_cache(client, api) -> None:
    api.get(URL_REPORT, payload=url_report(stats(harmless=60)))

    first = await client.scan_url(TARGET_URL)
    second = await client.scan_url(TARGET_URL)

    assert not first.from_cache
    assert second.from_cache
    assert second.verdict is Verdict.CLEAN
    assert request_count(api, "GET", URL_REPORT) == 1


async def test_unknown_results_are_not_cached(client, api) -> None:
    api.get(URL_REPORT, status=503)
    api.get(URL_REPORT, payload=url_report(stats(harmless=60)))

    assert (await client.scan_url(TARGET_URL)).verdict is Verdict.UNKNOWN
    assert (await client.scan_url(TARGET_URL)).verdict is Verdict.CLEAN
    assert request_count(api, "GET", URL_REPORT) == 2


async def test_concurrent_scans_of_the_same_url_share_one_request(api) -> None:
    api.get(URL_REPORT, payload=url_report(stats(harmless=60)))
    # gather() starts both scans before either finishes, so the second one finds
    # the first still in flight and waits for it instead of making a request.
    limiter = RateLimiter(requests_per_minute=600_000, daily_limit=500)

    async with make_client(limiter=limiter) as vt:
        first, second = await asyncio.gather(vt.scan_url(TARGET_URL), vt.scan_url(TARGET_URL))

    assert first.verdict is second.verdict is Verdict.CLEAN
    assert request_count(api, "GET", URL_REPORT) == 1
    assert limiter.usage().used_today == 1
