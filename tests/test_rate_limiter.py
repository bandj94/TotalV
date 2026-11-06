"""Tests for request spacing and the daily counter."""

from __future__ import annotations

import asyncio
import time
from datetime import date

import pytest

from totalv.rate_limiter import DailyQuotaExceeded, RateLimiter


async def test_requests_are_spaced_apart() -> None:
    limiter = RateLimiter(requests_per_minute=1200, daily_limit=100)  # 0.05 s apart
    started = time.monotonic()
    for _ in range(3):
        await limiter.acquire()
    # The first request goes straight through, the next two each wait one interval.
    assert time.monotonic() - started >= 0.09


async def test_daily_limit_refuses_without_waiting() -> None:
    limiter = RateLimiter(requests_per_minute=60_000, daily_limit=2)
    await limiter.acquire()
    await limiter.acquire()
    with pytest.raises(DailyQuotaExceeded):
        await limiter.acquire()
    assert limiter.usage().used_today == 2


async def test_counter_resets_when_the_utc_day_changes() -> None:
    current_day = [date(2026, 1, 1)]
    limiter = RateLimiter(requests_per_minute=60_000, daily_limit=1, today=lambda: current_day[0])
    await limiter.acquire()
    with pytest.raises(DailyQuotaExceeded):
        await limiter.acquire()

    current_day[0] = date(2026, 1, 2)
    await limiter.acquire()
    assert limiter.usage().used_today == 1


async def test_queue_length_counts_waiting_callers() -> None:
    limiter = RateLimiter(requests_per_minute=600, daily_limit=100)  # 0.1 s apart
    await limiter.acquire()
    waiters = [asyncio.create_task(limiter.acquire()) for _ in range(3)]
    await asyncio.sleep(0.01)
    assert limiter.usage().queue_length == 3

    await asyncio.gather(*waiters)
    usage = limiter.usage()
    assert usage.queue_length == 0
    assert usage.used_today == 4
