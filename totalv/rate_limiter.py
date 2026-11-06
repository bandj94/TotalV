"""One shared limiter for every VirusTotal request, plus a local daily counter."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime


class DailyQuotaExceeded(Exception):
    """The local daily request budget is used up."""


@dataclass(frozen=True)
class QuotaUsage:
    """A snapshot of request usage for the /quota command."""

    used_today: int
    daily_limit: int
    queue_length: int


def _utc_today() -> date:
    return datetime.now(UTC).date()


class RateLimiter:
    """Spaces requests evenly and refuses new ones once the daily budget is spent.

    The free VirusTotal API allows 4 requests per minute, so requests are spaced
    15 seconds apart. Callers wait their turn in arrival order. The daily counter
    is only a local guard: VirusTotal's HTTP 429 response remains the real limit.
    """

    def __init__(
        self,
        requests_per_minute: int,
        daily_limit: int,
        *,
        today: Callable[[], date] = _utc_today,
    ) -> None:
        self._interval = 60 / requests_per_minute
        self._daily_limit = daily_limit
        self._today = today
        # asyncio.Lock wakes waiters in the order they arrived, which makes it a fair queue.
        self._lock = asyncio.Lock()
        self._next_slot = 0.0
        self._waiting = 0
        self._day = today()
        self._used_today = 0

    async def acquire(self) -> None:
        """Wait for the next request slot and count it.

        Raises DailyQuotaExceeded instead of waiting when today's budget is spent.
        """
        self._check_daily_budget()
        self._waiting += 1
        try:
            async with self._lock:
                # Check again: the budget may have run out while this caller waited.
                self._check_daily_budget()
                loop = asyncio.get_running_loop()
                delay = self._next_slot - loop.time()
                if delay > 0:
                    await asyncio.sleep(delay)
                self._next_slot = loop.time() + self._interval
                self._used_today += 1
        finally:
            self._waiting -= 1

    def usage(self) -> QuotaUsage:
        """Current usage: requests made today and callers waiting for a slot."""
        self._roll_over_day()
        return QuotaUsage(self._used_today, self._daily_limit, self._waiting)

    def _check_daily_budget(self) -> None:
        self._roll_over_day()
        if self._used_today >= self._daily_limit:
            raise DailyQuotaExceeded

    def _roll_over_day(self) -> None:
        """Reset the counter when the UTC date changes, matching VirusTotal's reset."""
        today = self._today()
        if today != self._day:
            self._day = today
            self._used_today = 0
