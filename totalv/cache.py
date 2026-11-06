"""A time-limited result cache that also merges identical scans running at once."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Generic, TypeVar

T = TypeVar("T")


class TTLCache(Generic[T]):
    """Keeps values for ``ttl_seconds`` and de-duplicates in-flight work.

    If a second request for the same key arrives while the first is still being
    computed, it waits for that computation instead of starting another one.
    That saves VirusTotal quota when several people scan the same link at once.
    """

    def __init__(self, ttl_seconds: float, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._entries: dict[str, tuple[float, T]] = {}
        self._in_flight: dict[str, asyncio.Task[T]] = {}

    def __len__(self) -> int:
        self._remove_expired()
        return len(self._entries)

    def get(self, key: str) -> T | None:
        """Return the cached value, or None if it is missing or expired."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if self._clock() >= expires_at:
            del self._entries[key]
            return None
        return value

    def set(self, key: str, value: T) -> None:
        """Store a value until the TTL runs out."""
        self._remove_expired()
        self._entries[key] = (self._clock() + self._ttl, value)

    async def get_or_compute(
        self,
        key: str,
        compute: Callable[[], Awaitable[T]],
        *,
        should_cache: Callable[[T], bool] | None = None,
    ) -> tuple[T, bool]:
        """Return ``(value, from_cache)``, running ``compute`` only when needed.

        ``should_cache`` decides whether a fresh value is stored. Values it
        rejects are still returned to every caller that was waiting for them.
        """
        cached = self.get(key)
        if cached is not None:
            return cached, True

        task = self._in_flight.get(key)
        if task is None:
            task = asyncio.create_task(self._compute(key, compute, should_cache))
            self._in_flight[key] = task
        # shield() keeps the shared work running if one waiting caller is cancelled.
        return await asyncio.shield(task), False

    async def _compute(
        self,
        key: str,
        compute: Callable[[], Awaitable[T]],
        should_cache: Callable[[T], bool] | None,
    ) -> T:
        try:
            value = await compute()
            if should_cache is None or should_cache(value):
                self.set(key, value)
            return value
        finally:
            self._in_flight.pop(key, None)

    def _remove_expired(self) -> None:
        now = self._clock()
        expired = [key for key, (expires_at, _) in self._entries.items() if now >= expires_at]
        for key in expired:
            del self._entries[key]
