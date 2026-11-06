"""Tests for the TTL cache and in-flight de-duplication."""

from __future__ import annotations

import asyncio

import pytest

from totalv.cache import TTLCache


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_values_expire_after_the_ttl() -> None:
    clock = FakeClock()
    cache: TTLCache[str] = TTLCache(ttl_seconds=60, clock=clock)
    cache.set("key", "value")

    clock.now = 59
    assert cache.get("key") == "value"
    clock.now = 60
    assert cache.get("key") is None
    assert len(cache) == 0


async def test_second_call_is_served_from_cache() -> None:
    cache: TTLCache[str] = TTLCache(ttl_seconds=60)
    calls = 0

    async def compute() -> str:
        nonlocal calls
        calls += 1
        return "result"

    assert await cache.get_or_compute("key", compute) == ("result", False)
    assert await cache.get_or_compute("key", compute) == ("result", True)
    assert calls == 1


async def test_rejected_values_are_returned_but_not_stored() -> None:
    cache: TTLCache[str] = TTLCache(ttl_seconds=60)

    async def compute() -> str:
        return "error"

    value, _ = await cache.get_or_compute("key", compute, should_cache=lambda v: v != "error")
    assert value == "error"
    assert cache.get("key") is None


async def test_concurrent_requests_share_one_computation() -> None:
    cache: TTLCache[str] = TTLCache(ttl_seconds=60)
    release = asyncio.Event()
    calls = 0

    async def compute() -> str:
        nonlocal calls
        calls += 1
        await release.wait()
        return "result"

    first = asyncio.create_task(cache.get_or_compute("key", compute))
    second = asyncio.create_task(cache.get_or_compute("key", compute))
    await asyncio.sleep(0)  # let both tasks start waiting
    release.set()

    assert await first == ("result", False)
    assert await second == ("result", False)
    assert calls == 1


async def test_shared_work_survives_one_caller_being_cancelled() -> None:
    cache: TTLCache[str] = TTLCache(ttl_seconds=60)
    release = asyncio.Event()

    async def compute() -> str:
        await release.wait()
        return "result"

    first = asyncio.create_task(cache.get_or_compute("key", compute))
    second = asyncio.create_task(cache.get_or_compute("key", compute))
    await asyncio.sleep(0)
    first.cancel()
    release.set()

    assert await second == ("result", False)
    with pytest.raises(asyncio.CancelledError):
        await first


async def test_failed_computation_can_be_retried() -> None:
    cache: TTLCache[str] = TTLCache(ttl_seconds=60)

    async def broken() -> str:
        raise RuntimeError("boom")

    async def working() -> str:
        return "ok"

    with pytest.raises(RuntimeError):
        await cache.get_or_compute("key", broken)
    assert await cache.get_or_compute("key", working) == ("ok", False)
