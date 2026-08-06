"""Unit tests for EventLease renewal failure handling (ISSUE-226)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from app.orchestration.lease import EventLease


class _FakeRedis:
    """Minimal fake that lets us control ``renew()`` behaviour per-test."""

    def __init__(self, renew_side_effect: object = None) -> None:
        self._renew_side_effect = renew_side_effect
        self.get_calls: list[str] = []
        self.expire_calls: list[tuple[str, int]] = []

    async def get(self, key: str) -> bytes | None:
        self.get_calls.append(key)
        # Return the owner_id so the owner check passes.
        return b"worker-test"

    async def expire(self, key: str, ttl: int) -> bool:
        self.expire_calls.append((key, ttl))
        if callable(self._renew_side_effect):
            return self._renew_side_effect(key)
        if isinstance(self._renew_side_effect, Exception):
            raise self._renew_side_effect
        return True

    async def set(self, *args: object, **kwargs: object) -> bool:
        return True

    def register_script(self, _script: str) -> object:
        async def _release(*args: object, **kwargs: object) -> int:
            return 1

        return _release


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_renew_exception_triggers_on_renewal_failed_after_threshold() -> None:
    """After max_renew_failures+1 consecutive exceptions, on_renewal_failed is set."""
    redis_error = ConnectionError("redis down")
    fake_redis = _FakeRedis(renew_side_effect=redis_error)
    lease = EventLease(None)
    # Inject the fake redis client without going through RedisClient.
    lease._redis = fake_redis  # type: ignore[assignment]

    renewal_failed = asyncio.Event()
    # Use a short threshold so the test doesn't sleep for minutes.
    task = await lease.start_renewal(
        "evt-test", "worker-test",
        on_renewal_failed=renewal_failed,
        max_renew_failures=2,
    )

    try:
        # Wait for renewal_failed to be set (or timeout).
        await asyncio.wait_for(renewal_failed.wait(), timeout=5.0)
        assert renewal_failed.is_set()
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_renew_exception_resets_after_successful_renew() -> None:
    """A single exception followed by a success resets the counter."""
    call_count = 0

    async def _flaky_renew(_key: str) -> bool:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConnectionError("transient blip")
        return True

    fake_redis = _FakeRedis()
    fake_redis._renew_side_effect = None
    # Override expire to use the flaky function that raises once then succeeds.
    fake_redis.expire = _flaky_renew  # type: ignore[method-assign]

    lease = EventLease(None)
    lease._redis = fake_redis  # type: ignore[assignment]

    renewal_failed = asyncio.Event()
    # RENEW_INTERVAL_S is 60s — we need to fast-forward.  Monkey-patch the
    # sleep inside _renew_loop so the test runs instantly.
    sleep_count = 0

    async def _fast_sleep(_seconds: float) -> None:
        nonlocal sleep_count
        sleep_count += 1
        if sleep_count > 5:
            # Safety valve — should not need more than 2 iterations.
            raise TimeoutError("test took too many renew iterations")

    with patch("app.orchestration.lease.asyncio.sleep", _fast_sleep):
        task = await lease.start_renewal(
            "evt-test", "worker-test",
            on_renewal_failed=renewal_failed,
            max_renew_failures=2,
        )

    try:
        # The loop should survive the first exception (counter=1) and succeed
        # on the second iteration (counter reset to 0).  renewal_failed must
        # NOT be set.
        await asyncio.sleep(0.2)  # give the loop a moment
        assert not renewal_failed.is_set(), (
            "renewal_failed was set even though the exception count reset"
        )
        assert call_count >= 2
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_renew_owner_mismatch_still_triggers_immediately() -> None:
    """Stolen lease (renew returns False) still sets on_renewal_failed instantly."""
    fake_redis = _FakeRedis()
    # Override get to return a different owner — this makes renew() return False.
    fake_redis.get = AsyncMock(return_value=b"worker-thief")  # type: ignore[method-assign]

    lease = EventLease(None)
    lease._redis = fake_redis  # type: ignore[assignment]

    renewal_failed = asyncio.Event()

    async def _fast_sleep(_seconds: float) -> None:
        pass  # instant

    with patch("app.orchestration.lease.asyncio.sleep", _fast_sleep):
        task = await lease.start_renewal(
            "evt-test", "worker-test",
            on_renewal_failed=renewal_failed,
        )

    try:
        await asyncio.wait_for(renewal_failed.wait(), timeout=2.0)
        assert renewal_failed.is_set()
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_renew_single_exception_below_threshold_does_not_trigger() -> None:
    """One exception below threshold should NOT set on_renewal_failed."""
    error_count = 0

    async def _error_then_stop(_key: str) -> bool:
        nonlocal error_count
        error_count += 1
        if error_count <= 2:
            raise ConnectionError("transient")
        # Third call: succeed — loop continues normally
        return True

    fake_redis = _FakeRedis()
    fake_redis.expire = _error_then_stop  # type: ignore[method-assign]

    lease = EventLease(None)
    lease._redis = fake_redis  # type: ignore[assignment]

    renewal_failed = asyncio.Event()
    iteration = 0

    async def _fast_sleep(_seconds: float) -> None:
        nonlocal iteration
        iteration += 1
        if iteration > 4:
            raise TimeoutError("too many loops")

    with patch("app.orchestration.lease.asyncio.sleep", _fast_sleep):
        task = await lease.start_renewal(
            "evt-test", "worker-test",
            on_renewal_failed=renewal_failed,
            max_renew_failures=2,
        )

    try:
        await asyncio.sleep(0.2)
        assert not renewal_failed.is_set(), (
            "renewal_failed was set even though errors were below threshold"
        )
        # Both errors fired (counter reached 2, threshold is 2) then third
        # call succeeded.  There should have been at least 3 expire calls.
        assert error_count >= 3
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_renew_exception_default_threshold() -> None:
    """Default max_renew_failures=3 triggers on the 4th consecutive error."""
    call_count = 0

    async def _always_error(_key: str) -> bool:
        nonlocal call_count
        call_count += 1
        raise ConnectionError(f"error {call_count}")

    fake_redis = _FakeRedis()
    fake_redis.expire = _always_error  # type: ignore[method-assign]

    lease = EventLease(None)
    lease._redis = fake_redis  # type: ignore[assignment]

    renewal_failed = asyncio.Event()
    iteration = 0

    async def _fast_sleep(_seconds: float) -> None:
        nonlocal iteration
        iteration += 1
        if iteration > 6:
            raise TimeoutError("too many loops")

    with patch("app.orchestration.lease.asyncio.sleep", _fast_sleep):
        task = await lease.start_renewal(
            "evt-test", "worker-test",
            on_renewal_failed=renewal_failed,
        )

    try:
        await asyncio.wait_for(renewal_failed.wait(), timeout=3.0)
        assert renewal_failed.is_set()
        # Default threshold is 3, so trigger happens on the 4th error
        # (consecutive_errors > max_renew_failures, i.e. 4 > 3).
        assert call_count == 4
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_renew_loop_exits_on_first_exception_with_threshold_zero() -> None:
    """max_renew_failures=0 means the first exception triggers failure."""
    fake_redis = _FakeRedis(renew_side_effect=ConnectionError("boom"))
    lease = EventLease(None)
    lease._redis = fake_redis  # type: ignore[assignment]

    renewal_failed = asyncio.Event()

    async def _fast_sleep(_seconds: float) -> None:
        pass

    with patch("app.orchestration.lease.asyncio.sleep", _fast_sleep):
        task = await lease.start_renewal(
            "evt-test", "worker-test",
            on_renewal_failed=renewal_failed,
            max_renew_failures=0,
        )

    try:
        await asyncio.wait_for(renewal_failed.wait(), timeout=2.0)
        assert renewal_failed.is_set()
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_renew_success_does_not_trigger() -> None:
    """Normal successful renewal never sets on_renewal_failed."""
    fake_redis = _FakeRedis()
    lease = EventLease(None)
    lease._redis = fake_redis  # type: ignore[assignment]

    renewal_failed = asyncio.Event()
    iteration = 0

    async def _fast_sleep(_seconds: float) -> None:
        nonlocal iteration
        iteration += 1
        if iteration > 2:
            raise TimeoutError("enough iterations")

    with patch("app.orchestration.lease.asyncio.sleep", _fast_sleep):
        task = await lease.start_renewal(
            "evt-test", "worker-test",
            on_renewal_failed=renewal_failed,
        )

    try:
        await asyncio.sleep(0.2)
        assert not renewal_failed.is_set()
        assert fake_redis.expire_calls  # renew was called
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
