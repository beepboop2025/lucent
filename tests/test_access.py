"""Local tenant authentication, quota, and idempotency behavior."""

from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lucent.access import (  # noqa: E402
    MAX_QUOTA_CAPACITY,
    MAX_QUOTA_REFILL_TOKENS_PER_SECOND,
    AccessController,
    AuthenticationError,
    IdempotencyCapacityError,
    IdempotencyConflictError,
    IdempotencyInProgressError,
    IdempotencyOutcome,
    IdempotencyResponse,
    IdempotencyResponseTooLargeError,
    IdempotencyStore,
    InvalidIdempotencyInputError,
    InvalidReservationError,
    QuotaExceededError,
    QuotaPolicy,
    TenantConfig,
    TokenBucketLimiter,
    fingerprint_request,
    hash_api_key,
)


class FakeClock:
    def __init__(self, initial: float = 0.0) -> None:
        self.now = initial

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _tenant(
    tenant_id: str = "wallet-co",
    api_key: str = "lucent_test_key_0123456789",
    *,
    capacity: int = 2,
    refill: float = 1.0,
    enabled: bool = True,
) -> TenantConfig:
    return TenantConfig.from_api_key(
        tenant_id,
        api_key,
        quota=QuotaPolicy(capacity=capacity, refill_tokens_per_second=refill),
        enabled=enabled,
    )


def _response(body: bytes = b'{"ok":true}') -> IdempotencyResponse:
    return IdempotencyResponse.from_parts(
        200,
        body,
        {"Content-Type": "application/json", "X-Result": "complete"},
    )


def test_runtime_config_hashes_and_redacts_plaintext_api_keys():
    plaintext = "lucent_live_secret_never_render_me"
    config = TenantConfig.from_api_key("tenant-a", plaintext)

    assert config.api_key_hash == hash_api_key(plaintext)
    assert config.api_key_hash.startswith("sha256:")
    assert plaintext not in repr(config)
    assert config.api_key_hash not in repr(config)

    controller = AccessController([config])
    assert controller.authenticate(plaintext).tenant_id == "tenant-a"


@pytest.mark.parametrize("supplied", [None, "", "wrong-secret", object()])
def test_authentication_failures_are_indistinguishable_and_never_echo_keys(supplied):
    controller = AccessController([_tenant()])

    with pytest.raises(AuthenticationError) as caught:
        controller.authenticate(supplied)

    error = caught.value
    assert error.code == "AUTHENTICATION_FAILED"
    assert error.status_code == 401
    assert "wrong-secret" not in str(error)
    assert error.response_headers == {"WWW-Authenticate": 'ApiKey realm="lucent"'}
    assert error.as_problem(request_id="req-1") == {
        "type": "about:blank",
        "title": "Unauthorized",
        "status": 401,
        "code": "AUTHENTICATION_FAILED",
        "detail": "a valid API key is required",
        "request_id": "req-1",
    }


def test_disabled_key_uses_the_same_authentication_failure():
    controller = AccessController([_tenant(enabled=False)])

    with pytest.raises(AuthenticationError) as caught:
        controller.authenticate("lucent_test_key_0123456789")

    assert caught.value.code == "AUTHENTICATION_FAILED"


def test_authenticator_rejects_duplicate_tenants_or_key_hashes():
    with pytest.raises(ValueError, match="tenant ids"):
        AccessController([_tenant("same", "key-a"), _tenant("same", "key-b")])
    with pytest.raises(ValueError, match="key hashes"):
        AccessController([_tenant("one", "same-key"), _tenant("two", "same-key")])


def test_token_bucket_refills_deterministically_and_returns_retry_metadata():
    clock = FakeClock(100)
    limiter = TokenBucketLimiter(
        {"tenant-a": QuotaPolicy(capacity=2, refill_tokens_per_second=0.5)},
        clock=clock,
    )

    first = limiter.consume("tenant-a")
    second = limiter.consume("tenant-a")
    assert (first.limit, first.remaining, first.reset_after_seconds) == (2, 1, 2.0)
    assert (second.limit, second.remaining, second.reset_after_seconds) == (2, 0, 4.0)

    with pytest.raises(QuotaExceededError) as caught:
        limiter.consume("tenant-a")
    error = caught.value
    assert error.as_problem() == {
        "type": "about:blank",
        "title": "Too Many Requests",
        "status": 429,
        "code": "QUOTA_EXCEEDED",
        "detail": "tenant request quota exceeded",
        "retry_after_seconds": 2.0,
        "limit": 2,
        "remaining": 0,
    }
    assert error.response_headers == {"Retry-After": "2"}

    clock.advance(1)
    with pytest.raises(QuotaExceededError) as half_token:
        limiter.consume("tenant-a")
    assert half_token.value.retry_after_seconds == 1.0
    clock.advance(1)
    assert limiter.consume("tenant-a").remaining == 0


def test_quota_policy_enforces_finite_safe_configuration_maxima():
    policy = QuotaPolicy(
        capacity=MAX_QUOTA_CAPACITY,
        refill_tokens_per_second=MAX_QUOTA_REFILL_TOKENS_PER_SECOND,
    )
    assert policy.capacity == MAX_QUOTA_CAPACITY
    assert policy.refill_tokens_per_second == MAX_QUOTA_REFILL_TOKENS_PER_SECOND

    with pytest.raises(ValueError, match="capacity may not exceed"):
        QuotaPolicy(capacity=MAX_QUOTA_CAPACITY + 1)
    with pytest.raises(ValueError, match="refill_tokens_per_second may not exceed"):
        QuotaPolicy(refill_tokens_per_second=MAX_QUOTA_REFILL_TOKENS_PER_SECOND + 1)
    with pytest.raises(ValueError, match="refill_tokens_per_second"):
        QuotaPolicy(refill_tokens_per_second=10**400)


def test_quota_is_isolated_per_tenant_and_authorize_returns_safe_identity():
    clock = FakeClock()
    controller = AccessController(
        [_tenant("one", "key-one", capacity=1), _tenant("two", "key-two", capacity=1)],
        clock=clock,
    )

    grant = controller.authorize("key-one")
    assert grant.tenant.tenant_id == "one"
    assert grant.quota.remaining == 0
    with pytest.raises(QuotaExceededError):
        controller.authorize("key-one")
    assert controller.authorize("key-two").tenant.tenant_id == "two"


def test_quota_does_not_mint_tokens_when_clock_moves_backwards():
    clock = FakeClock(10)
    limiter = TokenBucketLimiter(
        {"tenant": QuotaPolicy(capacity=1, refill_tokens_per_second=1)}, clock=clock
    )
    limiter.consume("tenant")
    clock.now = 5
    with pytest.raises(QuotaExceededError):
        limiter.consume("tenant")
    clock.now = 10.5
    with pytest.raises(QuotaExceededError):
        limiter.consume("tenant")
    clock.now = 11
    assert limiter.consume("tenant").remaining == 0


def test_idempotency_reserve_in_progress_commit_and_replay():
    clock = FakeClock(20)
    store = IdempotencyStore(clock=clock, reservation_ttl_seconds=10, ttl_seconds=30)
    first = store.reserve("tenant", "payment-123", "sha256:request-a")

    assert first.outcome is IdempotencyOutcome.RESERVED
    assert first.reservation is not None
    assert "payment-123" not in repr(first.reservation)
    with pytest.raises(IdempotencyInProgressError) as in_progress:
        store.reserve("tenant", "payment-123", "sha256:request-a")
    assert in_progress.value.retry_after_seconds == 10
    with pytest.raises(IdempotencyConflictError):
        store.reserve("tenant", "payment-123", "sha256:request-b")

    response = _response()
    store.commit(first.reservation, response)
    replay = store.reserve("tenant", "payment-123", "sha256:request-a")
    assert replay.outcome is IdempotencyOutcome.REPLAY
    assert replay.is_replay is True
    assert replay.reservation is None
    assert replay.response == response
    assert replay.response is response
    with pytest.raises(IdempotencyConflictError):
        store.reserve("tenant", "payment-123", "sha256:request-b")


def test_abort_releases_work_and_stale_owner_cannot_commit():
    store = IdempotencyStore(clock=FakeClock())
    first = store.reserve("tenant", "job", "fingerprint")
    assert first.reservation is not None
    assert store.abort(first.reservation) is True
    assert store.abort(first.reservation) is False

    replacement = store.reserve("tenant", "job", "fingerprint")
    assert replacement.reservation is not None
    with pytest.raises(InvalidReservationError):
        store.commit(first.reservation, _response())
    store.commit(replacement.reservation, _response(b"replacement"))


def test_reservations_and_replays_expire_on_separate_ttls():
    clock = FakeClock()
    store = IdempotencyStore(
        clock=clock,
        reservation_ttl_seconds=5,
        ttl_seconds=10,
    )
    stale = store.reserve("tenant", "job", "fingerprint")
    assert stale.reservation is not None
    clock.advance(5)
    replacement = store.reserve("tenant", "job", "fingerprint")
    assert replacement.reservation is not None
    with pytest.raises(InvalidReservationError):
        store.commit(stale.reservation, _response())

    store.commit(replacement.reservation, _response())
    clock.advance(9.99)
    assert store.reserve("tenant", "job", "fingerprint").is_replay is True
    clock.advance(0.01)
    after_ttl = store.reserve("tenant", "job", "fingerprint")
    assert after_ttl.outcome is IdempotencyOutcome.RESERVED


def test_completed_entries_use_lru_eviction_but_live_reservations_are_preserved():
    clock = FakeClock()
    store = IdempotencyStore(clock=clock, max_entries=2)
    one = store.reserve("tenant", "one", "fp-one")
    two = store.reserve("tenant", "two", "fp-two")
    assert one.reservation is not None and two.reservation is not None
    store.commit(one.reservation, _response(b"one"))
    store.commit(two.reservation, _response(b"two"))

    # Touch one, making two the least recently used completed result.
    assert store.reserve("tenant", "one", "fp-one").is_replay
    three = store.reserve("tenant", "three", "fp-three")
    assert three.reservation is not None
    assert store.reserve("tenant", "one", "fp-one").is_replay
    assert store.reserve("tenant", "two", "fp-two").outcome is IdempotencyOutcome.RESERVED


def test_aggregate_response_budget_uses_lru_and_exact_byte_accounting():
    store = IdempotencyStore(
        clock=FakeClock(),
        max_entries=4,
        max_response_bytes=6,
        max_total_response_bytes=10,
    )
    one = store.reserve("tenant", "one", "fp-one")
    two = store.reserve("tenant", "two", "fp-two")
    assert one.reservation is not None and two.reservation is not None
    store.commit(one.reservation, IdempotencyResponse(200, b"123456"))
    store.commit(two.reservation, IdempotencyResponse(200, b"1234"))
    assert store.cached_response_bytes == 10

    # Make the six-byte response newer, then admit a four-byte response. The
    # aggregate limit should evict only the older four-byte response.
    assert store.reserve("tenant", "one", "fp-one").is_replay
    three = store.reserve("tenant", "three", "fp-three")
    assert three.reservation is not None
    store.commit(three.reservation, IdempotencyResponse(200, b"abcd"))

    assert store.cached_response_bytes == 10
    assert store.reserve("tenant", "one", "fp-one").is_replay
    assert store.reserve("tenant", "three", "fp-three").is_replay
    assert store.reserve("tenant", "two", "fp-two").outcome is IdempotencyOutcome.RESERVED


def test_cached_response_accounting_decrements_exactly_as_entries_expire():
    clock = FakeClock()
    store = IdempotencyStore(
        clock=clock,
        ttl_seconds=5,
        max_response_bytes=10,
        max_total_response_bytes=20,
    )
    one = store.reserve("tenant", "one", "fp-one")
    assert one.reservation is not None
    response_one = IdempotencyResponse(200, b"abc", [("X", "yz")])
    store.commit(one.reservation, response_one)
    clock.advance(2)
    two = store.reserve("tenant", "two", "fp-two")
    assert two.reservation is not None
    response_two = IdempotencyResponse(200, b"wxyz")
    store.commit(two.reservation, response_two)
    assert store.cached_response_bytes == response_one.size_bytes + response_two.size_bytes

    clock.advance(3)
    assert store.cached_response_bytes == response_two.size_bytes
    assert len(store) == 1
    clock.advance(2)
    assert store.cached_response_bytes == 0
    assert len(store) == 0


def test_no_evict_mode_reserves_response_capacity_before_work_starts():
    clock = FakeClock()
    store = IdempotencyStore(
        clock=clock,
        ttl_seconds=5,
        reservation_ttl_seconds=3,
        max_entries=4,
        max_response_bytes=6,
        max_total_response_bytes=10,
        evict_completed_entries=False,
    )
    one = store.reserve("tenant", "one", "fp-one")
    assert one.reservation is not None

    # Each live reservation holds the maximum response size, so the second
    # request fails before any paid work could begin.
    with pytest.raises(IdempotencyCapacityError) as unavailable:
        store.reserve("tenant", "two", "fp-two")
    assert unavailable.value.retry_after_seconds == 3
    assert store.abort(one.reservation) is True

    two = store.reserve("tenant", "two", "fp-two")
    assert two.reservation is not None
    store.commit(two.reservation, IdempotencyResponse(200, b"1234"))
    three = store.reserve("tenant", "three", "fp-three")
    assert three.reservation is not None
    store.commit(three.reservation, IdempotencyResponse(200, b"123456"))
    assert store.cached_response_bytes == 10

    with pytest.raises(IdempotencyCapacityError):
        store.reserve("tenant", "four", "fp-four")
    assert store.reserve("tenant", "two", "fp-two").is_replay
    assert store.reserve("tenant", "three", "fp-three").is_replay

    clock.advance(5)
    assert store.cached_response_bytes == 0
    assert store.reserve("tenant", "four", "fp-four").reservation is not None


def test_no_evict_mode_never_discards_completed_entries_at_entry_capacity():
    store = IdempotencyStore(
        clock=FakeClock(),
        max_entries=2,
        max_response_bytes=4,
        max_total_response_bytes=8,
        evict_completed_entries=False,
    )
    one = store.reserve("tenant", "one", "fp-one")
    two = store.reserve("tenant", "two", "fp-two")
    assert one.reservation is not None and two.reservation is not None
    store.commit(one.reservation, IdempotencyResponse(200, b"1"))
    store.commit(two.reservation, IdempotencyResponse(200, b"2"))

    with pytest.raises(IdempotencyCapacityError):
        store.reserve("tenant", "three", "fp-three")
    assert store.cached_response_bytes == 2
    assert store.reserve("tenant", "one", "fp-one").is_replay
    assert store.reserve("tenant", "two", "fp-two").is_replay


def test_aggregate_budget_configuration_and_controller_wiring():
    with pytest.raises(ValueError, match="may not be less"):
        IdempotencyStore(max_response_bytes=5, max_total_response_bytes=4)
    with pytest.raises(TypeError, match="evict_completed_entries"):
        IdempotencyStore(evict_completed_entries=1)

    controller = AccessController(
        [_tenant()],
        clock=FakeClock(),
        max_idempotency_entries=2,
        max_idempotency_response_bytes=4,
        max_idempotency_total_response_bytes=4,
        evict_completed_idempotency_entries=False,
    )
    controller.reserve_idempotency("wallet-co", "one", "fp-one")
    with pytest.raises(IdempotencyCapacityError):
        controller.reserve_idempotency("wallet-co", "two", "fp-two")


def test_store_full_of_live_reservations_fails_closed_until_one_expires():
    clock = FakeClock()
    store = IdempotencyStore(clock=clock, max_entries=1, reservation_ttl_seconds=3)
    store.reserve("tenant", "one", "fp-one")

    with pytest.raises(IdempotencyCapacityError) as caught:
        store.reserve("tenant", "two", "fp-two")
    assert caught.value.status_code == 503
    assert caught.value.retry_after_seconds == 3
    assert caught.value.response_headers == {"Retry-After": "3"}

    clock.advance(3)
    assert store.reserve("tenant", "two", "fp-two").outcome is IdempotencyOutcome.RESERVED


def test_cached_response_size_is_bounded_and_reservation_remains_abortable():
    store = IdempotencyStore(clock=FakeClock(), max_response_bytes=4)
    decision = store.reserve("tenant", "key", "fingerprint")
    assert decision.reservation is not None

    with pytest.raises(IdempotencyResponseTooLargeError) as caught:
        store.commit(decision.reservation, IdempotencyResponse(200, b"12345"))
    assert caught.value.context == {"max_bytes": 4}
    assert store.abort(decision.reservation) is True


def test_response_freezes_mutable_inputs_and_rejects_header_injection():
    body = bytearray(b"safe")
    response = IdempotencyResponse(200, body, [("X-Test", "yes")])
    body[:] = b"evil"
    assert response.body == b"safe"
    assert response.headers == (("X-Test", "yes"),)

    with pytest.raises(ValueError, match="newlines"):
        IdempotencyResponse(200, b"ok", [("X-Test", "safe\r\nInjected: yes")])


def test_idempotency_keys_are_tenant_scoped_and_controller_rejects_unknown_tenant():
    controller = AccessController([_tenant("configured")], clock=FakeClock())
    one = controller.reserve_idempotency("configured", "same-key", "fingerprint")
    assert one.outcome is IdempotencyOutcome.RESERVED

    with pytest.raises(ValueError, match="not configured"):
        controller.reserve_idempotency("attacker", "same-key", "fingerprint")

    store = IdempotencyStore(clock=FakeClock())
    assert store.reserve("one", "same-key", "fingerprint").reservation is not None
    assert store.reserve("two", "same-key", "fingerprint").reservation is not None


def test_bounded_unicode_fingerprints_have_normal_conflict_semantics():
    store = IdempotencyStore(clock=FakeClock())
    store.reserve("tenant", "key", "request-☃")
    with pytest.raises(IdempotencyInProgressError):
        store.reserve("tenant", "key", "request-☃")
    with pytest.raises(IdempotencyConflictError):
        store.reserve("tenant", "key", "request-☀")


@pytest.mark.parametrize(
    ("key", "fingerprint"),
    [
        ("", "fingerprint"),
        ("key", ""),
        ("x" * 257, "fingerprint"),
        ("key", "x" * 257),
    ],
)
def test_invalid_idempotency_input_is_structured_and_does_not_echo_values(key, fingerprint):
    store = IdempotencyStore(clock=FakeClock())
    with pytest.raises(InvalidIdempotencyInputError) as caught:
        store.reserve("tenant", key, fingerprint)

    assert caught.value.code == "INVALID_IDEMPOTENCY_INPUT"
    assert caught.value.status_code == 400
    assert key not in caught.value.detail or not key
    assert fingerprint not in caught.value.detail or not fingerprint


def test_concurrent_equivalent_requests_have_exactly_one_owner():
    store = IdempotencyStore(clock=FakeClock())

    def attempt():
        try:
            return store.reserve("tenant", "same-key", "same-fingerprint").outcome
        except IdempotencyInProgressError:
            return "in_progress"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _index: attempt(), range(32)))

    assert outcomes.count(IdempotencyOutcome.RESERVED) == 1
    assert outcomes.count("in_progress") == 31


def test_request_fingerprint_is_stable_and_type_checked():
    assert fingerprint_request(b'{"a":1}') == fingerprint_request(bytearray(b'{"a":1}'))
    assert fingerprint_request(b'{"a":1}').startswith("sha256:")
    assert fingerprint_request(b'{"a":1}') != fingerprint_request(b'{"a":2}')
    with pytest.raises(TypeError, match="bytes-like"):
        fingerprint_request('{"a":1}')
