"""Local authentication, quota, and idempotency primitives for hosted Lucent.

This module deliberately has no HTTP or persistence dependency.  It is suitable
for a single-process edge service; callers can translate :class:`AccessError`
into their transport's error shape and replace this implementation when shared
state is required across workers.

Plaintext API keys are accepted only at authentication/provisioning boundaries.
Runtime configuration and idempotency state retain hashes, never those secrets.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

API_KEY_HASH_PREFIX = "sha256:"
MAX_API_KEY_BYTES = 4_096
MAX_TENANT_ID_BYTES = 128
MAX_IDEMPOTENCY_KEY_BYTES = 256
MAX_FINGERPRINT_BYTES = 256
MAX_CACHED_HEADERS = 64
MAX_HEADER_LINE_BYTES = 8_192
MAX_QUOTA_CAPACITY = 1_000_000
MAX_QUOTA_REFILL_TOKENS_PER_SECOND = 100_000.0
DEFAULT_IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60
DEFAULT_RESERVATION_TTL_SECONDS = 60
DEFAULT_MAX_IDEMPOTENCY_ENTRIES = 10_000
DEFAULT_MAX_IDEMPOTENCY_RESPONSE_BYTES = 1024 * 1024
DEFAULT_MAX_IDEMPOTENCY_TOTAL_RESPONSE_BYTES = 64 * 1024 * 1024

_HASH_RE = re.compile(r"^sha256:([0-9a-f]{64})$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

Clock = Callable[[], float]


class AccessError(Exception):
    """A safe, structured failure at the access-control boundary."""

    def __init__(
        self,
        *,
        code: str,
        title: str,
        status_code: int,
        detail: str,
        retry_after_seconds: float | None = None,
        context: Mapping[str, int | float | str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.title = title
        self.status_code = status_code
        self.detail = detail
        self.retry_after_seconds = retry_after_seconds
        self.context = dict(context or {})

    def as_problem(self, *, request_id: str | None = None) -> dict[str, Any]:
        """Return an RFC 9457-style problem object with stable extension fields."""
        problem: dict[str, Any] = {
            "type": "about:blank",
            "title": self.title,
            "status": self.status_code,
            "code": self.code,
            "detail": self.detail,
        }
        if request_id is not None:
            problem["request_id"] = request_id
        if self.retry_after_seconds is not None:
            problem["retry_after_seconds"] = self.retry_after_seconds
        problem.update(self.context)
        return problem

    @property
    def response_headers(self) -> dict[str, str]:
        """Headers a transport should attach to this error response."""
        if self.retry_after_seconds is None:
            return {}
        return {"Retry-After": str(max(1, math.ceil(self.retry_after_seconds)))}


class AuthenticationError(AccessError):
    """A missing, malformed, disabled, or unrecognized API credential."""

    def __init__(self) -> None:
        # Use one response for every authentication failure to avoid tenant/key
        # enumeration and, importantly, never interpolate the supplied key.
        super().__init__(
            code="AUTHENTICATION_FAILED",
            title="Unauthorized",
            status_code=401,
            detail="a valid API key is required",
        )

    @property
    def response_headers(self) -> dict[str, str]:
        return {"WWW-Authenticate": 'ApiKey realm="lucent"'}


class QuotaExceededError(AccessError):
    """The authenticated tenant's token bucket lacks sufficient capacity."""

    def __init__(self, *, limit: int, remaining: int, retry_after_seconds: float) -> None:
        super().__init__(
            code="QUOTA_EXCEEDED",
            title="Too Many Requests",
            status_code=429,
            detail="tenant request quota exceeded",
            retry_after_seconds=retry_after_seconds,
            context={"limit": limit, "remaining": remaining},
        )


class IdempotencyConflictError(AccessError):
    """An idempotency key was reused for a different request fingerprint."""

    def __init__(self) -> None:
        super().__init__(
            code="IDEMPOTENCY_CONFLICT",
            title="Conflict",
            status_code=409,
            detail="idempotency key was already used for a different request",
        )


class IdempotencyInProgressError(AccessError):
    """An equivalent request currently owns the idempotency reservation."""

    def __init__(self, *, retry_after_seconds: float) -> None:
        super().__init__(
            code="IDEMPOTENCY_IN_PROGRESS",
            title="Conflict",
            status_code=409,
            detail="an equivalent request is still in progress",
            retry_after_seconds=retry_after_seconds,
        )


class IdempotencyCapacityError(AccessError):
    """The bounded store cannot admit work without violating its policy."""

    def __init__(self, *, retry_after_seconds: float) -> None:
        super().__init__(
            code="IDEMPOTENCY_CAPACITY_EXCEEDED",
            title="Service Unavailable",
            status_code=503,
            detail="idempotency capacity is temporarily exhausted",
            retry_after_seconds=retry_after_seconds,
        )


class InvalidIdempotencyInputError(AccessError):
    """An idempotency key or request fingerprint is missing or malformed."""

    def __init__(self, detail: str) -> None:
        super().__init__(
            code="INVALID_IDEMPOTENCY_INPUT",
            title="Bad Request",
            status_code=400,
            detail=detail,
        )


class InvalidReservationError(AccessError):
    """A reservation is expired, already finalized, or owned by another caller."""

    def __init__(self) -> None:
        super().__init__(
            code="INVALID_IDEMPOTENCY_RESERVATION",
            title="Conflict",
            status_code=409,
            detail="idempotency reservation is no longer active",
        )


class IdempotencyResponseTooLargeError(AccessError):
    """A response cannot be retained within the configured memory bound."""

    def __init__(self, *, max_bytes: int) -> None:
        super().__init__(
            code="IDEMPOTENCY_RESPONSE_TOO_LARGE",
            title="Internal Server Error",
            status_code=500,
            detail="response exceeds the idempotency cache limit",
            context={"max_bytes": max_bytes},
        )


def _secret_bytes(secret: str | bytes | bytearray | memoryview) -> bytes:
    if isinstance(secret, str):
        encoded = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        encoded = secret
    elif isinstance(secret, (bytearray, memoryview)):
        encoded = bytes(secret)
    else:
        raise TypeError("API key must be text or bytes")
    if not encoded:
        raise ValueError("API key must not be empty")
    if len(encoded) > MAX_API_KEY_BYTES:
        raise ValueError(f"API key may not exceed {MAX_API_KEY_BYTES} encoded bytes")
    return encoded


def hash_api_key(api_key: str | bytes | bytearray | memoryview) -> str:
    """Hash an API key for runtime configuration without retaining plaintext."""
    return API_KEY_HASH_PREFIX + hashlib.sha256(_secret_bytes(api_key)).hexdigest()


def fingerprint_request(body: bytes | bytearray | memoryview) -> str:
    """Return a stable fingerprint for an already canonicalized request body."""
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise TypeError("request body must be bytes-like")
    return API_KEY_HASH_PREFIX + hashlib.sha256(bytes(body)).hexdigest()


def _parse_api_key_hash(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("api_key_hash must be a sha256 string")
    match = _HASH_RE.fullmatch(value)
    if match is None:
        raise ValueError("api_key_hash must use canonical sha256:<lowercase hex>")
    return bytes.fromhex(match.group(1))


def _positive_finite(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number")
    try:
        normalized = float(value)
    except OverflowError as exc:
        raise ValueError(f"{name} must be positive and finite") from exc
    if not math.isfinite(normalized) or normalized <= 0:
        raise ValueError(f"{name} must be positive and finite")
    return normalized


def _positive_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _bounded_text(value: str, name: str, max_bytes: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be text")
    if not value or len(value.encode("utf-8")) > max_bytes:
        raise ValueError(f"{name} must contain 1 to {max_bytes} encoded bytes")
    return value


def _now(clock: Clock) -> float:
    value = clock()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("clock must return a number")
    normalized = float(value)
    if not math.isfinite(normalized):
        raise ValueError("clock must return a finite number")
    return normalized


@dataclass(frozen=True, slots=True)
class QuotaPolicy:
    """Token-bucket parameters for one tenant."""

    capacity: int = 60
    refill_tokens_per_second: float = 1.0

    def __post_init__(self) -> None:
        capacity = _positive_int(self.capacity, "capacity")
        if capacity > MAX_QUOTA_CAPACITY:
            raise ValueError(f"capacity may not exceed {MAX_QUOTA_CAPACITY}")
        refill = _positive_finite(
            self.refill_tokens_per_second,
            "refill_tokens_per_second",
        )
        if refill > MAX_QUOTA_REFILL_TOKENS_PER_SECOND:
            raise ValueError(
                "refill_tokens_per_second may not exceed "
                f"{MAX_QUOTA_REFILL_TOKENS_PER_SECOND:g}"
            )


@dataclass(frozen=True, slots=True)
class TenantConfig:
    """Runtime tenant configuration containing a hash, never a plaintext key."""

    tenant_id: str
    api_key_hash: str = field(repr=False)
    quota: QuotaPolicy = field(default_factory=QuotaPolicy)
    enabled: bool = True

    def __post_init__(self) -> None:
        _bounded_text(self.tenant_id, "tenant_id", MAX_TENANT_ID_BYTES)
        _parse_api_key_hash(self.api_key_hash)
        if not isinstance(self.quota, QuotaPolicy):
            raise TypeError("quota must be a QuotaPolicy")
        if not isinstance(self.enabled, bool):
            raise TypeError("enabled must be a boolean")

    @classmethod
    def from_api_key(
        cls,
        tenant_id: str,
        api_key: str | bytes | bytearray | memoryview,
        *,
        quota: QuotaPolicy | None = None,
        enabled: bool = True,
    ) -> TenantConfig:
        """Provision a config while immediately discarding the plaintext key."""
        return cls(
            tenant_id=tenant_id,
            api_key_hash=hash_api_key(api_key),
            quota=quota or QuotaPolicy(),
            enabled=enabled,
        )


@dataclass(frozen=True, slots=True)
class TenantIdentity:
    """The non-secret identity returned after successful authentication."""

    tenant_id: str


class ApiKeyAuthenticator:
    """Authenticate supplied API keys against configured SHA-256 digests."""

    def __init__(self, tenants: Iterable[TenantConfig]) -> None:
        records: list[tuple[bytes, TenantIdentity, bool]] = []
        tenant_ids: set[str] = set()
        digests: set[bytes] = set()
        for config in tenants:
            if not isinstance(config, TenantConfig):
                raise TypeError("tenants must contain TenantConfig values")
            digest = _parse_api_key_hash(config.api_key_hash)
            if config.tenant_id in tenant_ids:
                raise ValueError("tenant ids must be unique")
            if digest in digests:
                raise ValueError("API key hashes must be unique")
            tenant_ids.add(config.tenant_id)
            digests.add(digest)
            records.append((digest, TenantIdentity(config.tenant_id), config.enabled))
        if not records:
            raise ValueError("at least one tenant must be configured")
        self._records = tuple(records)

    def authenticate(self, api_key: str | bytes | bytearray | memoryview | None) -> TenantIdentity:
        """Return the matching tenant or one generic authentication failure.

        Every configured digest is checked with ``compare_digest`` and there is
        no logging in this module.  Invalid inputs are intentionally collapsed
        into the same safe failure as an unknown key.
        """
        supplied_digest = hashlib.sha256(b"invalid-api-key").digest()
        candidate_is_valid = False
        if api_key is not None:
            try:
                supplied_digest = hashlib.sha256(_secret_bytes(api_key)).digest()
                candidate_is_valid = True
            except (TypeError, ValueError, UnicodeError):
                pass

        match: TenantIdentity | None = None
        match_enabled = False
        for configured_digest, identity, enabled in self._records:
            if hmac.compare_digest(supplied_digest, configured_digest):
                match = identity
                match_enabled = enabled
        if not candidate_is_valid or match is None or not match_enabled:
            raise AuthenticationError
        return match


@dataclass(frozen=True, slots=True)
class QuotaReceipt:
    """Quota information for an accepted request."""

    limit: int
    remaining: int
    reset_after_seconds: float


@dataclass(slots=True)
class _Bucket:
    tokens: float
    last_refill: float


class TokenBucketLimiter:
    """Thread-safe, per-configured-tenant in-memory token buckets."""

    def __init__(self, policies: Mapping[str, QuotaPolicy], *, clock: Clock = time.monotonic):
        if not policies:
            raise ValueError("at least one quota policy must be configured")
        checked: dict[str, QuotaPolicy] = {}
        for tenant_id, policy in policies.items():
            _bounded_text(tenant_id, "tenant_id", MAX_TENANT_ID_BYTES)
            if not isinstance(policy, QuotaPolicy):
                raise TypeError("policies must map tenant ids to QuotaPolicy values")
            checked[tenant_id] = policy
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._policies = checked
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.RLock()

    def consume(self, tenant_id: str, *, cost: float = 1.0) -> QuotaReceipt:
        """Consume quota or raise :class:`QuotaExceededError`."""
        policy = self._policies.get(tenant_id)
        if policy is None:
            raise ValueError("tenant has no configured quota policy")
        normalized_cost = _positive_finite(cost, "cost")
        if normalized_cost > policy.capacity:
            raise ValueError("cost may not exceed tenant quota capacity")

        with self._lock:
            now = _now(self._clock)
            bucket = self._buckets.get(tenant_id)
            if bucket is None:
                bucket = _Bucket(tokens=float(policy.capacity), last_refill=now)
                self._buckets[tenant_id] = bucket
            else:
                elapsed = max(0.0, now - bucket.last_refill)
                bucket.tokens = min(
                    float(policy.capacity),
                    bucket.tokens + elapsed * policy.refill_tokens_per_second,
                )
                # A misbehaving/test clock moving backwards must not make the
                # next forward reading double-count elapsed time.
                bucket.last_refill = max(bucket.last_refill, now)

            if bucket.tokens + 1e-12 < normalized_cost:
                retry_after = (normalized_cost - bucket.tokens) / policy.refill_tokens_per_second
                raise QuotaExceededError(
                    limit=policy.capacity,
                    remaining=max(0, math.floor(bucket.tokens)),
                    retry_after_seconds=retry_after,
                )

            bucket.tokens = max(0.0, bucket.tokens - normalized_cost)
            reset_after = (
                (policy.capacity - bucket.tokens) / policy.refill_tokens_per_second
            )
            return QuotaReceipt(
                limit=policy.capacity,
                remaining=max(0, math.floor(bucket.tokens + 1e-12)),
                reset_after_seconds=reset_after,
            )


class IdempotencyOutcome(StrEnum):
    RESERVED = "reserved"
    REPLAY = "replay"


@dataclass(frozen=True, slots=True)
class IdempotencyResponse:
    """An immutable transport-neutral response retained for exact replay."""

    status_code: int
    body: bytes
    headers: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.status_code, bool) or not isinstance(self.status_code, int):
            raise TypeError("status_code must be an integer")
        if not 100 <= self.status_code <= 599:
            raise ValueError("status_code must be between 100 and 599")
        if not isinstance(self.body, (bytes, bytearray, memoryview)):
            raise TypeError("body must be bytes-like")
        object.__setattr__(self, "body", bytes(self.body))
        if not isinstance(self.headers, (tuple, list)):
            raise TypeError("headers must be a sequence of name/value pairs")
        if len(self.headers) > MAX_CACHED_HEADERS:
            raise ValueError(f"headers may not exceed {MAX_CACHED_HEADERS} entries")
        normalized_headers: list[tuple[str, str]] = []
        for header in self.headers:
            if not isinstance(header, (tuple, list)) or len(header) != 2:
                raise TypeError("headers must contain name/value pairs")
            name, value = header
            if not isinstance(name, str) or _HEADER_NAME_RE.fullmatch(name) is None:
                raise ValueError("header names must be valid HTTP tokens")
            if not isinstance(value, str):
                raise TypeError("header values must be text")
            if "\r" in value or "\n" in value:
                raise ValueError("header values may not contain newlines")
            if len(name.encode("ascii")) + len(value.encode("utf-8")) > MAX_HEADER_LINE_BYTES:
                raise ValueError(
                    f"cached header lines may not exceed {MAX_HEADER_LINE_BYTES} bytes"
                )
            normalized_headers.append((name, value))
        object.__setattr__(self, "headers", tuple(normalized_headers))

    @classmethod
    def from_parts(
        cls,
        status_code: int,
        body: bytes | bytearray | memoryview,
        headers: Mapping[str, str] | Sequence[tuple[str, str]] | None = None,
    ) -> IdempotencyResponse:
        if headers is None:
            normalized: tuple[tuple[str, str], ...] = ()
        elif isinstance(headers, Mapping):
            normalized = tuple(headers.items())
        else:
            normalized = tuple(headers)
        return cls(status_code=status_code, body=bytes(body), headers=normalized)

    @property
    def size_bytes(self) -> int:
        return len(self.body) + sum(
            len(name.encode("ascii")) + len(value.encode("utf-8"))
            for name, value in self.headers
        )


@dataclass(frozen=True, slots=True)
class IdempotencyReservation:
    """Opaque ownership proof for completing or aborting one reservation."""

    tenant_id: str
    expires_at: float
    _key_digest: bytes = field(repr=False)
    _fingerprint: str = field(repr=False)
    _token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class IdempotencyDecision:
    """Either ownership of new work or an immutable completed replay."""

    outcome: IdempotencyOutcome
    reservation: IdempotencyReservation | None = None
    response: IdempotencyResponse | None = None

    @property
    def is_replay(self) -> bool:
        return self.outcome is IdempotencyOutcome.REPLAY


class _EntryState(StrEnum):
    RESERVED = "reserved"
    COMPLETE = "complete"


@dataclass(slots=True)
class _IdempotencyEntry:
    fingerprint: str
    token: str
    state: _EntryState
    expires_at: float
    response: IdempotencyResponse | None = None
    reserved_response_bytes: int = 0


class IdempotencyStore:
    """A thread-safe TTL/LRU idempotency store with bounded response memory.

    Expired entries are removed lazily on every operation.  By default, entry
    or aggregate-byte pressure evicts least-recently-used completed responses;
    ``evict_completed_entries=False`` instead fails capacity so payment callers
    can preserve every unexpired outcome. In that mode, each admitted reservation
    holds enough aggregate capacity for a maximum-sized response, so capacity
    failure occurs before paid work starts rather than after it finishes. Active
    reservations are never evicted.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_IDEMPOTENCY_TTL_SECONDS,
        reservation_ttl_seconds: float = DEFAULT_RESERVATION_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_IDEMPOTENCY_ENTRIES,
        max_response_bytes: int = DEFAULT_MAX_IDEMPOTENCY_RESPONSE_BYTES,
        max_total_response_bytes: int = DEFAULT_MAX_IDEMPOTENCY_TOTAL_RESPONSE_BYTES,
        evict_completed_entries: bool = True,
        clock: Clock = time.monotonic,
    ) -> None:
        self._ttl_seconds = _positive_finite(ttl_seconds, "ttl_seconds")
        self._reservation_ttl_seconds = _positive_finite(
            reservation_ttl_seconds, "reservation_ttl_seconds"
        )
        self._max_entries = _positive_int(max_entries, "max_entries")
        self._max_response_bytes = _positive_int(max_response_bytes, "max_response_bytes")
        self._max_total_response_bytes = _positive_int(
            max_total_response_bytes,
            "max_total_response_bytes",
        )
        if self._max_total_response_bytes < self._max_response_bytes:
            raise ValueError("max_total_response_bytes may not be less than max_response_bytes")
        if not isinstance(evict_completed_entries, bool):
            raise TypeError("evict_completed_entries must be a boolean")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._evict_completed_entries = evict_completed_entries
        self._clock = clock
        self._entries: OrderedDict[tuple[str, bytes], _IdempotencyEntry] = OrderedDict()
        self._cached_response_bytes = 0
        self._reserved_response_bytes = 0
        self._lock = threading.RLock()

    def reserve(self, tenant_id: str, key: str, fingerprint: str) -> IdempotencyDecision:
        """Reserve unseen work, replay completed work, or raise on key misuse."""
        try:
            checked_tenant = _bounded_text(tenant_id, "tenant_id", MAX_TENANT_ID_BYTES)
            checked_key = _bounded_text(key, "idempotency key", MAX_IDEMPOTENCY_KEY_BYTES)
            checked_fingerprint = _bounded_text(
                fingerprint, "request fingerprint", MAX_FINGERPRINT_BYTES
            )
        except (TypeError, ValueError) as exc:
            raise InvalidIdempotencyInputError(str(exc)) from None
        key_digest = hashlib.sha256(checked_key.encode("utf-8")).digest()
        cache_key = (checked_tenant, key_digest)

        with self._lock:
            now = _now(self._clock)
            self._expire(now)
            existing = self._entries.get(cache_key)
            if existing is not None:
                # Fingerprints are bounded request identifiers rather than
                # secrets, so ordinary equality also supports Unicode input.
                if existing.fingerprint != checked_fingerprint:
                    raise IdempotencyConflictError
                if existing.state is _EntryState.RESERVED:
                    raise IdempotencyInProgressError(
                        retry_after_seconds=max(0.0, existing.expires_at - now)
                    )
                if existing.response is None:  # defensive invariant
                    raise InvalidReservationError
                self._entries.move_to_end(cache_key)
                return IdempotencyDecision(
                    outcome=IdempotencyOutcome.REPLAY,
                    response=existing.response,
                )

            self._make_room(now)
            reserved_response_bytes = 0
            if not self._evict_completed_entries:
                reserved_response_bytes = self._max_response_bytes
                if (
                    self._cached_response_bytes
                    + self._reserved_response_bytes
                    + reserved_response_bytes
                    > self._max_total_response_bytes
                ):
                    raise self._capacity_error(now)
            token = secrets.token_urlsafe(24)
            expires_at = now + self._reservation_ttl_seconds
            self._entries[cache_key] = _IdempotencyEntry(
                fingerprint=checked_fingerprint,
                token=token,
                state=_EntryState.RESERVED,
                expires_at=expires_at,
                reserved_response_bytes=reserved_response_bytes,
            )
            self._reserved_response_bytes += reserved_response_bytes
            reservation = IdempotencyReservation(
                tenant_id=checked_tenant,
                expires_at=expires_at,
                _key_digest=key_digest,
                _fingerprint=checked_fingerprint,
                _token=token,
            )
            return IdempotencyDecision(
                outcome=IdempotencyOutcome.RESERVED,
                reservation=reservation,
            )

    def commit(
        self,
        reservation: IdempotencyReservation,
        response: IdempotencyResponse,
    ) -> None:
        """Atomically publish a response for future equivalent replays."""
        if not isinstance(reservation, IdempotencyReservation):
            raise TypeError("reservation must be an IdempotencyReservation")
        if not isinstance(response, IdempotencyResponse):
            raise TypeError("response must be an IdempotencyResponse")
        if response.size_bytes > self._max_response_bytes:
            raise IdempotencyResponseTooLargeError(max_bytes=self._max_response_bytes)

        cache_key = (reservation.tenant_id, reservation._key_digest)
        with self._lock:
            now = _now(self._clock)
            self._expire(now)
            entry = self._entries.get(cache_key)
            if not self._owns(entry, reservation):
                raise InvalidReservationError
            if self._evict_completed_entries:
                self._make_response_room(response.size_bytes, now)
            else:
                projected_bytes = (
                    self._cached_response_bytes
                    + self._reserved_response_bytes
                    - entry.reserved_response_bytes
                    + response.size_bytes
                )
                if projected_bytes > self._max_total_response_bytes:  # defensive invariant
                    raise self._capacity_error(now)
                self._reserved_response_bytes -= entry.reserved_response_bytes
                entry.reserved_response_bytes = 0
            entry.state = _EntryState.COMPLETE
            entry.response = response
            entry.expires_at = now + self._ttl_seconds
            self._cached_response_bytes += response.size_bytes
            self._entries.move_to_end(cache_key)

    def abort(self, reservation: IdempotencyReservation) -> bool:
        """Release owned in-flight work; safe to call after expiry or cleanup."""
        if not isinstance(reservation, IdempotencyReservation):
            raise TypeError("reservation must be an IdempotencyReservation")
        cache_key = (reservation.tenant_id, reservation._key_digest)
        with self._lock:
            now = _now(self._clock)
            self._expire(now)
            entry = self._entries.get(cache_key)
            if not self._owns(entry, reservation):
                return False
            self._remove(cache_key)
            return True

    def __len__(self) -> int:
        with self._lock:
            self._expire(_now(self._clock))
            return len(self._entries)

    @property
    def cached_response_bytes(self) -> int:
        """Exact encoded body/header bytes currently retained for replay."""
        with self._lock:
            self._expire(_now(self._clock))
            return self._cached_response_bytes

    @staticmethod
    def _owns(
        entry: _IdempotencyEntry | None, reservation: IdempotencyReservation
    ) -> bool:
        return bool(
            entry is not None
            and entry.state is _EntryState.RESERVED
            and hmac.compare_digest(entry.token, reservation._token)
            and entry.fingerprint == reservation._fingerprint
        )

    def _expire(self, now: float) -> None:
        expired = [key for key, entry in self._entries.items() if entry.expires_at <= now]
        for key in expired:
            self._remove(key)

    def _make_room(self, now: float) -> None:
        if len(self._entries) < self._max_entries:
            return
        if self._evict_completed_entries:
            completed_key = self._oldest_completed_key()
            if completed_key is not None:
                self._remove(completed_key)
                return
        raise self._capacity_error(now)

    def _make_response_room(self, required_bytes: int, now: float) -> None:
        while self._cached_response_bytes + required_bytes > self._max_total_response_bytes:
            if not self._evict_completed_entries:
                raise self._capacity_error(now)
            completed_key = self._oldest_completed_key()
            if completed_key is None:
                raise self._capacity_error(now)
            self._remove(completed_key)

    def _oldest_completed_key(self) -> tuple[str, bytes] | None:
        return next(
            (
                key
                for key, entry in self._entries.items()
                if entry.state is _EntryState.COMPLETE
            ),
            None,
        )

    def _remove(self, key: tuple[str, bytes]) -> None:
        entry = self._entries.pop(key)
        self._reserved_response_bytes -= entry.reserved_response_bytes
        if self._reserved_response_bytes < 0:  # defensive invariant
            raise RuntimeError("idempotency response reservation accounting underflow")
        if entry.response is not None:
            self._cached_response_bytes -= entry.response.size_bytes
            if self._cached_response_bytes < 0:  # defensive invariant
                raise RuntimeError("idempotency response-byte accounting underflow")

    def _capacity_error(self, now: float) -> IdempotencyCapacityError:
        retry_after = min(
            (max(0.0, entry.expires_at - now) for entry in self._entries.values()),
            default=self._reservation_ttl_seconds,
        )
        return IdempotencyCapacityError(retry_after_seconds=retry_after)


@dataclass(frozen=True, slots=True)
class AccessGrant:
    """An authenticated tenant and the quota charged for this request."""

    tenant: TenantIdentity
    quota: QuotaReceipt


class AccessController:
    """Convenience facade joining authentication, quota, and idempotency state."""

    def __init__(
        self,
        tenants: Iterable[TenantConfig],
        *,
        clock: Clock = time.monotonic,
        idempotency_ttl_seconds: float = DEFAULT_IDEMPOTENCY_TTL_SECONDS,
        reservation_ttl_seconds: float = DEFAULT_RESERVATION_TTL_SECONDS,
        max_idempotency_entries: int = DEFAULT_MAX_IDEMPOTENCY_ENTRIES,
        max_idempotency_response_bytes: int = DEFAULT_MAX_IDEMPOTENCY_RESPONSE_BYTES,
        max_idempotency_total_response_bytes: int = (
            DEFAULT_MAX_IDEMPOTENCY_TOTAL_RESPONSE_BYTES
        ),
        evict_completed_idempotency_entries: bool = True,
    ) -> None:
        configs = tuple(tenants)
        self.authenticator = ApiKeyAuthenticator(configs)
        policies = {config.tenant_id: config.quota for config in configs}
        self.quotas = TokenBucketLimiter(policies, clock=clock)
        self.idempotency = IdempotencyStore(
            ttl_seconds=idempotency_ttl_seconds,
            reservation_ttl_seconds=reservation_ttl_seconds,
            max_entries=max_idempotency_entries,
            max_response_bytes=max_idempotency_response_bytes,
            max_total_response_bytes=max_idempotency_total_response_bytes,
            evict_completed_entries=evict_completed_idempotency_entries,
            clock=clock,
        )
        self._tenant_ids = frozenset(policies)

    def authenticate(self, api_key: str | bytes | None) -> TenantIdentity:
        return self.authenticator.authenticate(api_key)

    def authorize(self, api_key: str | bytes | None, *, cost: float = 1.0) -> AccessGrant:
        tenant = self.authenticate(api_key)
        quota = self.quotas.consume(tenant.tenant_id, cost=cost)
        return AccessGrant(tenant=tenant, quota=quota)

    def reserve_idempotency(
        self,
        tenant: TenantIdentity | str,
        key: str,
        fingerprint: str,
    ) -> IdempotencyDecision:
        tenant_id = tenant.tenant_id if isinstance(tenant, TenantIdentity) else tenant
        if tenant_id not in self._tenant_ids:
            raise ValueError("tenant is not configured")
        return self.idempotency.reserve(tenant_id, key, fingerprint)


__all__ = [
    "AccessController",
    "AccessError",
    "AccessGrant",
    "ApiKeyAuthenticator",
    "AuthenticationError",
    "DEFAULT_MAX_IDEMPOTENCY_TOTAL_RESPONSE_BYTES",
    "IdempotencyCapacityError",
    "IdempotencyConflictError",
    "IdempotencyDecision",
    "IdempotencyInProgressError",
    "IdempotencyOutcome",
    "IdempotencyReservation",
    "IdempotencyResponse",
    "IdempotencyResponseTooLargeError",
    "IdempotencyStore",
    "InvalidIdempotencyInputError",
    "InvalidReservationError",
    "MAX_QUOTA_CAPACITY",
    "MAX_QUOTA_REFILL_TOKENS_PER_SECOND",
    "QuotaExceededError",
    "QuotaPolicy",
    "QuotaReceipt",
    "TenantConfig",
    "TenantIdentity",
    "TokenBucketLimiter",
    "fingerprint_request",
    "hash_api_key",
]
