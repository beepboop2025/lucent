"""Deployment configuration and process-local hosted-service dependencies."""

from __future__ import annotations

import json
import math
import os
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .access import (
    AccessController,
    IdempotencyStore,
    QuotaPolicy,
    TenantConfig,
)
from .payments import PaymentConfig, PaymentGateway
from .verified_source import (
    VerifiedSourceError,
    VerifiedSourceResult,
    resolve_verified_source,
)

MAX_TENANT_CONFIG_BYTES = 64 * 1024
MAX_TENANTS = 256
MAX_SOURCE_CACHE_ENTRIES = 64
MAX_SOURCE_CACHE_BYTES = 16 * 1024 * 1024
MIN_SOURCE_CACHE_TTL_SECONDS = 1.0
MAX_SOURCE_CACHE_TTL_SECONDS = 60.0
SOURCE_NEGATIVE_CACHE_TTL_SECONDS = 2.0
PROTECTED_RESERVATION_TTL_SECONDS = 120.0
# Signing decisions are time-sensitive because proxy implementations can
# change. Five minutes is long enough for network retries without turning an
# idempotency replay into a day-old provenance cache.
PROTECTED_RESULT_TTL_SECONDS = 5 * 60.0
MAX_CACHED_RESULT_BYTES = 2 * 1024 * 1024
MAX_RESULT_CACHE_ENTRIES = 512
MAX_RESULT_CACHE_BYTES = 32 * 1024 * 1024
PAYMENT_CLAIM_TTL_SECONDS = 15 * 60.0
MAX_PAYMENT_CLAIM_ENTRIES = 4_096
MAX_PAYMENT_CLAIM_CACHE_BYTES = 4 * 1024 * 1024


class AccessMode(StrEnum):
    DISABLED = "disabled"
    OPEN = "open"
    API_KEY = "api_key"
    X402 = "x402"
    API_KEY_OR_X402 = "api_key_or_x402"

    @property
    def uses_api_keys(self) -> bool:
        return self in {self.API_KEY, self.API_KEY_OR_X402}

    @property
    def uses_x402(self) -> bool:
        return self in {self.X402, self.API_KEY_OR_X402}


class VerifiedSourceMode(StrEnum):
    OFF = "off"
    REQUIRED = "required"


def _finite_float(value: str, *, setting: str, minimum: float, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{setting} must be numeric") from exc
    if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
        raise ValueError(f"{setting} must be between {minimum:g} and {maximum:g}")
    return parsed


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _parse_tenants(raw: str | None) -> tuple[TenantConfig, ...]:
    if raw is None or raw == "":
        return ()
    if len(raw.encode("utf-8")) > MAX_TENANT_CONFIG_BYTES:
        raise ValueError("LUCENT_TENANTS_JSON exceeds its 64 KiB limit")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_json_object)
    except (json.JSONDecodeError, UnicodeError, RecursionError, ValueError) as exc:
        raise ValueError("LUCENT_TENANTS_JSON must be valid bounded JSON") from exc
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_TENANTS:
        raise ValueError("LUCENT_TENANTS_JSON must contain 1 to 256 tenants")

    configs: list[TenantConfig] = []
    allowed = {
        "tenant_id",
        "api_key_hash",
        "capacity",
        "refill_tokens_per_second",
        "enabled",
    }
    for item in value:
        if not isinstance(item, dict) or set(item) - allowed:
            raise ValueError("tenant configuration contains unsupported fields")
        if "api_key" in item:
            raise ValueError("tenant configuration must contain hashes, never plaintext keys")
        capacity = item.get("capacity", 60)
        refill = item.get("refill_tokens_per_second", 1.0)
        enabled = item.get("enabled", True)
        try:
            configs.append(
                TenantConfig(
                    tenant_id=item.get("tenant_id"),
                    api_key_hash=item.get("api_key_hash"),
                    quota=QuotaPolicy(
                        capacity=capacity,
                        refill_tokens_per_second=refill,
                    ),
                    enabled=enabled,
                )
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("tenant configuration is invalid") from exc
    return tuple(configs)


@dataclass(frozen=True, slots=True)
class HostedSettings:
    access_mode: AccessMode
    verified_source_mode: VerifiedSourceMode
    source_cache_ttl_seconds: float
    tenants: tuple[TenantConfig, ...]
    payment: PaymentConfig

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> HostedSettings:
        env = os.environ if environ is None else environ
        try:
            access_mode = AccessMode(env.get("LUCENT_ACCESS_MODE", AccessMode.DISABLED))
        except ValueError as exc:
            raise ValueError("LUCENT_ACCESS_MODE is invalid") from exc
        try:
            source_mode = VerifiedSourceMode(
                env.get("LUCENT_VERIFIED_SOURCE_MODE", VerifiedSourceMode.OFF)
            )
        except ValueError as exc:
            raise ValueError("LUCENT_VERIFIED_SOURCE_MODE is invalid") from exc

        cache_ttl = _finite_float(
            env.get("LUCENT_VERIFIED_SOURCE_CACHE_TTL", "15"),
            setting="LUCENT_VERIFIED_SOURCE_CACHE_TTL",
            minimum=MIN_SOURCE_CACHE_TTL_SECONDS,
            maximum=MAX_SOURCE_CACHE_TTL_SECONDS,
        )
        tenants = _parse_tenants(env.get("LUCENT_TENANTS_JSON"))
        payment = PaymentConfig.from_env(env)

        if access_mode.uses_api_keys and not tenants:
            raise ValueError("API-key access requires LUCENT_TENANTS_JSON")
        if not access_mode.uses_api_keys and tenants:
            raise ValueError("tenant keys were configured but API-key access is disabled")
        if access_mode.uses_x402 and not payment.enabled:
            raise ValueError("x402 access requires LUCENT_X402_ENABLED=true")
        if not access_mode.uses_x402 and payment.enabled:
            raise ValueError("x402 was enabled but the selected access mode does not use it")
        if access_mode.uses_x402 and source_mode is not VerifiedSourceMode.REQUIRED:
            raise ValueError("monetized access requires verified source mode")
        if (
            source_mode is VerifiedSourceMode.REQUIRED
            and access_mode in {AccessMode.DISABLED, AccessMode.OPEN}
        ):
            raise ValueError("verified source mode requires protected API-key or x402 access")

        return cls(
            access_mode=access_mode,
            verified_source_mode=source_mode,
            source_cache_ttl_seconds=cache_ttl,
            tenants=tenants,
            payment=payment,
        )


@dataclass(slots=True)
class _SourceCacheEntry:
    result: VerifiedSourceResult
    expires_at: float
    size_bytes: int


@dataclass(frozen=True, slots=True)
class _SourceFailureEntry:
    code: str
    message: str
    expires_at: float


class VerifiedSourceCache:
    """Byte-bounded, single-flight cache with a short failure backoff."""

    def __init__(
        self,
        resolver: Callable[[int, str], VerifiedSourceResult] = resolve_verified_source,
        *,
        ttl_seconds: float = 15.0,
        max_entries: int = MAX_SOURCE_CACHE_ENTRIES,
        max_bytes: int = MAX_SOURCE_CACHE_BYTES,
        negative_ttl_seconds: float = SOURCE_NEGATIVE_CACHE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not callable(resolver) or not callable(clock):
            raise TypeError("resolver and clock must be callable")
        if not MIN_SOURCE_CACHE_TTL_SECONDS <= ttl_seconds <= MAX_SOURCE_CACHE_TTL_SECONDS:
            raise ValueError("source cache TTL is outside its safe range")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("source cache entry limit must be positive")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
            raise ValueError("source cache byte limit must be positive")
        if not 0 <= negative_ttl_seconds <= SOURCE_NEGATIVE_CACHE_TTL_SECONDS:
            raise ValueError("source failure cache TTL is outside its safe range")
        self._resolver = resolver
        self._ttl_seconds = float(ttl_seconds)
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._negative_ttl_seconds = float(negative_ttl_seconds)
        self._clock = clock
        self._entries: OrderedDict[tuple[int, str], _SourceCacheEntry] = OrderedDict()
        self._failures: OrderedDict[
            tuple[int, str], _SourceFailureEntry
        ] = OrderedDict()
        self._inflight: set[tuple[int, str]] = set()
        self._cached_bytes = 0
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)

    @property
    def cached_bytes(self) -> int:
        with self._lock:
            return self._cached_bytes

    def _expire_locked(self, now: float) -> None:
        for key, entry in list(self._entries.items()):
            if entry.expires_at <= now:
                self._cached_bytes -= entry.size_bytes
                del self._entries[key]
        for key, entry in list(self._failures.items()):
            if entry.expires_at <= now:
                del self._failures[key]

    def _store_success_locked(
        self,
        key: tuple[int, str],
        result: VerifiedSourceResult,
        now: float,
    ) -> None:
        size_bytes = result.cache_size_bytes
        if size_bytes > self._max_bytes:
            return
        replaced = self._entries.pop(key, None)
        if replaced is not None:
            self._cached_bytes -= replaced.size_bytes
        while self._entries and (
            len(self._entries) >= self._max_entries
            or self._cached_bytes + size_bytes > self._max_bytes
        ):
            _, evicted = self._entries.popitem(last=False)
            self._cached_bytes -= evicted.size_bytes
        self._entries[key] = _SourceCacheEntry(
            result=result,
            expires_at=now + self._ttl_seconds,
            size_bytes=size_bytes,
        )
        self._cached_bytes += size_bytes

    def resolve(self, chain_id: int, address: str) -> VerifiedSourceResult:
        key = (chain_id, address.lower())
        with self._condition:
            while True:
                now = self._clock()
                self._expire_locked(now)
                entry = self._entries.get(key)
                if entry is not None:
                    self._entries.move_to_end(key)
                    return entry.result
                failure = self._failures.get(key)
                if failure is not None:
                    self._failures.move_to_end(key)
                    raise VerifiedSourceError(failure.code, failure.message)
                if key not in self._inflight:
                    if len(self._inflight) >= self._max_entries:
                        raise VerifiedSourceError(
                            "SOURCE_CACHE_CAPACITY",
                            "verified-source concurrency capacity was exhausted",
                        )
                    self._inflight.add(key)
                    break
                self._condition.wait()

        try:
            result = self._resolver(chain_id, address)
            if not isinstance(result, VerifiedSourceResult):
                raise TypeError("verified source resolver returned an invalid result")
        except VerifiedSourceError as exc:
            with self._condition:
                if self._negative_ttl_seconds:
                    self._failures[key] = _SourceFailureEntry(
                        code=exc.code,
                        message=exc.message,
                        expires_at=self._clock() + self._negative_ttl_seconds,
                    )
                    self._failures.move_to_end(key)
                    while len(self._failures) > self._max_entries:
                        self._failures.popitem(last=False)
                self._inflight.discard(key)
                self._condition.notify_all()
            raise
        except Exception:
            with self._condition:
                self._inflight.discard(key)
                self._condition.notify_all()
            raise

        with self._condition:
            self._store_success_locked(key, result, self._clock())
            self._inflight.discard(key)
            self._condition.notify_all()
        return result


@dataclass(slots=True)
class HostedRuntime:
    settings: HostedSettings
    access: AccessController | None
    payments: PaymentGateway | None
    payment_idempotency: IdempotencyStore | None
    payment_claims: IdempotencyStore | None
    verified_sources: VerifiedSourceCache | None

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        source_resolver: Callable[[int, str], VerifiedSourceResult] = resolve_verified_source,
        payment_gateway: PaymentGateway | None = None,
    ) -> HostedRuntime:
        settings = HostedSettings.from_env(environ)
        access = None
        if settings.access_mode.uses_api_keys:
            access = AccessController(
                settings.tenants,
                idempotency_ttl_seconds=PROTECTED_RESULT_TTL_SECONDS,
                reservation_ttl_seconds=PROTECTED_RESERVATION_TTL_SECONDS,
                max_idempotency_entries=MAX_RESULT_CACHE_ENTRIES,
                max_idempotency_response_bytes=MAX_CACHED_RESULT_BYTES,
                max_idempotency_total_response_bytes=MAX_RESULT_CACHE_BYTES,
            )
        payments = None
        payment_idempotency = None
        payment_claims = None
        if settings.access_mode.uses_x402:
            payments = payment_gateway or PaymentGateway(settings.payment)
            payment_idempotency = IdempotencyStore(
                ttl_seconds=PAYMENT_CLAIM_TTL_SECONDS,
                reservation_ttl_seconds=PROTECTED_RESERVATION_TTL_SECONDS,
                max_entries=MAX_RESULT_CACHE_ENTRIES,
                max_response_bytes=MAX_CACHED_RESULT_BYTES,
                max_total_response_bytes=MAX_RESULT_CACHE_BYTES,
                evict_completed_entries=False,
            )
            payment_claims = IdempotencyStore(
                ttl_seconds=PAYMENT_CLAIM_TTL_SECONDS,
                reservation_ttl_seconds=PROTECTED_RESERVATION_TTL_SECONDS,
                max_entries=MAX_PAYMENT_CLAIM_ENTRIES,
                max_response_bytes=1_024,
                max_total_response_bytes=MAX_PAYMENT_CLAIM_CACHE_BYTES,
                evict_completed_entries=False,
            )
        verified_sources = None
        if settings.verified_source_mode is VerifiedSourceMode.REQUIRED:
            verified_sources = VerifiedSourceCache(
                source_resolver,
                ttl_seconds=settings.source_cache_ttl_seconds,
            )
        return cls(
            settings=settings,
            access=access,
            payments=payments,
            payment_idempotency=payment_idempotency,
            payment_claims=payment_claims,
            verified_sources=verified_sources,
        )

    def readiness(self) -> dict[str, Any]:
        return {
            "access_mode": self.settings.access_mode.value,
            "verified_source_mode": self.settings.verified_source_mode.value,
            "x402_enabled": bool(self.payments and self.payments.enabled),
            "api_key_tenants": len(self.settings.tenants),
            "state_backend": "process_local",
        }


__all__ = [
    "AccessMode",
    "HostedRuntime",
    "HostedSettings",
    "MAX_CACHED_RESULT_BYTES",
    "VerifiedSourceCache",
    "VerifiedSourceMode",
]
