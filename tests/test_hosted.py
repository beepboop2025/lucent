"""Hosted deployment-mode composition and source-cache semantics."""

from __future__ import annotations

import json

import pytest

from lucent import hosted
from lucent.access import hash_api_key
from lucent.payments import PaymentConfig
from lucent.verified_source import (
    BlockIdentity,
    CodeIdentity,
    VerifiedSourceError,
    VerifiedSourceResult,
)

PAYEE = "0x" + "11" * 20
TARGET = "0x" + "22" * 20
TX_HASH = "0x" + "aa" * 32


def _tenant_json():
    return json.dumps([{
        "tenant_id": "wallet-co",
        "api_key_hash": hash_api_key("secret"),
        "capacity": 5,
        "refill_tokens_per_second": 0.5,
    }])


def _payment_env():
    return {
        "LUCENT_X402_ENABLED": "true",
        "LUCENT_X402_PAY_TO": PAYEE,
        "LUCENT_X402_RESOURCE_URL": "https://api.lucent.example/v1/preflight",
        "LUCENT_X402_FACILITATOR_URL": "https://api.cdp.coinbase.com/platform/v2/x402",
    }


def _source_result(address=TARGET):
    abi = json.dumps([], separators=(",", ":")).encode()
    code = CodeIdentity(address=address, keccak256="0x" + "33" * 32, size_bytes=5)
    return VerifiedSourceResult(
        chain_id=1,
        address=address,
        block=BlockIdentity(number=123, hash="0x" + "44" * 32),
        target=code,
        effective_contract=code,
        proxy_chain=(),
        verification_match="exact_match",
        abi_hash="sha256:" + __import__("hashlib").sha256(abi).hexdigest(),
        _abi_json=abi,
    )


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


class FakeGateway:
    enabled = True


def test_hosted_runtime_is_closed_by_default():
    settings = hosted.HostedSettings.from_env({})
    assert settings.access_mode is hosted.AccessMode.DISABLED
    assert settings.verified_source_mode is hosted.VerifiedSourceMode.OFF
    assert settings.payment.enabled is False
    runtime = hosted.HostedRuntime.from_env({})
    assert runtime.access is None
    assert runtime.payments is None
    assert runtime.verified_sources is None


def test_open_mode_requires_explicit_local_development_opt_in():
    settings = hosted.HostedSettings.from_env({"LUCENT_ACCESS_MODE": "open"})
    assert settings.access_mode is hosted.AccessMode.OPEN


def test_api_key_mode_loads_only_hashed_tenant_configuration():
    runtime = hosted.HostedRuntime.from_env({
        "LUCENT_ACCESS_MODE": "api_key",
        "LUCENT_TENANTS_JSON": _tenant_json(),
        "LUCENT_VERIFIED_SOURCE_MODE": "required",
    }, source_resolver=lambda chain, address: _source_result(address))
    assert runtime.access is not None
    assert runtime.access.authenticate("secret").tenant_id == "wallet-co"
    assert runtime.readiness() == {
        "access_mode": "api_key",
        "verified_source_mode": "required",
        "x402_enabled": False,
        "api_key_tenants": 1,
        "state_backend": "process_local",
    }


def test_x402_mode_requires_verified_source_and_builds_separate_idempotency():
    env = {
        **_payment_env(),
        "LUCENT_ACCESS_MODE": "x402",
        "LUCENT_VERIFIED_SOURCE_MODE": "required",
    }
    runtime = hosted.HostedRuntime.from_env(
        env,
        source_resolver=lambda chain, address: _source_result(address),
        payment_gateway=FakeGateway(),
    )
    assert runtime.access is None
    assert runtime.payments is not None
    assert runtime.payment_idempotency is not None
    assert runtime.payment_claims is not None
    assert runtime.verified_sources is not None


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"LUCENT_ACCESS_MODE": "unknown"}, "ACCESS_MODE"),
        ({"LUCENT_VERIFIED_SOURCE_MODE": "optional"}, "SOURCE_MODE"),
        ({"LUCENT_VERIFIED_SOURCE_CACHE_TTL": "0"}, "CACHE_TTL"),
        ({"LUCENT_ACCESS_MODE": "api_key"}, "TENANTS_JSON"),
        ({"LUCENT_TENANTS_JSON": _tenant_json()}, "API-key access is disabled"),
        ({"LUCENT_ACCESS_MODE": "x402"}, "X402_ENABLED"),
        ({**_payment_env()}, "does not use it"),
        ({**_payment_env(), "LUCENT_ACCESS_MODE": "x402"}, "verified source"),
        (
            {"LUCENT_VERIFIED_SOURCE_MODE": "required"},
            "protected API-key or x402 access",
        ),
    ],
)
def test_incoherent_deployment_modes_fail_at_startup(env, message):
    with pytest.raises(ValueError, match=message):
        hosted.HostedSettings.from_env(env)


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        json.dumps({"tenant_id": "one"}),
        json.dumps([{"tenant_id": "one", "api_key": "plaintext"}]),
        json.dumps([{"tenant_id": "one", "api_key_hash": "bad"}]),
        json.dumps([{
            "tenant_id": "one",
            "api_key_hash": hash_api_key("key"),
            "extra": True,
        }]),
        (
            '[{"tenant_id":"one","tenant_id":"two","api_key_hash":"'
            + hash_api_key("key")
            + '"}]'
        ),
    ],
)
def test_tenant_configuration_is_strict_and_never_accepts_plaintext(raw):
    with pytest.raises(ValueError):
        hosted.HostedSettings.from_env({
            "LUCENT_ACCESS_MODE": "api_key",
            "LUCENT_TENANTS_JSON": raw,
        })


def test_source_cache_reuses_success_only_until_the_short_ttl():
    clock = FakeClock()
    calls = []

    def resolve(chain, address):
        calls.append((chain, address))
        return _source_result(address)

    cache = hosted.VerifiedSourceCache(resolve, ttl_seconds=10, clock=clock)
    first = cache.resolve(1, TARGET)
    assert cache.resolve(1, TARGET.upper().replace("0X", "0x")) is first
    assert len(calls) == 1
    clock.value = 10
    assert cache.resolve(1, TARGET) is not first
    assert len(calls) == 2


def test_source_cache_cannot_disable_singleflight_with_a_zero_ttl():
    with pytest.raises(ValueError, match="TTL"):
        hosted.VerifiedSourceCache(
            lambda _chain, address: _source_result(address),
            ttl_seconds=0,
        )


def test_source_failures_receive_only_a_short_backoff_cache():
    clock = FakeClock()
    calls = 0

    def fail(_chain, _address):
        nonlocal calls
        calls += 1
        raise VerifiedSourceError("SOURCE_NOT_VERIFIED", "not verified")

    cache = hosted.VerifiedSourceCache(fail, clock=clock)
    for _ in range(2):
        with pytest.raises(VerifiedSourceError):
            cache.resolve(1, TARGET)
    assert calls == 1
    clock.value = hosted.SOURCE_NEGATIVE_CACHE_TTL_SECONDS
    with pytest.raises(VerifiedSourceError):
        cache.resolve(1, TARGET)
    assert calls == 2


def test_source_cache_coalesces_concurrent_misses():
    import concurrent.futures
    import threading

    calls = 0
    release = threading.Event()

    def resolve(_chain, address):
        nonlocal calls
        calls += 1
        release.wait(timeout=2)
        return _source_result(address)

    cache = hosted.VerifiedSourceCache(resolve)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(cache.resolve, 1, TARGET) for _ in range(8)]
        release.set()
        results = [future.result(timeout=2) for future in futures]
    assert calls == 1
    assert all(item is results[0] for item in results)


def test_source_cache_enforces_an_aggregate_byte_budget():
    result = _source_result()
    cache = hosted.VerifiedSourceCache(
        lambda _chain, _address: result,
        max_bytes=result.cache_size_bytes,
    )
    cache.resolve(1, TARGET)
    cache.resolve(1, "0x" + "77" * 20)
    assert cache.cached_bytes == result.cache_size_bytes


def test_source_cache_rejects_invalid_results_and_does_not_store_them():
    cache = hosted.VerifiedSourceCache(lambda _chain, _address: object())
    with pytest.raises(TypeError, match="invalid result"):
        cache.resolve(1, TARGET)


def test_hosted_settings_retains_official_base_payment_config():
    config = PaymentConfig.from_env(_payment_env())
    assert config.network == "eip155:8453"
