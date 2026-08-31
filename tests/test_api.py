"""Hosted API contract, failure semantics, limits, and security headers."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from eth_abi import encode as abi_encode
from fastapi.testclient import TestClient
from x402 import PaymentPayload
from x402.extensions.payment_identifier import (
    PAYMENT_IDENTIFIER,
    append_payment_identifier_to_extensions,
    declare_payment_identifier_extension,
)
from x402.http.utils import (
    decode_payment_required_header,
    decode_payment_response_header,
    encode_payment_signature_header,
)
from x402.schemas import ResourceInfo, SettleResponse, VerifyResponse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lucent import hosted, payments, preflight, verified_source  # noqa: E402
from lucent.access import hash_api_key  # noqa: E402
from lucent.api import MAX_BODY_BYTES, app  # noqa: E402

CLIENT = TestClient(app)
app.state.runtime = hosted.HostedRuntime.from_env({"LUCENT_ACCESS_MODE": "open"})
ADDRESS = "0x" + "11" * 20
RECIPIENT = "0x" + "22" * 20
SENDER = "0x" + "aa" * 20
PAYMENT_NOW = 2_000_000_000


def _function(name, inputs, *, mutability="nonpayable"):
    return {
        "type": "function",
        "name": name,
        "stateMutability": mutability,
        "inputs": [{"name": item_name, "type": item_type} for item_name, item_type in inputs],
    }


TRANSFER = _function("transfer", [("to", "address"), ("amount", "uint256")])
DEPOSIT = _function("deposit", [], mutability="payable")


class FakeFacilitator:
    def __init__(self):
        self.verify_calls = 0
        self.settle_calls = 0
        self.settlement_network = None
        self.cancel_next_settlement = False

    async def verify(self, _payload, _requirements):
        self.verify_calls += 1
        return VerifyResponse(isValid=True, payer=SENDER)

    async def settle(self, _payload, requirements):
        self.settle_calls += 1
        if self.cancel_next_settlement:
            self.cancel_next_settlement = False
            raise asyncio.CancelledError
        return SettleResponse(
            success=True,
            payer=SENDER,
            transaction="0x" + "ab" * 32,
            network=self.settlement_network or requirements.network,
            amount=requirements.amount,
        )


def _payload(function=TRANSFER, *, value="0x0", formats=None, values=None):
    signature = preflight.common.signature(function)
    types = [preflight.common.canonical_type(item) for item in function["inputs"]]
    if values is None:
        values = [RECIPIENT, 42] if function is TRANSFER else []
    calldata = preflight.common.selector(signature)
    if types:
        calldata += abi_encode(types, values).hex()
    if formats is None:
        formats = {
            "transfer(address,uint256)": {
                "intent": "Send tokens",
                "interpolatedIntent": "Send {amount} to {to}",
                "fields": [
                    {"path": "#.to", "label": "To", "format": "addressName"},
                    {"path": "#.amount", "label": "Amount", "format": "amount"},
                ],
            }
        }
    return {
        "transaction": {
            "chain_id": 1,
            "from": SENDER,
            "to": ADDRESS,
            "data": calldata,
            "value": value,
        },
        "descriptor": {
            "context": {"contract": {
                "abi": [function],
                "deployments": [{"chainId": 1, "address": ADDRESS}],
            }},
            "display": {"formats": formats},
        },
    }


def _verified_source_result(abi=None, *, block_number=123, proxy=False):
    selected_abi = abi or [TRANSFER]
    abi_json = json.dumps(
        selected_abi,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    target = verified_source.CodeIdentity(
        address=ADDRESS,
        keccak256="0x" + "33" * 32,
        size_bytes=5,
    )
    effective = target
    proxy_chain = ()
    if proxy:
        effective = verified_source.CodeIdentity(
            address="0x" + "77" * 20,
            keccak256="0x" + "88" * 32,
            size_bytes=7,
        )
        proxy_chain = (
            verified_source.ProxyHop(
                proxy=target,
                kind="eip1967_implementation",
                implementation_address=effective.address,
            ),
        )
    return verified_source.VerifiedSourceResult(
        chain_id=1,
        address=ADDRESS,
        block=verified_source.BlockIdentity(
            number=block_number,
            hash=(
                "0x" + "44" * 32
                if block_number == 123
                else "0x" + f"{block_number % 256:02x}" * 32
            ),
        ),
        target=target,
        effective_contract=effective,
        proxy_chain=proxy_chain,
        verification_match="exact_match",
        abi_hash="sha256:" + hashlib.sha256(abi_json).hexdigest(),
        _abi_json=abi_json,
    )


def _tenant_env(*, capacity=2):
    tenants = [{
        "tenant_id": "wallet-co",
        "api_key_hash": hash_api_key("lucent-live-key"),
        "capacity": capacity,
        "refill_tokens_per_second": 0.001,
    }]
    return {
        "LUCENT_ACCESS_MODE": "api_key",
        "LUCENT_TENANTS_JSON": json.dumps(tenants),
    }


def _paid_runtime(*, resolver=None):
    env = {
        "LUCENT_ACCESS_MODE": "x402",
        "LUCENT_VERIFIED_SOURCE_MODE": "required",
        "LUCENT_X402_ENABLED": "true",
        "LUCENT_X402_PAY_TO": "0x" + "55" * 20,
        "LUCENT_X402_RESOURCE_URL": "https://api.lucent.example/v1/preflight",
        "LUCENT_X402_FACILITATOR_URL": (
            "https://api.cdp.coinbase.com/platform/v2/x402"
        ),
    }
    facilitator = FakeFacilitator()
    config = payments.PaymentConfig.from_env(env)
    gateway = payments.PaymentGateway(
        config,
        facilitator,
        clock=lambda: PAYMENT_NOW,
    )
    runtime = hosted.HostedRuntime.from_env(
        env,
        source_resolver=resolver or (lambda _chain, _address: _verified_source_result()),
        payment_gateway=gateway,
    )
    return runtime, gateway, facilitator


def _source_runtime(resolver, *, capacity=8):
    return hosted.HostedRuntime.from_env(
        {
            **_tenant_env(capacity=capacity),
            "LUCENT_VERIFIED_SOURCE_MODE": "required",
        },
        source_resolver=resolver,
    )


def _api_headers(idempotency_key):
    return {
        "X-API-Key": "lucent-live-key",
        "Idempotency-Key": idempotency_key,
    }


def _payment_signature(gateway, payment_identifier):
    extensions = {
        PAYMENT_IDENTIFIER: declare_payment_identifier_extension(required=True),
    }
    append_payment_identifier_to_extensions(extensions, payment_identifier)
    payload = PaymentPayload(
        x402Version=2,
        payload={
            "signature": "0x" + "01" * 65,
            "authorization": {
                "from": SENDER,
                "to": gateway.config.pay_to,
                "value": gateway.config.amount,
                "validAfter": "0",
                "validBefore": str(PAYMENT_NOW + 300),
                "nonce": "0x" + "66" * 32,
            },
        },
        accepted=gateway._requirements,
        resource=ResourceInfo(url=gateway.config.resource_url),
        extensions=extensions,
    )
    return encode_payment_signature_header(payload)


def test_health_and_request_headers():
    response = CLIENT.get("/health", headers={"X-Request-ID": "wallet-42"})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["policy_version"] == preflight.POLICY_VERSION
    assert response.json()["identity_status"] == "local"
    assert response.json()["source_commit"] is None
    assert response.json()["release_id"] is None
    assert response.headers["x-request-id"] == "wallet-42"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    readiness = CLIENT.get("/ready").json()
    assert readiness["access_mode"] == "open"
    assert readiness["verified_source_mode"] == "off"
    assert readiness["state_backend"] == "process_local"
    assert readiness["identity_status"] == "local"


def test_real_app_registers_and_starts_operational_routes_without_model_inference(
    monkeypatch,
):
    monkeypatch.delenv("RAILWAY_ENVIRONMENT_NAME", raising=False)
    monkeypatch.delenv("FLEET_SOURCE_COMMIT", raising=False)
    monkeypatch.delenv("FLEET_RELEASE_ID", raising=False)
    routes = {
        route.path: route
        for route in app.routes
        if getattr(route, "path", None) in {"/health", "/ready"}
    }

    assert set(routes) == {"/health", "/ready"}
    assert all(route.response_model is None for route in routes.values())
    assert {"/health", "/ready"} <= set(app.openapi()["paths"])
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["identity_status"] == "local"


def test_railway_health_and_readiness_require_exact_fleet_identity(monkeypatch):
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.delenv("FLEET_SOURCE_COMMIT", raising=False)
    monkeypatch.delenv("FLEET_RELEASE_ID", raising=False)

    missing = CLIENT.get("/health")
    assert missing.status_code == 503
    assert missing.json()["identity_status"] == "invalid"
    assert missing.json()["source_commit"] is None
    assert missing.json()["release_id"] is None

    monkeypatch.setenv("FLEET_SOURCE_COMMIT", "a" * 40 + "\n")
    monkeypatch.setenv("FLEET_RELEASE_ID", "b" * 64)
    assert CLIENT.get("/ready").status_code == 503

    source_commit = "a" * 40
    release_id = "b" * 64
    monkeypatch.setenv("FLEET_SOURCE_COMMIT", source_commit)
    monkeypatch.setenv("FLEET_RELEASE_ID", release_id)
    for path in ("/health", "/ready"):
        response = CLIENT.get(path)
        assert response.status_code == 200
        assert response.json()["identity_status"] == "verified"
        assert response.json()["source_commit"] == source_commit
        assert response.json()["release_id"] == release_id


def test_default_runtime_is_closed_until_access_is_explicitly_configured(monkeypatch):
    runtime = hosted.HostedRuntime.from_env({})
    monkeypatch.setattr(app.state, "runtime", runtime)
    ready = CLIENT.get("/ready")
    assert ready.status_code == 503
    assert ready.json()["code"] == "SERVICE_NOT_CONFIGURED"
    preflight_response = CLIENT.post("/v1/preflight", json=_payload())
    assert preflight_response.status_code == 503
    assert preflight_response.json()["code"] == "SERVICE_NOT_CONFIGURED"


def test_preflight_returns_transaction_bound_result():
    response = CLIENT.post("/v1/preflight", json=_payload())
    assert response.status_code == 200
    body = response.json()
    assert body["assessment_fingerprint"].startswith("sha256:")
    assert body["verdict"]["gate"] == "safe_to_present"
    assert body["analysis_scope"] == "static_selected_call"
    assert body["call_fingerprint"].startswith("sha256:")
    assert body["request_id"] == response.headers["x-request-id"]
    assert body["assurance"]["bytecode_verified"] is False
    assert body["assurance"]["sender_bound"] is True
    assert body["call"]["from"] == SENDER


def test_block_is_an_assessment_not_an_http_error():
    payload = _payload(
        DEPOSIT,
        value="0x1",
        formats={"deposit()": {"intent": "Deposit", "fields": []}},
    )
    response = CLIENT.post("/v1/preflight", json=payload)
    assert response.status_code == 200
    assert response.json()["verdict"]["gate"] == "block"
    assert response.json()["verdict"]["code"] == "PRESENTATION_CRITICAL"


def test_deployment_mismatch_uses_stable_problem_code():
    payload = _payload()
    payload["transaction"]["to"] = "0x" + "44" * 20
    response = CLIENT.post("/v1/preflight", json=payload)
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == "DEPLOYMENT_MISMATCH"
    assert response.json()["request_id"] == response.headers["x-request-id"]


def test_malformed_json_is_400_and_worker_survives():
    response = CLIENT.post(
        "/v1/preflight", content=b"{not-json", headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 400
    assert response.json()["code"] == "MALFORMED_JSON"
    assert CLIENT.get("/health").status_code == 200


def test_unknown_fields_are_rejected():
    payload = _payload()
    payload["transaction"]["gas"] = "0x5208"
    response = CLIENT.post("/v1/preflight", json=payload)
    assert response.status_code == 422
    assert response.json()["code"] == "REQUEST_VALIDATION_FAILED"


def test_chain_id_is_not_coerced_from_a_string():
    payload = _payload()
    payload["transaction"]["chain_id"] = "1"
    response = CLIENT.post("/v1/preflight", json=payload)
    assert response.status_code == 422
    assert response.json()["code"] == "REQUEST_VALIDATION_FAILED"


def test_oversized_body_is_rejected_before_json_parsing():
    raw = b'{"descriptor":{"padding":"' + b"x" * MAX_BODY_BYTES + b'"}}'
    response = CLIENT.post(
        "/v1/preflight", content=raw, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413
    assert response.json()["code"] == "REQUEST_TOO_LARGE"
    assert response.json()["request_id"] == response.headers["x-request-id"]
    assert response.headers["cache-control"] == "no-store"


def test_chunked_oversized_body_is_a_stable_413():
    def chunks():
        yield b'{"padding":"'
        for _ in range((MAX_BODY_BYTES // 4096) + 2):
            yield b"x" * 4096
        yield b'"}'

    response = CLIENT.post(
        "/v1/preflight",
        content=chunks(),
        headers={"Content-Type": "application/json", "Transfer-Encoding": "chunked"},
    )
    assert response.status_code == 413
    assert response.json()["code"] == "REQUEST_TOO_LARGE"


def test_pathological_json_is_a_stable_400_and_worker_recovers():
    bodies = [
        b'{"transaction":' + b"[" * 10_000 + b"0" + b"]" * 10_000 + b"}",
        b'{"transaction":' + b"9" * 10_000 + b"}",
    ]
    for raw in bodies:
        response = CLIENT.post(
            "/v1/preflight",
            content=raw,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400
        assert response.json()["code"] == "MALFORMED_JSON"
    assert CLIENT.get("/health").status_code == 200


def test_http_json_preserves_large_solidity_integers_exactly():
    amount = (1 << 53) + 1
    response = CLIENT.post(
        "/v1/preflight", json=_payload(values=[RECIPIENT, amount])
    )
    assert response.status_code == 200
    rendered = response.json()["call"]["decoded_arguments"][1]["value"]
    assert rendered == str(amount)
    assert isinstance(rendered, str)


def test_internal_errors_are_redacted(monkeypatch):
    def fail(_payload):
        raise RuntimeError("private RPC token and local path")

    monkeypatch.setattr(preflight, "preflight_transaction", fail)
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post("/v1/preflight", json=_payload())
    assert response.status_code == 500
    rendered = response.text
    assert "private RPC" not in rendered
    assert "local path" not in rendered
    assert response.json()["code"] == "INTERNAL_ERROR"


def test_openapi_exposes_only_versioned_product_routes():
    response = CLIENT.get("/openapi.json")
    assert response.status_code == 200
    paths = set(response.json()["paths"])
    assert {path for path in paths if path.startswith("/v1/")} == {"/v1/preflight"}
    assert all("simulate" not in path and "attest" not in path for path in paths)

    spec = response.json()
    operation = spec["paths"]["/v1/preflight"]["post"]
    success_schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert success_schema["$ref"].endswith("/PreflightResponse")
    preflight_schema = spec["components"]["schemas"]["PreflightResponse"]
    assert "assessment_fingerprint" in preflight_schema["required"]
    assert spec["components"]["schemas"]["Gate"]["enum"] == [
        "safe_to_present",
        "review",
        "block",
    ]
    for status in ("400", "401", "402", "409", "413", "422", "429", "500", "502", "503"):
        assert set(operation["responses"][status]["content"]) == {
            "application/problem+json"
        }
    assurance = spec["components"]["schemas"]["AssuranceResponse"]["properties"]
    assert assurance["verified_source"]["anyOf"][0]["$ref"].endswith(
        "/VerifiedSourceResponse"
    )


def test_every_openapi_internal_reference_resolves():
    spec = CLIENT.get("/openapi.json").json()

    def resolve(reference):
        assert reference.startswith("#/")
        current = spec
        for raw in reference[2:].split("/"):
            key = raw.replace("~1", "/").replace("~0", "~")
            current = current[key]
        return current

    pending = [spec]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if "$ref" in value:
                assert resolve(value["$ref"])
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)


def test_api_key_auth_quota_and_idempotent_replay(monkeypatch):
    runtime = hosted.HostedRuntime.from_env(_tenant_env(capacity=4))
    monkeypatch.setattr(app.state, "runtime", runtime)

    assert CLIENT.post("/v1/preflight", json=_payload()).status_code == 401
    missing_key = CLIENT.post(
        "/v1/preflight",
        json=_payload(),
        headers={"X-API-Key": "lucent-live-key"},
    )
    assert missing_key.status_code == 400
    assert missing_key.json()["code"] == "INVALID_IDEMPOTENCY_INPUT"

    headers = {
        "X-API-Key": "lucent-live-key",
        "Idempotency-Key": "wallet-request-1",
    }
    first = CLIENT.post("/v1/preflight", json=_payload(), headers=headers)
    assert first.status_code == 200
    assert first.headers["x-lucent-access"] == "api_key"
    assert first.headers["x-ratelimit-limit"] == "4"
    assert first.headers["x-ratelimit-remaining"] == "2"

    replay = CLIENT.post("/v1/preflight", json=_payload(), headers=headers)
    assert replay.status_code == 200
    assert replay.headers["idempotency-replayed"] == "true"
    assert replay.headers["x-ratelimit-remaining"] == "1"
    assert replay.json()["call_fingerprint"] == first.json()["call_fingerprint"]
    assert replay.json()["request_id"] != first.json()["request_id"]

    changed = CLIENT.post(
        "/v1/preflight",
        json=_payload(values=[RECIPIENT, 43]),
        headers=headers,
    )
    assert changed.status_code == 409
    assert changed.json()["code"] == "IDEMPOTENCY_CONFLICT"

    exhausted = CLIENT.post(
        "/v1/preflight",
        json=_payload(),
        headers={**headers, "Idempotency-Key": "wallet-request-2"},
    )
    assert exhausted.status_code == 429
    assert exhausted.json()["code"] == "QUOTA_EXCEEDED"
    assert exhausted.headers["retry-after"]


def test_required_source_replaces_caller_abi_and_returns_compact_provenance(monkeypatch):
    calls = []

    def resolve(chain_id, address):
        calls.append((chain_id, address))
        return _verified_source_result()

    runtime = _source_runtime(resolve)
    monkeypatch.setattr(app.state, "runtime", runtime)
    response = CLIENT.post(
        "/v1/preflight",
        json=_payload(),
        headers=_api_headers("source-request-1"),
    )
    assert response.status_code == 200
    assurance = response.json()["assurance"]
    assert assurance["bytecode_verified"] is True
    assert assurance["abi_source"] == "sourcify_v2_finalized_runtime"
    source = assurance["verified_source"]
    assert source["provider"] == "sourcify_v2"
    assert source["block"] == {"number": 123, "hash": "0x" + "44" * 32}
    assert source["target"]["keccak256"] == "0x" + "33" * 32
    assert source["abi_hash"].startswith("sha256:")
    assert "abi" not in source
    assert calls == [(1, ADDRESS)]

    # The short cache prevents duplicate upstream work for an immediate retry.
    second = CLIENT.post(
        "/v1/preflight",
        json=_payload(),
        headers=_api_headers("source-request-2"),
    )
    assert second.status_code == 200
    assert calls == [(1, ADDRESS)]


def test_malformed_local_input_never_reaches_verified_source(monkeypatch):
    calls = 0

    def resolve(_chain_id, _address):
        nonlocal calls
        calls += 1
        return _verified_source_result()

    runtime = _source_runtime(resolve)
    monkeypatch.setattr(app.state, "runtime", runtime)
    payload = _payload()
    payload["descriptor"]["context"]["contract"]["abi"] = "not-an-abi"
    response = CLIENT.post(
        "/v1/preflight",
        json=payload,
        headers=_api_headers("source-malformed-1"),
    )
    assert response.status_code == 422
    assert calls == 0


def test_verified_source_failures_keep_stable_http_semantics(monkeypatch):
    def unverified(_chain_id, _address):
        raise verified_source.VerifiedSourceError(
            "SOURCE_NOT_VERIFIED",
            "no verified runtime source was found",
        )

    runtime = _source_runtime(unverified)
    monkeypatch.setattr(app.state, "runtime", runtime)
    response = CLIENT.post(
        "/v1/preflight",
        json=_payload(),
        headers=_api_headers("source-unverified-1"),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "SOURCE_NOT_VERIFIED"


def test_verified_source_integrity_failures_are_upstream_errors(monkeypatch):
    for index, code in enumerate(
        ("SOURCE_IDENTITY_MISMATCH", "SOURCE_CODE_MISMATCH", "INVALID_VERIFIED_ABI")
    ):
        def invalid_source(_chain_id, _address, *, failure_code=code):
            raise verified_source.VerifiedSourceError(
                failure_code,
                "verified source evidence was internally inconsistent",
            )

        runtime = _source_runtime(invalid_source)
        monkeypatch.setattr(app.state, "runtime", runtime)
        response = CLIENT.post(
            "/v1/preflight",
            json=_payload(),
            headers=_api_headers(f"source-integrity-{index}"),
        )
        assert response.status_code == 503
        assert response.json()["code"] == code
        assert response.headers["retry-after"] == "2"

    runtime = _source_runtime(
        lambda _chain, _address: replace(
            _verified_source_result(),
            address="0x" + "99" * 20,
        )
    )
    monkeypatch.setattr(app.state, "runtime", runtime)
    mismatched = CLIENT.post(
        "/v1/preflight",
        json=_payload(),
        headers=_api_headers("source-integrity-result"),
    )
    assert mismatched.status_code == 503
    assert mismatched.json()["code"] == "SOURCE_IDENTITY_MISMATCH"


def test_proxy_backed_source_is_rejected_before_its_implementation_abi_is_used(monkeypatch):
    runtime = _source_runtime(
        lambda _chain, _address: _verified_source_result(proxy=True)
    )
    monkeypatch.setattr(app.state, "runtime", runtime)
    response = CLIENT.post(
        "/v1/preflight",
        json=_payload(),
        headers=_api_headers("source-proxy-1"),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "PROXY_SEMANTICS_UNVERIFIED"


def test_assessment_fingerprint_binds_source_evidence(monkeypatch):
    first_runtime = _source_runtime(
        lambda _chain, _address: _verified_source_result(block_number=123)
    )
    monkeypatch.setattr(app.state, "runtime", first_runtime)
    first = CLIENT.post(
        "/v1/preflight",
        json=_payload(),
        headers=_api_headers("source-fingerprint-1"),
    ).json()

    second_runtime = _source_runtime(
        lambda _chain, _address: _verified_source_result(block_number=124)
    )
    monkeypatch.setattr(app.state, "runtime", second_runtime)
    second = CLIENT.post(
        "/v1/preflight",
        json=_payload(),
        headers=_api_headers("source-fingerprint-2"),
    ).json()

    assert first["call_fingerprint"] == second["call_fingerprint"]
    assert first["assessment_fingerprint"] != second["assessment_fingerprint"]


def test_x402_challenge_success_receipt_and_exact_replay(monkeypatch):
    runtime, gateway, facilitator = _paid_runtime()
    monkeypatch.setattr(app.state, "runtime", runtime)

    challenge = CLIENT.post("/v1/preflight", json=_payload())
    assert challenge.status_code == 402
    required = decode_payment_required_header(challenge.headers["payment-required"])
    assert required.x402_version == 2
    assert required.accepts[0].network == "eip155:8453"
    assert required.accepts[0].asset == payments.BASE_MAINNET_USDC
    assert facilitator.verify_calls == 0

    headers = {
        payments.PAYMENT_SIGNATURE_HEADER: _payment_signature(
            gateway,
            "paid-preflight-1",
        ),
        "Idempotency-Key": "paid-preflight-1",
    }
    paid = CLIENT.post("/v1/preflight", json=_payload(), headers=headers)
    assert paid.status_code == 200
    assert paid.headers["x-lucent-access"] == "x402"
    receipt = decode_payment_response_header(paid.headers["payment-response"])
    assert receipt.success is True
    assert receipt.network == "eip155:8453"
    assert paid.json()["assurance"]["bytecode_verified"] is True
    assert (facilitator.verify_calls, facilitator.settle_calls) == (1, 1)

    replay = CLIENT.post("/v1/preflight", json=_payload(), headers=headers)
    assert replay.status_code == 200
    assert replay.headers["idempotency-replayed"] == "true"
    assert replay.headers["payment-response"] == paid.headers["payment-response"]
    assert "lucent-internal-payment-proof" not in replay.headers
    assert "lucent-internal-payment-proof" not in paid.headers
    assert (facilitator.verify_calls, facilitator.settle_calls) == (1, 1)

    forged_replay = CLIENT.post(
        "/v1/preflight",
        json=_payload(),
        headers={
            **headers,
            payments.PAYMENT_SIGNATURE_HEADER: "Z2FyYmFnZQ==",
        },
    )
    assert forged_replay.status_code == 402
    assert forged_replay.json()["code"] == "PAYMENT_REPLAY_PROOF_MISMATCH"
    assert (facilitator.verify_calls, facilitator.settle_calls) == (1, 1)


def test_same_payment_authorization_cannot_be_rewrapped_under_a_new_identifier(monkeypatch):
    runtime, gateway, facilitator = _paid_runtime()
    monkeypatch.setattr(app.state, "runtime", runtime)
    first_headers = {
        payments.PAYMENT_SIGNATURE_HEADER: _payment_signature(
            gateway,
            "payment-wrapper-one",
        ),
        "Idempotency-Key": "payment-wrapper-one",
    }
    first = CLIENT.post("/v1/preflight", json=_payload(), headers=first_headers)
    assert first.status_code == 200

    second_headers = {
        payments.PAYMENT_SIGNATURE_HEADER: _payment_signature(
            gateway,
            "payment-wrapper-two",
        ),
        "Idempotency-Key": "payment-wrapper-two",
    }
    second = CLIENT.post("/v1/preflight", json=_payload(), headers=second_headers)
    assert second.status_code == 409
    assert second.json()["code"] == "PAYMENT_AUTHORIZATION_ALREADY_USED"
    assert (facilitator.verify_calls, facilitator.settle_calls) == (2, 1)


def test_unsupported_paid_chain_is_rejected_before_facilitator_verification(monkeypatch):
    runtime, gateway, facilitator = _paid_runtime()
    monkeypatch.setattr(app.state, "runtime", runtime)
    payload = _payload()
    payload["transaction"]["chain_id"] = 137
    payload["descriptor"]["context"]["contract"]["deployments"][0]["chainId"] = 137
    response = CLIENT.post(
        "/v1/preflight",
        json=payload,
        headers={
            payments.PAYMENT_SIGNATURE_HEADER: _payment_signature(
                gateway,
                "unsupported-chain-1",
            ),
            "Idempotency-Key": "unsupported-chain-1",
        },
    )
    assert response.status_code == 422
    assert response.json()["code"] == "UNSUPPORTED_CHAIN"
    assert (facilitator.verify_calls, facilitator.settle_calls) == (0, 0)

def test_paid_request_verifies_before_source_but_never_settles_on_source_failure(monkeypatch):
    def unavailable(_chain_id, _address):
        raise verified_source.VerifiedSourceError(
            "UPSTREAM_UNAVAILABLE",
            "a required upstream service was unavailable",
        )

    runtime, gateway, facilitator = _paid_runtime(resolver=unavailable)
    monkeypatch.setattr(app.state, "runtime", runtime)
    response = CLIENT.post(
        "/v1/preflight",
        json=_payload(),
        headers={
            payments.PAYMENT_SIGNATURE_HEADER: _payment_signature(
                gateway,
                "paid-source-failure",
            ),
            "Idempotency-Key": "paid-source-failure",
        },
    )
    assert response.status_code == 503
    assert response.json()["code"] == "UPSTREAM_UNAVAILABLE"
    assert (facilitator.verify_calls, facilitator.settle_calls) == (1, 0)


def test_post_settlement_receipt_failure_is_terminal_and_never_retried(monkeypatch):
    runtime, gateway, facilitator = _paid_runtime()
    facilitator.settlement_network = "eip155:1"
    monkeypatch.setattr(app.state, "runtime", runtime)
    headers = {
        payments.PAYMENT_SIGNATURE_HEADER: _payment_signature(
            gateway,
            "paid-bad-receipt-1",
        ),
        "Idempotency-Key": "paid-bad-receipt-1",
    }
    first = CLIENT.post("/v1/preflight", json=_payload(), headers=headers)
    assert first.status_code == 502
    assert first.json()["code"] == "FACILITATOR_INVALID_RESPONSE"
    assert (facilitator.verify_calls, facilitator.settle_calls) == (1, 1)

    replay = CLIENT.post("/v1/preflight", json=_payload(), headers=headers)
    assert replay.status_code == 502
    assert replay.json()["code"] == "FACILITATOR_INVALID_RESPONSE"
    assert replay.headers["idempotency-replayed"] == "true"
    assert "retry-after" not in replay.headers
    assert (facilitator.verify_calls, facilitator.settle_calls) == (1, 1)
    assert len(runtime.payment_idempotency) == 1


def test_settlement_cancellation_cannot_resubmit_the_authorization(monkeypatch):
    runtime, gateway, facilitator = _paid_runtime()
    facilitator.cancel_next_settlement = True
    monkeypatch.setattr(app.state, "runtime", runtime)
    first_headers = {
        payments.PAYMENT_SIGNATURE_HEADER: _payment_signature(
            gateway,
            "cancelled-settlement-1",
        ),
        "Idempotency-Key": "cancelled-settlement-1",
    }
    with pytest.raises(RuntimeError, match="No response returned"):
        CLIENT.post("/v1/preflight", json=_payload(), headers=first_headers)
    assert facilitator.settle_calls == 1

    second_headers = {
        payments.PAYMENT_SIGNATURE_HEADER: _payment_signature(
            gateway,
            "cancelled-settlement-2",
        ),
        "Idempotency-Key": "cancelled-settlement-2",
    }
    second = CLIENT.post("/v1/preflight", json=_payload(), headers=second_headers)
    assert second.status_code == 409
    assert second.json()["code"] == "PAYMENT_AUTHORIZATION_ALREADY_USED"
    assert facilitator.settle_calls == 1


def test_malformed_paid_request_is_rejected_before_payment_verification(monkeypatch):
    runtime, gateway, facilitator = _paid_runtime()
    monkeypatch.setattr(app.state, "runtime", runtime)
    payload = _payload()
    payload["transaction"]["data"] = "0x1234"
    response = CLIENT.post(
        "/v1/preflight",
        json=payload,
        headers={
            payments.PAYMENT_SIGNATURE_HEADER: _payment_signature(
                gateway,
                "paid-invalid-call",
            ),
            "Idempotency-Key": "paid-invalid-call",
        },
    )
    assert response.status_code == 422
    assert facilitator.verify_calls == 0
    assert facilitator.settle_calls == 0
