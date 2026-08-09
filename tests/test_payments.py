"""x402 configuration, challenge, verification, and settlement boundaries."""

from __future__ import annotations

import asyncio
import base64
import json

import pytest
from x402 import PaymentPayload
from x402.extensions.payment_identifier import (
    PAYMENT_IDENTIFIER,
    append_payment_identifier_to_extensions,
    declare_payment_identifier_extension,
)
from x402.http.utils import (
    decode_payment_required_header,
    decode_payment_response_header,
    decode_payment_signature_header,
    encode_payment_signature_header,
)
from x402.schemas import ResourceInfo, SettleResponse, VerifyResponse

from lucent.payments import (
    BASE_MAINNET,
    BASE_MAINNET_USDC,
    PAYMENT_REQUIRED_HEADER,
    PaymentConfig,
    PaymentError,
    PaymentGateway,
    UrllibFacilitatorClient,
)

PAYEE = "0x" + "11" * 20
PAYER = "0x" + "22" * 20
TX_HASH = "0x" + "ab" * 32
RESOURCE_URL = "https://api.lucent.example/v1/preflight"
FACILITATOR_URL = "https://api.cdp.coinbase.com/platform/v2/x402"
FIXED_NOW = 2_000_000_000


class FakeFacilitator:
    def __init__(self, *, verify=None, settle=None, error=None):
        self.verify_result = verify or VerifyResponse(isValid=True, payer=PAYER)
        self.settle_result = settle or SettleResponse(
            success=True,
            payer=PAYER,
            transaction=TX_HASH,
            network=BASE_MAINNET,
            amount="10000",
        )
        self.error = error
        self.verify_calls = 0
        self.settle_calls = 0

    async def verify(self, payload, requirements):
        self.verify_calls += 1
        if self.error == "verify":
            raise RuntimeError("private facilitator detail")
        return self.verify_result

    async def settle(self, payload, requirements):
        self.settle_calls += 1
        if self.error == "settle":
            raise RuntimeError("private settlement detail")
        return self.settle_result


def _config(**changes):
    values = {
        "enabled": True,
        "network": BASE_MAINNET,
        "asset": BASE_MAINNET_USDC,
        "amount": "10000",
        "pay_to": PAYEE,
        "resource_url": RESOURCE_URL,
        "facilitator_url": FACILITATOR_URL,
    }
    values.update(changes)
    return PaymentConfig(**values)


def _gateway(facilitator=None, **changes):
    return PaymentGateway(
        _config(**changes),
        facilitator or FakeFacilitator(),
        clock=lambda: FIXED_NOW,
    )


def _signature(
    gateway,
    *,
    requirements=None,
    resource_url=RESOURCE_URL,
    payment_identifier="payment_test_123456",
):
    requirement = requirements or gateway._requirements
    extensions = {
        PAYMENT_IDENTIFIER: declare_payment_identifier_extension(required=True),
    }
    append_payment_identifier_to_extensions(extensions, payment_identifier)
    payload = PaymentPayload(
        x402Version=2,
        payload={
            "signature": "0x" + "01" * 65,
            "authorization": {
                "from": PAYER,
                "to": PAYEE,
                "value": "10000",
                "validAfter": "0",
                "validBefore": str(FIXED_NOW + 300),
                "nonce": "0x" + "33" * 32,
            },
        },
        accepted=requirement,
        resource=ResourceInfo(url=resource_url),
        extensions=extensions,
    )
    return encode_payment_signature_header(payload)


def test_disabled_is_the_safe_default():
    config = PaymentConfig.from_env({})
    gateway = PaymentGateway(config)
    assert config.enabled is False
    with pytest.raises(PaymentError) as caught:
        gateway.challenge()
    assert caught.value.code == "PAYMENTS_DISABLED"
    assert caught.value.status == 503


def test_enabled_environment_builds_fixed_base_usdc_terms():
    config = PaymentConfig.from_env({
        "LUCENT_X402_ENABLED": "true",
        "LUCENT_X402_PAY_TO": PAYEE,
        "LUCENT_X402_RESOURCE_URL": RESOURCE_URL,
        "LUCENT_X402_FACILITATOR_URL": FACILITATOR_URL,
        "LUCENT_X402_AMOUNT": "25000",
    })
    assert config.network == "eip155:8453"
    assert config.asset == BASE_MAINNET_USDC
    assert config.amount == "25000"


def test_facilitator_bearer_credential_is_server_only_and_redacted():
    secret = "facilitator.jwt.secret"
    config = PaymentConfig.from_env({
        "LUCENT_X402_ENABLED": "true",
        "LUCENT_X402_PAY_TO": PAYEE,
        "LUCENT_X402_RESOURCE_URL": RESOURCE_URL,
        "LUCENT_X402_FACILITATOR_URL": FACILITATOR_URL,
        "LUCENT_X402_FACILITATOR_BEARER_TOKEN": secret,
    })
    assert config.facilitator_bearer_token == secret
    assert secret not in repr(config)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"LUCENT_X402_ENABLED": "sometimes"}, "boolean"),
        ({"LUCENT_X402_NETWORK": "8453"}, "eip155:8453"),
        ({"LUCENT_X402_PAY_TO": "0x1234"}, "20-byte"),
        ({"LUCENT_X402_AMOUNT": "0"}, "positive"),
        ({"LUCENT_X402_AMOUNT": "100000001"}, "ceiling"),
        ({"LUCENT_X402_RESOURCE_URL": "http://api.example/v1/preflight"}, "HTTPS"),
        ({"LUCENT_X402_RESOURCE_URL": "https://api.example/other"}, "/v1/preflight"),
        ({"LUCENT_X402_FACILITATOR_URL": "https://127.0.0.1/x402"}, "allowlisted"),
        ({"LUCENT_X402_FACILITATOR_TIMEOUT": "30"}, "between 1 and 15"),
        ({"LUCENT_X402_FACILITATOR_BEARER_TOKEN": "bad\nheader"}, "visible ASCII"),
    ],
)
def test_invalid_payment_configuration_fails_closed(change, message):
    env = {
        "LUCENT_X402_ENABLED": "true",
        "LUCENT_X402_PAY_TO": PAYEE,
        "LUCENT_X402_RESOURCE_URL": RESOURCE_URL,
        "LUCENT_X402_FACILITATOR_URL": FACILITATOR_URL,
    }
    env.update(change)
    with pytest.raises(ValueError, match=message):
        PaymentConfig.from_env(env)


def test_programmatic_payment_timeout_cannot_outlive_the_claim_window():
    with pytest.raises(ValueError, match="between 1 and 300"):
        PaymentGateway(
            _config(max_timeout_seconds=301),
            FakeFacilitator(),
            clock=lambda: FIXED_NOW,
        )


def test_private_facilitator_requires_explicit_server_allowlist():
    config = PaymentConfig.from_env({
        "LUCENT_X402_ENABLED": "true",
        "LUCENT_X402_PAY_TO": PAYEE,
        "LUCENT_X402_RESOURCE_URL": RESOURCE_URL,
        "LUCENT_X402_FACILITATOR_URL": "https://payments.lucent.example/x402",
        "LUCENT_X402_ALLOWED_FACILITATOR_HOSTS": "payments.lucent.example",
    })
    assert config.facilitator_url == "https://payments.lucent.example/x402"


def test_challenge_uses_official_v2_header_and_server_terms():
    challenge = _gateway().challenge()
    decoded = decode_payment_required_header(challenge.header_value)
    assert decoded.x402_version == 2
    assert decoded.resource.url == RESOURCE_URL
    assert len(decoded.accepts) == 1
    requirement = decoded.accepts[0]
    assert requirement.scheme == "exact"
    assert requirement.network == BASE_MAINNET
    assert requirement.asset == BASE_MAINNET_USDC
    assert requirement.amount == "10000"
    assert requirement.pay_to == PAYEE
    assert requirement.extra["assetTransferMethod"] == "eip3009"
    assert decoded.extensions[PAYMENT_IDENTIFIER]["info"]["required"] is True
    assert challenge.body == decoded.model_dump(by_alias=True, exclude_none=True)


def test_valid_proof_is_verified_then_settled_once():
    facilitator = FakeFacilitator()
    gateway = _gateway(facilitator)
    signature = _signature(gateway)
    receipt = asyncio.run(gateway.verify_and_settle(signature))
    assert facilitator.verify_calls == 1
    assert facilitator.settle_calls == 1
    assert receipt.transaction == TX_HASH
    assert receipt.amount == "10000"
    assert receipt.proof_fingerprint.startswith("sha256:")
    decoded = decode_payment_response_header(receipt.response_header)
    assert decoded.success is True
    assert decoded.transaction == TX_HASH


def test_verification_can_precede_resource_work_without_settlement():
    facilitator = FakeFacilitator()
    gateway = _gateway(facilitator)
    verified = asyncio.run(gateway.verify(_signature(gateway)))
    assert verified.payer == PAYER
    assert verified.payment_identifier == "payment_test_123456"
    assert verified.authorization_fingerprint.startswith("sha256:")
    assert facilitator.verify_calls == 1
    assert facilitator.settle_calls == 0

    receipt = asyncio.run(gateway.settle(verified))
    assert receipt.payer == PAYER
    assert facilitator.settle_calls == 1


def test_malformed_or_oversized_proof_never_reaches_facilitator():
    facilitator = FakeFacilitator()
    gateway = _gateway(facilitator)
    for value in ("not-base64", "x" * (64 * 1024 + 1)):
        with pytest.raises(PaymentError) as caught:
            asyncio.run(gateway.verify_and_settle(value))
        assert caught.value.code == "INVALID_PAYMENT_SIGNATURE"
    assert facilitator.verify_calls == 0
    assert facilitator.settle_calls == 0


def test_payment_identifier_is_required_and_must_match_http_idempotency_key():
    facilitator = FakeFacilitator()
    gateway = _gateway(facilitator)
    payload = PaymentPayload(
        x402Version=2,
        payload={},
        accepted=gateway._requirements,
        resource=ResourceInfo(url=RESOURCE_URL),
    )
    missing = encode_payment_signature_header(payload)
    with pytest.raises(PaymentError) as caught:
        asyncio.run(gateway.verify(missing))
    assert caught.value.code == "PAYMENT_IDENTIFIER_REQUIRED"

    signature = _signature(gateway, payment_identifier="payment_test_123456")
    with pytest.raises(PaymentError) as mismatch:
        asyncio.run(
            gateway.verify(signature, payment_identifier="different_test_12345")
        )
    assert mismatch.value.code == "PAYMENT_IDENTIFIER_MISMATCH"
    assert facilitator.verify_calls == 0


def test_authorization_identity_ignores_mutable_payment_identifier():
    gateway = _gateway()
    first = asyncio.run(
        gateway.verify(_signature(gateway, payment_identifier="payment_first_12345"))
    )
    second = asyncio.run(
        gateway.verify(_signature(gateway, payment_identifier="payment_second_1234"))
    )
    assert first.payment_identifier != second.payment_identifier
    assert first.proof_fingerprint != second.proof_fingerprint
    assert first.authorization_fingerprint == second.authorization_fingerprint

    changed_payload = decode_payment_signature_header(
        _signature(gateway, payment_identifier="payment_third_12345")
    )
    changed_payload.payload["signature"] = "0x" + "02" * 65
    third = asyncio.run(
        gateway.verify(encode_payment_signature_header(changed_payload))
    )
    assert third.proof_fingerprint != first.proof_fingerprint
    assert third.authorization_fingerprint == first.authorization_fingerprint


def test_payment_resource_is_mandatory_not_merely_checked_when_present():
    facilitator = FakeFacilitator()
    gateway = _gateway(facilitator)
    payload = decode_payment_signature_header(_signature(gateway))
    missing_resource = encode_payment_signature_header(
        payload.model_copy(update={"resource": None})
    )
    with pytest.raises(PaymentError) as caught:
        asyncio.run(gateway.verify(missing_resource))
    assert caught.value.code == "PAYMENT_RESOURCE_MISMATCH"
    assert facilitator.verify_calls == 0


def test_paid_replay_requires_the_exact_original_proof():
    gateway = _gateway()
    signature = _signature(gateway)
    expected = gateway.proof_fingerprint(signature)
    gateway.assert_replay_proof(signature, expected)
    with pytest.raises(PaymentError) as caught:
        gateway.assert_replay_proof(signature + "AAAA", expected)
    assert caught.value.code == "PAYMENT_REPLAY_PROOF_MISMATCH"


def test_v1_proof_is_rejected_without_verification():
    facilitator = FakeFacilitator()
    gateway = _gateway(facilitator)
    encoded = base64.b64encode(json.dumps({"x402Version": 1}).encode()).decode()
    with pytest.raises(PaymentError) as caught:
        asyncio.run(gateway.verify_and_settle(encoded))
    assert caught.value.code in {"INVALID_PAYMENT_SIGNATURE", "UNSUPPORTED_PAYMENT_VERSION"}
    assert facilitator.verify_calls == 0


def test_caller_cannot_change_price_or_resource():
    for mutation in ("terms", "resource"):
        facilitator = FakeFacilitator()
        gateway = _gateway(facilitator)
        if mutation == "terms":
            changed = gateway._requirements.model_copy(update={"amount": "1"})
            signature = _signature(gateway, requirements=changed)
            expected = "PAYMENT_REQUIREMENTS_MISMATCH"
        else:
            signature = _signature(gateway, resource_url="https://other.example/v1/preflight")
            expected = "PAYMENT_RESOURCE_MISMATCH"
        with pytest.raises(PaymentError) as caught:
            asyncio.run(gateway.verify_and_settle(signature))
        assert caught.value.code == expected
        assert facilitator.verify_calls == 0
        assert facilitator.settle_calls == 0


def test_signed_authorization_must_match_fixed_amount_and_payee():
    for field, value in (("value", "1"), ("to", "0x" + "77" * 20)):
        facilitator = FakeFacilitator()
        gateway = _gateway(facilitator)
        payload = decode_payment_signature_header(_signature(gateway))
        payload.payload["authorization"][field] = value
        signature = encode_payment_signature_header(payload)
        with pytest.raises(PaymentError) as caught:
            asyncio.run(gateway.verify(signature))
        assert caught.value.code == "PAYMENT_REQUIREMENTS_MISMATCH"
        assert facilitator.verify_calls == 0


def test_authorization_window_is_server_bounded_before_facilitator_work():
    for field, value in (
        ("validAfter", str(FIXED_NOW + 1)),
        ("validBefore", str(FIXED_NOW)),
        ("validBefore", str(FIXED_NOW + 301)),
    ):
        facilitator = FakeFacilitator()
        gateway = _gateway(facilitator)
        payload = decode_payment_signature_header(_signature(gateway))
        payload.payload["authorization"][field] = value
        with pytest.raises(PaymentError) as caught:
            asyncio.run(gateway.verify(encode_payment_signature_header(payload)))
        assert caught.value.code == "PAYMENT_AUTHORIZATION_WINDOW_MISMATCH"
        assert facilitator.verify_calls == 0


def test_failed_verification_never_settles():
    facilitator = FakeFacilitator(verify=VerifyResponse(isValid=False, invalidReason="bad"))
    gateway = _gateway(facilitator)
    with pytest.raises(PaymentError) as caught:
        asyncio.run(gateway.verify_and_settle(_signature(gateway)))
    assert caught.value.code == "PAYMENT_NOT_VERIFIED"
    assert facilitator.verify_calls == 1
    assert facilitator.settle_calls == 0
    assert "bad" not in caught.value.message


def test_facilitator_exceptions_are_redacted_and_retryable():
    facilitator = FakeFacilitator(error="verify")
    gateway = _gateway(facilitator)
    with pytest.raises(PaymentError) as caught:
        asyncio.run(gateway.verify_and_settle(_signature(gateway)))
    assert caught.value.code == "FACILITATOR_UNAVAILABLE"
    assert caught.value.status == 502
    assert caught.value.retryable is True
    assert "private" not in caught.value.message


def test_unsuccessful_or_mismatched_settlement_is_not_a_receipt():
    cases = [
        (
            SettleResponse(
                success=False,
                errorReason="failed",
                transaction="",
                network=BASE_MAINNET,
            ),
            "PAYMENT_NOT_SETTLED",
        ),
        (
            SettleResponse(
                success=True,
                payer=PAYER,
                transaction=TX_HASH,
                network="eip155:1",
                amount="10000",
            ),
            "FACILITATOR_INVALID_RESPONSE",
        ),
    ]
    for result, expected in cases:
        facilitator = FakeFacilitator(settle=result)
        gateway = _gateway(facilitator)
        with pytest.raises(PaymentError) as caught:
            asyncio.run(gateway.verify_and_settle(_signature(gateway)))
        assert caught.value.code == expected
        assert facilitator.verify_calls == 1
        assert facilitator.settle_calls == 1
        assert caught.value.terminal is True
        assert caught.value.retryable is False


def test_verifier_and_settlement_payer_must_match():
    other_payer = "0x" + "44" * 20
    facilitator = FakeFacilitator(
        verify=VerifyResponse(isValid=True, payer=PAYER),
        settle=SettleResponse(
            success=True,
            payer=other_payer,
            transaction=TX_HASH,
            network=BASE_MAINNET,
            amount="10000",
        ),
    )
    gateway = _gateway(facilitator)
    with pytest.raises(PaymentError) as caught:
        asyncio.run(gateway.verify_and_settle(_signature(gateway)))
    assert caught.value.code == "FACILITATOR_INVALID_RESPONSE"
    assert caught.value.terminal is True


def test_verifier_payer_must_match_the_signed_authorization():
    facilitator = FakeFacilitator(
        verify=VerifyResponse(isValid=True, payer="0x" + "44" * 20)
    )
    gateway = _gateway(facilitator)
    with pytest.raises(PaymentError) as caught:
        asyncio.run(gateway.verify(_signature(gateway)))
    assert caught.value.code == "FACILITATOR_INVALID_RESPONSE"
    assert caught.value.retryable is True
    assert facilitator.settle_calls == 0


def test_header_names_are_the_x402_v2_contract():
    assert PAYMENT_REQUIRED_HEADER == "PAYMENT-REQUIRED"


@pytest.mark.parametrize(
    "body",
    [
        b'{"isValid":true,"isValid":false}',
        b'{"isValid":true,"extra":NaN}',
        (b'{"isValid":true,"extra":' + b"[" * 40 + b"0" + b"]" * 40 + b"}"),
    ],
)
def test_facilitator_json_must_be_unique_finite_and_bounded(body):
    class Response:
        status = 200
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit):
            return body

    class Opener:
        def open(self, _request, timeout):
            assert timeout == 8
            return Response()

    gateway = _gateway()
    payload = decode_payment_signature_header(_signature(gateway))
    client = UrllibFacilitatorClient(FACILITATOR_URL)
    client._opener = Opener()
    with pytest.raises(PaymentError) as caught:
        asyncio.run(client.verify(payload, gateway._requirements))
    assert caught.value.code == "FACILITATOR_INVALID_RESPONSE"
