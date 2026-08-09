"""Feature-gated x402 v2 settlement for the hosted preflight API.

The module deliberately keeps all payment terms server-owned.  A caller may
submit a ``PAYMENT-SIGNATURE`` header, but may not choose the network, token,
price, payee, resource URL, or facilitator.  Cryptographic verification and
EIP-3009 settlement are delegated to an x402 facilitator; Lucent only builds
and validates the official x402 models and HTTP headers.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import math
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from pydantic import ValidationError
from x402 import PaymentPayload, PaymentRequired, PaymentRequirements
from x402.extensions.payment_identifier import (
    PAYMENT_IDENTIFIER,
    declare_payment_identifier_extension,
    extract_and_validate_payment_identifier,
)
from x402.http.utils import (
    decode_payment_signature_header,
    encode_payment_required_header,
    encode_payment_response_header,
)
from x402.schemas import ResourceInfo, SettleResponse, VerifyResponse

PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"
PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"
PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE"

BASE_MAINNET = "eip155:8453"
BASE_MAINNET_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
DEFAULT_ALLOWED_FACILITATOR_HOSTS = frozenset({"api.cdp.coinbase.com", "x402.org"})
MAX_PAYMENT_HEADER_BYTES = 64 * 1024
MAX_FACILITATOR_RESPONSE_BYTES = 256 * 1024
MAX_FACILITATOR_JSON_DEPTH = 32
MAX_FACILITATOR_JSON_NODES = 20_000
MAX_FACILITATOR_JSON_STRING = 64 * 1024
MAX_PRICE_ATOMIC = 100_000_000  # 100 USDC; catches dangerous deployment typos.
MAX_PAYMENT_TIMEOUT_SECONDS = 300
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


class PaymentError(RuntimeError):
    """Stable, redacted payment failure safe to expose through HTTP."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int,
        retryable: bool = False,
        terminal: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.retryable = retryable
        self.terminal = terminal


def _strict_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError("boolean setting must be true or false")


def _server_https_url(value: str, *, setting: str, path: str | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError(f"{setting} must be a non-empty HTTPS URL")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port not in {None, 443}
    ):
        raise ValueError(f"{setting} must be a canonical HTTPS URL without credentials")
    if path is not None and parsed.path != path:
        raise ValueError(f"{setting} must end at {path}")
    return urllib.parse.urlunsplit(("https", parsed.netloc, parsed.path.rstrip("/"), "", ""))


@dataclass(frozen=True)
class PaymentConfig:
    """Immutable server-side x402 terms.

    ``amount`` is expressed in USDC atomic units (six decimals), avoiding all
    floating-point price ambiguity.
    """

    enabled: bool = False
    network: str = BASE_MAINNET
    asset: str = BASE_MAINNET_USDC
    amount: str = "10000"  # $0.01
    pay_to: str | None = None
    resource_url: str | None = None
    facilitator_url: str | None = None
    facilitator_bearer_token: str | None = field(default=None, repr=False)
    max_timeout_seconds: int = 300
    facilitator_timeout_seconds: float = 8.0

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> PaymentConfig:
        env = os.environ if environ is None else environ
        enabled = _strict_bool(env.get("LUCENT_X402_ENABLED"), default=False)
        if not enabled:
            return cls(enabled=False)

        network = env.get("LUCENT_X402_NETWORK", BASE_MAINNET)
        if network != BASE_MAINNET:
            raise ValueError("LUCENT_X402_NETWORK must be eip155:8453")

        pay_to = env.get("LUCENT_X402_PAY_TO", "")
        if not ADDRESS_RE.fullmatch(pay_to):
            raise ValueError("LUCENT_X402_PAY_TO must be a 20-byte EVM address")

        amount = env.get("LUCENT_X402_AMOUNT", "10000")
        if not re.fullmatch(r"[1-9][0-9]*", amount):
            raise ValueError("LUCENT_X402_AMOUNT must be a positive atomic-unit integer")
        if int(amount) > MAX_PRICE_ATOMIC:
            raise ValueError("LUCENT_X402_AMOUNT exceeds the 100 USDC safety ceiling")

        resource_url = _server_https_url(
            env.get("LUCENT_X402_RESOURCE_URL", ""),
            setting="LUCENT_X402_RESOURCE_URL",
            path="/v1/preflight",
        )
        facilitator_url = _server_https_url(
            env.get("LUCENT_X402_FACILITATOR_URL", ""),
            setting="LUCENT_X402_FACILITATOR_URL",
        )

        configured_hosts = {
            item.strip().lower()
            for item in env.get("LUCENT_X402_ALLOWED_FACILITATOR_HOSTS", "").split(",")
            if item.strip()
        }
        allowed_hosts = DEFAULT_ALLOWED_FACILITATOR_HOSTS | configured_hosts
        facilitator_host = urllib.parse.urlsplit(facilitator_url).hostname
        if facilitator_host is None or facilitator_host.lower() not in allowed_hosts:
            raise ValueError("LUCENT_X402_FACILITATOR_URL host is not allowlisted")

        try:
            facilitator_timeout = float(env.get("LUCENT_X402_FACILITATOR_TIMEOUT", "8"))
        except ValueError as exc:
            raise ValueError("LUCENT_X402_FACILITATOR_TIMEOUT must be numeric") from exc
        if not 1 <= facilitator_timeout <= 15:
            raise ValueError("LUCENT_X402_FACILITATOR_TIMEOUT must be between 1 and 15 seconds")

        bearer_token = env.get("LUCENT_X402_FACILITATOR_BEARER_TOKEN")
        if bearer_token is not None:
            if (
                not bearer_token
                or len(bearer_token.encode("utf-8")) > 8_192
                or any(ord(character) < 0x21 or ord(character) > 0x7E for character in bearer_token)
            ):
                raise ValueError(
                    "LUCENT_X402_FACILITATOR_BEARER_TOKEN must be bounded visible ASCII"
                )

        return cls(
            enabled=True,
            network=network,
            amount=amount,
            pay_to=pay_to,
            resource_url=resource_url,
            facilitator_url=facilitator_url,
            facilitator_bearer_token=bearer_token,
            facilitator_timeout_seconds=facilitator_timeout,
        )


@dataclass(frozen=True)
class PaymentChallenge:
    header_value: str
    body: dict[str, Any]


@dataclass(frozen=True)
class PaymentReceipt:
    payer: str | None
    transaction: str
    network: str
    amount: str
    response_header: str
    proof_fingerprint: str

    def to_dict(self) -> dict[str, str | None]:
        return {
            "payer": self.payer,
            "transaction": self.transaction,
            "network": self.network,
            "amount": self.amount,
            "proof_fingerprint": self.proof_fingerprint,
        }


@dataclass(frozen=True)
class VerifiedPayment:
    """An opaque facilitator-verified proof awaiting resource settlement."""

    payer: str | None
    payment_identifier: str
    proof_fingerprint: str
    authorization_fingerprint: str
    _payload: PaymentPayload = field(repr=False)


class FacilitatorClient(Protocol):
    async def verify(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> VerifyResponse: ...

    async def settle(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> SettleResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate_facilitator_json(value: object) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_FACILITATOR_JSON_NODES or depth > MAX_FACILITATOR_JSON_DEPTH:
            raise ValueError("facilitator JSON structure exceeds its limit")
        if isinstance(item, str):
            if len(item) > MAX_FACILITATOR_JSON_STRING:
                raise ValueError("facilitator JSON string exceeds its limit")
        elif isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif item is None or isinstance(item, (bool, int)):
            continue
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("facilitator JSON number was non-finite")
        else:
            raise ValueError("facilitator response contained non-JSON data")


class UrllibFacilitatorClient:
    """Small bounded transport implementing the official facilitator protocol."""

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 8.0,
        bearer_token: str | None = None,
    ) -> None:
        self._url = url.rstrip("/")
        self._timeout = timeout
        self._bearer_token = bearer_token
        # Do not silently route a bearer credential through ambient
        # HTTP(S)_PROXY process configuration.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect,
        )

    async def verify(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> VerifyResponse:
        data = await asyncio.to_thread(self._post, "verify", payload, requirements)
        try:
            return VerifyResponse.model_validate(data)
        except (ValidationError, ValueError, TypeError) as exc:
            raise PaymentError(
                "FACILITATOR_INVALID_RESPONSE",
                "payment verifier returned an invalid response",
                status=502,
                retryable=True,
            ) from exc

    async def settle(
        self,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> SettleResponse:
        data = await asyncio.to_thread(self._post, "settle", payload, requirements)
        try:
            return SettleResponse.model_validate(data)
        except (ValidationError, ValueError, TypeError) as exc:
            raise PaymentError(
                "FACILITATOR_INVALID_RESPONSE",
                "payment settlement returned an invalid response",
                status=502,
                retryable=True,
            ) from exc

    def _post(
        self,
        operation: str,
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> dict[str, Any]:
        body = json.dumps(
            {
                "x402Version": 2,
                "paymentPayload": payload.model_dump(by_alias=True, exclude_none=True),
                "paymentRequirements": requirements.model_dump(by_alias=True, exclude_none=True),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "lucent-x402/0.2.0",
        }
        if self._bearer_token is not None:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        request = urllib.request.Request(
            f"{self._url}/{operation}",
            data=body,
            method="POST",
            headers=headers,
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > MAX_FACILITATOR_RESPONSE_BYTES:
                    raise PaymentError(
                        "FACILITATOR_INVALID_RESPONSE",
                        "payment facilitator response was too large",
                        status=502,
                        retryable=True,
                    )
                raw = response.read(MAX_FACILITATOR_RESPONSE_BYTES + 1)
        except PaymentError:
            raise
        except (OSError, urllib.error.HTTPError, urllib.error.URLError, ValueError) as exc:
            raise PaymentError(
                "FACILITATOR_UNAVAILABLE",
                "payment facilitator is temporarily unavailable",
                status=502,
                retryable=True,
            ) from exc
        if len(raw) > MAX_FACILITATOR_RESPONSE_BYTES:
            raise PaymentError(
                "FACILITATOR_INVALID_RESPONSE",
                "payment facilitator response was too large",
                status=502,
                retryable=True,
            )
        try:
            parsed = json.loads(
                raw,
                parse_constant=_reject_json_constant,
                object_pairs_hook=_unique_json_object,
            )
            _validate_facilitator_json(parsed)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
            raise PaymentError(
                "FACILITATOR_INVALID_RESPONSE",
                "payment facilitator returned invalid JSON",
                status=502,
                retryable=True,
            ) from exc
        if not isinstance(parsed, dict):
            raise PaymentError(
                "FACILITATOR_INVALID_RESPONSE",
                "payment facilitator returned invalid data",
                status=502,
                retryable=True,
            )
        return parsed


class PaymentGateway:
    """Build challenges and perform one verified x402 settlement."""

    def __init__(
        self,
        config: PaymentConfig,
        facilitator: FacilitatorClient | None = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._clock = clock
        if config.enabled and (
            isinstance(config.max_timeout_seconds, bool)
            or not isinstance(config.max_timeout_seconds, int)
            or not 1 <= config.max_timeout_seconds <= MAX_PAYMENT_TIMEOUT_SECONDS
        ):
            raise ValueError("payment timeout must be between 1 and 300 seconds")
        if config.enabled and facilitator is None:
            if config.facilitator_url is None:
                raise ValueError("enabled payments require a facilitator URL")
            facilitator = UrllibFacilitatorClient(
                config.facilitator_url,
                timeout=config.facilitator_timeout_seconds,
                bearer_token=config.facilitator_bearer_token,
            )
        self._facilitator = facilitator
        self._requirements = self._build_requirements() if config.enabled else None

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def _require_enabled(self) -> tuple[PaymentRequirements, FacilitatorClient]:
        if not self.enabled or self._requirements is None or self._facilitator is None:
            raise PaymentError(
                "PAYMENTS_DISABLED",
                "x402 payment access is not enabled",
                status=503,
            )
        return self._requirements, self._facilitator

    def _build_requirements(self) -> PaymentRequirements:
        assert self.config.pay_to is not None
        return PaymentRequirements(
            scheme="exact",
            network=self.config.network,
            asset=self.config.asset,
            amount=self.config.amount,
            payTo=self.config.pay_to,
            maxTimeoutSeconds=self.config.max_timeout_seconds,
            extra={
                "name": "USD Coin",
                "version": "2",
                "assetTransferMethod": "eip3009",
            },
        )

    def challenge(self, *, error: str | None = None) -> PaymentChallenge:
        requirements, _ = self._require_enabled()
        assert self.config.resource_url is not None
        required = PaymentRequired(
            x402Version=2,
            error=error,
            resource=ResourceInfo(
                url=self.config.resource_url,
                description="Lucent call-scoped EVM preflight analysis",
                mimeType="application/json",
                serviceName="lucent",
            ),
            accepts=[requirements],
            extensions={
                PAYMENT_IDENTIFIER: declare_payment_identifier_extension(required=True),
            },
        )
        return PaymentChallenge(
            header_value=encode_payment_required_header(required),
            body=required.model_dump(by_alias=True, exclude_none=True),
        )

    @staticmethod
    def proof_fingerprint(payment_signature: str) -> str:
        return "sha256:" + hashlib.sha256(payment_signature.encode("ascii")).hexdigest()

    @staticmethod
    def _authorization_fingerprint(
        payload: PaymentPayload,
        requirements: PaymentRequirements,
    ) -> str:
        """Identify the signed transfer independently of caller-owned extensions."""
        authorization = (
            payload.payload.get("authorization")
            if isinstance(payload.payload, dict)
            else None
        )
        if not isinstance(authorization, dict):
            raise PaymentError(
                "INVALID_PAYMENT_SIGNATURE",
                "PAYMENT-SIGNATURE contains an invalid authorization",
                status=402,
            )

        def decimal(field_name: str) -> str:
            value = authorization.get(field_name)
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise ValueError(field_name)
            rendered = str(value)
            if not re.fullmatch(r"(?:0|[1-9][0-9]*)", rendered):
                raise ValueError(field_name)
            return str(int(rendered))

        try:
            payer = authorization.get("from")
            pay_to = authorization.get("to")
            nonce = authorization.get("nonce")
            if (
                not isinstance(payer, str)
                or not ADDRESS_RE.fullmatch(payer)
                or not isinstance(pay_to, str)
                or not ADDRESS_RE.fullmatch(pay_to)
                or not isinstance(nonce, str)
                or not TX_HASH_RE.fullmatch(nonce)
            ):
                raise ValueError("authorization identity")
            transfer_value = decimal("value")
            if (
                pay_to.lower() != requirements.pay_to.lower()
                or transfer_value != requirements.amount
            ):
                raise PaymentError(
                    "PAYMENT_REQUIREMENTS_MISMATCH",
                    "payment authorization does not match this resource's terms",
                    status=402,
                )
            canonical = json.dumps(
                {
                    "scheme": requirements.scheme,
                    "network": requirements.network,
                    "asset": requirements.asset,
                    "amount": requirements.amount,
                    "pay_to": requirements.pay_to,
                    "authorization": {
                        "from": payer.lower(),
                        "to": pay_to.lower(),
                        "value": transfer_value,
                        "valid_after": decimal("validAfter"),
                        "valid_before": decimal("validBefore"),
                        "nonce": nonce.lower(),
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise PaymentError(
                "INVALID_PAYMENT_SIGNATURE",
                "PAYMENT-SIGNATURE contains an invalid authorization",
                status=402,
            ) from exc
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    @classmethod
    def assert_replay_proof(cls, payment_signature: str, expected_fingerprint: str) -> None:
        """Require the exact original payment proof before replaying a paid result."""
        try:
            actual = cls.proof_fingerprint(payment_signature)
        except (AttributeError, UnicodeEncodeError) as exc:
            raise PaymentError(
                "INVALID_PAYMENT_SIGNATURE",
                "PAYMENT-SIGNATURE is malformed",
                status=402,
            ) from exc
        if not hmac.compare_digest(actual, expected_fingerprint):
            raise PaymentError(
                "PAYMENT_REPLAY_PROOF_MISMATCH",
                "paid replay requires the original payment proof",
                status=402,
            )

    async def verify(
        self,
        payment_signature: str,
        *,
        payment_identifier: str | None = None,
    ) -> VerifiedPayment:
        """Validate fixed terms and ask the facilitator to verify the proof."""
        requirements, facilitator = self._require_enabled()
        if (
            not isinstance(payment_signature, str)
            or not payment_signature
            or len(payment_signature.encode("utf-8")) > MAX_PAYMENT_HEADER_BYTES
            or not payment_signature.isascii()
        ):
            raise PaymentError(
                "INVALID_PAYMENT_SIGNATURE",
                "PAYMENT-SIGNATURE is missing or malformed",
                status=402,
            )
        try:
            base64.b64decode(payment_signature, validate=True)
        except (ValueError, TypeError) as exc:
            raise PaymentError(
                "INVALID_PAYMENT_SIGNATURE",
                "PAYMENT-SIGNATURE is malformed",
                status=402,
            ) from exc
        try:
            payload = decode_payment_signature_header(payment_signature)
        except Exception as exc:
            raise PaymentError(
                "INVALID_PAYMENT_SIGNATURE",
                "PAYMENT-SIGNATURE is malformed",
                status=402,
            ) from exc
        if not isinstance(payload, PaymentPayload) or payload.x402_version != 2:
            raise PaymentError(
                "UNSUPPORTED_PAYMENT_VERSION",
                "only x402 v2 payments are accepted",
                status=402,
            )
        identifier, identifier_validation = extract_and_validate_payment_identifier(payload)
        if not identifier_validation.valid or identifier is None:
            raise PaymentError(
                "PAYMENT_IDENTIFIER_REQUIRED",
                "payment proof must contain a valid payment identifier",
                status=402,
            )
        if payment_identifier is not None and identifier != payment_identifier:
            raise PaymentError(
                "PAYMENT_IDENTIFIER_MISMATCH",
                "payment identifier does not match Idempotency-Key",
                status=402,
            )
        expected = requirements.model_dump(by_alias=True, exclude_none=True)
        accepted = payload.accepted.model_dump(by_alias=True, exclude_none=True)
        if accepted != expected:
            raise PaymentError(
                "PAYMENT_REQUIREMENTS_MISMATCH",
                "payment proof does not match this resource's terms",
                status=402,
            )
        if payload.resource is None or payload.resource.url != self.config.resource_url:
            raise PaymentError(
                "PAYMENT_RESOURCE_MISMATCH",
                "payment proof is bound to a different resource",
                status=402,
            )
        authorization_fingerprint = self._authorization_fingerprint(
            payload,
            requirements,
        )
        authorization = payload.payload["authorization"]
        authorization_payer = authorization["from"]
        try:
            now = float(self._clock())
            valid_after = int(authorization["validAfter"])
            valid_before = int(authorization["validBefore"])
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise PaymentError(
                "INVALID_PAYMENT_SIGNATURE",
                "PAYMENT-SIGNATURE contains an invalid authorization window",
                status=402,
            ) from exc
        if (
            not math.isfinite(now)
            or valid_after > now
            or valid_before <= now
            or valid_before > now + self.config.max_timeout_seconds
        ):
            raise PaymentError(
                "PAYMENT_AUTHORIZATION_WINDOW_MISMATCH",
                "payment authorization is outside the server-owned time window",
                status=402,
            )

        try:
            verified = await facilitator.verify(payload, requirements)
        except PaymentError:
            raise
        except Exception as exc:
            raise PaymentError(
                "FACILITATOR_UNAVAILABLE",
                "payment verifier is temporarily unavailable",
                status=502,
                retryable=True,
            ) from exc
        if not verified.is_valid:
            raise PaymentError(
                "PAYMENT_NOT_VERIFIED",
                "payment proof was not accepted",
                status=402,
            )
        if verified.payer is not None and not ADDRESS_RE.fullmatch(verified.payer):
            raise PaymentError(
                "FACILITATOR_INVALID_RESPONSE",
                "payment verifier did not return a valid payer",
                status=502,
                retryable=True,
            )
        if (
            verified.payer is not None
            and not hmac.compare_digest(
                verified.payer.lower(),
                authorization_payer.lower(),
            )
        ):
            raise PaymentError(
                "FACILITATOR_INVALID_RESPONSE",
                "payment verifier payer did not match the authorization",
                status=502,
                retryable=True,
            )

        return VerifiedPayment(
            payer=authorization_payer,
            payment_identifier=identifier,
            proof_fingerprint=self.proof_fingerprint(payment_signature),
            authorization_fingerprint=authorization_fingerprint,
            _payload=payload,
        )

    async def settle(self, verified_payment: VerifiedPayment) -> PaymentReceipt:
        """Settle a proof that this gateway previously verified."""
        requirements, facilitator = self._require_enabled()
        if not isinstance(verified_payment, VerifiedPayment):
            raise TypeError("verified_payment must be a VerifiedPayment")
        try:
            settled = await facilitator.settle(verified_payment._payload, requirements)
        except PaymentError as exc:
            # Once settlement has been submitted, a transport failure leaves
            # the transfer outcome unknown. Retrying automatically could
            # repeat the side effect, so the authorization is terminalized.
            exc.retryable = False
            exc.terminal = True
            raise
        except Exception as exc:
            raise PaymentError(
                "FACILITATOR_UNAVAILABLE",
                "payment settlement outcome is unknown and requires reconciliation",
                status=502,
                terminal=True,
            ) from exc
        if not settled.success:
            raise PaymentError(
                "PAYMENT_NOT_SETTLED",
                "payment could not be settled",
                status=402,
                terminal=True,
            )
        if settled.network != self.config.network:
            raise PaymentError(
                "FACILITATOR_INVALID_RESPONSE",
                "payment receipt did not match the configured network",
                status=502,
                terminal=True,
            )
        if settled.amount is not None and settled.amount != self.config.amount:
            raise PaymentError(
                "FACILITATOR_INVALID_RESPONSE",
                "payment receipt did not match the configured amount",
                status=502,
                terminal=True,
            )
        if not TX_HASH_RE.fullmatch(settled.transaction):
            raise PaymentError(
                "FACILITATOR_INVALID_RESPONSE",
                "payment receipt did not contain a Base transaction hash",
                status=502,
                terminal=True,
            )
        if settled.payer is not None and not ADDRESS_RE.fullmatch(settled.payer):
            raise PaymentError(
                "FACILITATOR_INVALID_RESPONSE",
                "payment receipt did not contain a valid payer",
                status=502,
                terminal=True,
            )
        if (
            verified_payment.payer is not None
            and settled.payer is not None
            and not hmac.compare_digest(
                verified_payment.payer.lower(),
                settled.payer.lower(),
            )
        ):
            raise PaymentError(
                "FACILITATOR_INVALID_RESPONSE",
                "payment receipt payer did not match the verified payer",
                status=502,
                terminal=True,
            )

        # Only protocol-essential receipt fields cross back into an HTTP
        # header. Facilitator extensions are intentionally omitted so an
        # upstream cannot inflate or inject model-facing response metadata.
        receipt_payer = settled.payer or verified_payment.payer
        receipt_model = SettleResponse(
            success=True,
            payer=receipt_payer,
            transaction=settled.transaction,
            network=settled.network,
            amount=settled.amount or self.config.amount,
        )
        response_header = encode_payment_response_header(receipt_model)
        if len(response_header.encode("ascii")) > MAX_PAYMENT_HEADER_BYTES:
            raise PaymentError(
                "FACILITATOR_INVALID_RESPONSE",
                "payment receipt exceeded its response-header limit",
                status=502,
                terminal=True,
            )
        return PaymentReceipt(
            payer=receipt_payer,
            transaction=settled.transaction,
            network=settled.network,
            amount=settled.amount or self.config.amount,
            response_header=response_header,
            proof_fingerprint=verified_payment.proof_fingerprint,
        )

    async def verify_and_settle(self, payment_signature: str) -> PaymentReceipt:
        """Convenience path for callers without resource work between phases."""
        verified = await self.verify(payment_signature)
        return await self.settle(verified)
