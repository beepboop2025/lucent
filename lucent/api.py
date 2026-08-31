"""Versioned HTTP API for Lucent's static Clear Signing analysis.

Run locally with::

    uvicorn lucent.api:app --host 127.0.0.1 --port 8780

Authentication, quotas, finalized-source provenance, and x402 settlement are
feature-gated deployment layers. Simulation and attestation signing remain
outside this process. No request may supply an RPC or facilitator URL.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import time
import uuid
from enum import StrEnum
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import access, hosted, payments, preflight, verified_source

LOGGER = logging.getLogger("lucent.api")
if not LOGGER.handlers:
    logging.basicConfig(level=os.environ.get("LUCENT_LOG_LEVEL", "INFO").upper())

MAX_BODY_BYTES = preflight.MAX_TRANSPORT_BODY_BYTES
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,96}$")
FULL_GIT_OBJECT_ID_RE = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
FLEET_RELEASE_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
_CACHED_PAYMENT_PROOF_HEADER = "Lucent-Internal-Payment-Proof"


class MaxBodySizeMiddleware:
    """Reject oversized fixed-length and chunked request bodies before parsing."""

    def __init__(self, app, max_bytes: int = MAX_BODY_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    await self._reject(scope, send)
                    return
            except ValueError:
                pass

        received = 0
        messages = []
        while True:
            message = await receive()
            messages.append(message)
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    await self._reject(scope, send)
                    return
                if not message.get("more_body", False):
                    break
            elif message.get("type") == "http.disconnect":
                break

        index = 0

        async def replay_receive():
            nonlocal index
            if index < len(messages):
                message = messages[index]
                index += 1
                return message
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)

    async def _reject(self, scope, send):
        request_headers = {key.lower(): value for key, value in scope.get("headers", [])}
        supplied = request_headers.get(b"x-request-id", b"").decode("ascii", errors="ignore")
        state_request_id = scope.get("state", {}).get("request_id")
        request_id = (
            state_request_id
            if isinstance(state_request_id, str)
            else supplied
            if REQUEST_ID_RE.fullmatch(supplied)
            else "req_" + uuid.uuid4().hex
        )
        response = JSONResponse(
            {
                "type": "about:blank",
                "title": "Payload Too Large",
                "status": 413,
                "code": "REQUEST_TOO_LARGE",
                "detail": f"request body may not exceed {self.max_bytes} bytes",
                "request_id": request_id,
            },
            status_code=413,
            media_type="application/problem+json",
            headers={
                "X-Request-ID": request_id,
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
            },
        )

        async def empty_receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        await response(scope, empty_receive, send)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UnsignedCall(StrictModel):
    chain_id: int = Field(gt=0, description="Positive EVM chain id")
    from_address: str = Field(
        alias="from",
        description="0x-prefixed 20-byte sender address used as msg.sender",
    )
    to: str = Field(description="0x-prefixed 20-byte contract address")
    data: str = Field(description="0x-prefixed calldata with a four-byte selector")
    value: int | str = Field(
        default="0x0",
        description="Native value as a non-negative integer or canonical hex quantity",
    )


class PreflightRequest(StrictModel):
    transaction: UnsignedCall
    descriptor: dict[str, Any]


class Gate(StrEnum):
    SAFE_TO_PRESENT = "safe_to_present"
    REVIEW = "review"
    BLOCK = "block"


class VerdictCode(StrEnum):
    PRESENTATION_CLEAR = "PRESENTATION_CLEAR"
    MISSING_CLEAR_SIGNING_FORMAT = "MISSING_CLEAR_SIGNING_FORMAT"
    PRESENTATION_CRITICAL = "PRESENTATION_CRITICAL"
    DANGER_CRITICAL = "DANGER_CRITICAL"
    COMPREHENSION_REVIEW = "COMPREHENSION_REVIEW"
    UNLIMITED_APPROVAL = "UNLIMITED_APPROVAL"
    PRESENTATION_REVIEW = "PRESENTATION_REVIEW"
    DANGER_REVIEW = "DANGER_REVIEW"
    NONPAYABLE_WITH_VALUE = "NONPAYABLE_WITH_VALUE"
    PRESENTATION_UNBOUND = "PRESENTATION_UNBOUND"


class VerdictResponse(ResponseModel):
    gate: Gate
    code: VerdictCode
    reason: str


class DecodedArgumentResponse(ResponseModel):
    name: str
    type: str
    value: Any


class CallResponse(ResponseModel):
    chain_id: int
    from_address: str = Field(alias="from")
    to: str
    selector: str
    function: str
    value: str
    decoded_arguments: list[DecodedArgumentResponse]


class PresentationResponse(ResponseModel):
    sentence_template: str
    tier: str
    reason: str
    source: str
    descriptor_prose_included: bool
    descriptor_text_is_untrusted: bool


class BindingResponse(ResponseModel):
    complete: bool
    findings: list[dict[str, Any]]


class ChecksResponse(ResponseModel):
    audit: dict[str, Any]
    comprehension: dict[str, Any]
    presentation_binding: BindingResponse
    danger: dict[str, Any]


class AssuranceResponse(ResponseModel):
    descriptor_source: str
    abi_source: str
    descriptor_semantics_verified: bool
    deployment_match: bool
    sender_bound: bool
    selector_and_calldata_decoded: bool
    bytecode_verified: bool
    runtime_simulated: bool
    verified_source: VerifiedSourceResponse | None = None


class BlockIdentityResponse(ResponseModel):
    number: int
    hash: str


class CodeIdentityResponse(ResponseModel):
    address: str
    keccak256: str
    size_bytes: int


class ProxyHopResponse(ResponseModel):
    proxy: CodeIdentityResponse
    kind: str
    implementation_address: str
    beacon: CodeIdentityResponse | None = None


class VerifiedSourceResponse(ResponseModel):
    provider: str
    chain_id: int
    address: str
    block: BlockIdentityResponse
    target: CodeIdentityResponse
    effective_contract: CodeIdentityResponse
    proxy_chain: list[ProxyHopResponse]
    verification_match: str
    abi_hash: str


class PreflightResponse(ResponseModel):
    api_version: str
    policy_version: str
    analysis_scope: str
    call_fingerprint: str
    assessment_fingerprint: str
    call: CallResponse
    verdict: VerdictResponse
    presentation: PresentationResponse
    checks: ChecksResponse
    assurance: AssuranceResponse
    limitations: list[str]
    request_id: str


class ProblemError(ResponseModel):
    location: list[str]
    message: str
    type: str


class ProblemResponse(ResponseModel):
    type: str
    title: str
    status: int
    code: str
    detail: str
    request_id: str | None = None
    errors: list[ProblemError] | None = None
    retry_after_seconds: float | None = None
    limit: int | None = None
    remaining: int | None = None


def _problem_response(description: str) -> dict:
    return {
        "description": description,
        "model": ProblemResponse,
        "content": {
            "application/problem+json": {
                "schema": {"$ref": "#/components/schemas/ProblemResponse"},
            }
        },
    }


PREFLIGHT_ERROR_RESPONSES = {
    400: _problem_response("Malformed JSON"),
    401: _problem_response("API-key authentication failed"),
    402: _problem_response("An x402 v2 payment is required or was rejected"),
    409: _problem_response("Idempotency state conflicts with this request"),
    413: _problem_response("Request body exceeds the transport limit"),
    422: _problem_response("Call or descriptor input was rejected"),
    429: _problem_response("Tenant quota was exhausted"),
    500: _problem_response("Analysis failed without a verdict"),
    502: _problem_response("A payment facilitator returned no usable result"),
    503: _problem_response("A required provenance or access dependency is unavailable"),
}


app = FastAPI(
    title="Lucent Preflight API",
    summary="Call-scoped, fail-closed Clear Signing analysis for EVM wallets and agents.",
    description=(
        "Lucent determines whether one unsigned EVM call is clear enough to present to a "
        "signer. It does not certify that executing the call is safe. Every assessment "
        "states its evidence boundary and unsupported guarantees."
    ),
    version="0.2.1",
    docs_url="/docs",
    redoc_url=None,
    openapi_url="/openapi.json",
)
app.add_middleware(MaxBodySizeMiddleware)
app.state.runtime = hosted.HostedRuntime.from_env()


def _openapi_schema() -> dict:
    """Keep documented error media types identical to runtime responses."""
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        summary=app.summary,
        description=app.description,
        routes=app.routes,
    )
    operation = schema["paths"]["/v1/preflight"]["post"]
    for status in PREFLIGHT_ERROR_RESPONSES:
        operation["responses"][str(status)]["content"].pop("application/json", None)
    app.openapi_schema = schema
    return schema


app.openapi = _openapi_schema


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "req_unknown")


def _problem(
    request: Request,
    *,
    status: int,
    code: str,
    title: str,
    detail: str,
    errors: list[dict] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {
        "type": "about:blank",
        "title": title,
        "status": status,
        "code": code,
        "detail": detail,
        "request_id": _request_id(request),
    }
    if errors:
        body["errors"] = errors
    return JSONResponse(
        body,
        status_code=status,
        media_type="application/problem+json",
        headers=headers,
    )


@app.middleware("http")
async def request_context(request: Request, call_next):
    supplied = request.headers.get("x-request-id", "")
    request.state.request_id = (
        supplied if REQUEST_ID_RE.fullmatch(supplied) else "req_" + uuid.uuid4().hex
    )
    started = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Server-Timing"] = f"app;dur={elapsed_ms}"
    LOGGER.info(json.dumps({
        "event": "request_complete",
        "request_id": request.state.request_id,
        "method": request.method,
        "path": request.url.path,
        "status": response.status_code,
        "duration_ms": elapsed_ms,
    }, separators=(",", ":")))
    return response


@app.exception_handler(preflight.PreflightInputError)
async def preflight_input_error(request: Request, exc: preflight.PreflightInputError):
    return _problem(
        request,
        status=422,
        code=exc.code,
        title="Preflight Input Rejected",
        detail=exc.message,
    )


@app.exception_handler(access.AccessError)
async def access_error(request: Request, exc: access.AccessError):
    return JSONResponse(
        exc.as_problem(request_id=_request_id(request)),
        status_code=exc.status_code,
        media_type="application/problem+json",
        headers=exc.response_headers,
    )


@app.exception_handler(payments.PaymentError)
async def payment_error(request: Request, exc: payments.PaymentError):
    runtime: hosted.HostedRuntime = request.app.state.runtime
    return _problem(
        request,
        status=exc.status,
        code=exc.code,
        title="Payment Required" if exc.status == 402 else "Payment Dependency Failed",
        detail=exc.message,
        headers=_payment_failure_headers(runtime, exc),
    )


def _payment_failure_headers(
    runtime: hosted.HostedRuntime,
    exc: payments.PaymentError,
) -> dict[str, str]:
    headers: dict[str, str] = {}
    if exc.status == 402 and runtime.payments is not None:
        challenge = runtime.payments.challenge(error=exc.code)
        headers[payments.PAYMENT_REQUIRED_HEADER] = challenge.header_value
    if exc.retryable and not exc.terminal:
        headers["Retry-After"] = "2"
    return headers


_SOURCE_INPUT_CODES = {
    "INVALID_CHAIN_ID",
    "UNSUPPORTED_CHAIN",
    "INVALID_ADDRESS",
    "NO_CONTRACT_CODE",
    "INVALID_PROXY_SLOT",
    "INVALID_PROXY_BEACON",
    "AMBIGUOUS_PROXY",
    "PROXY_CYCLE",
    "PROXY_DEPTH_EXCEEDED",
    "PROXY_SEMANTICS_UNVERIFIED",
    "UNSUPPORTED_DISPATCH",
    "SOURCE_NOT_VERIFIED",
    "SOURCE_NOT_RUNTIME_VERIFIED",
}


@app.exception_handler(verified_source.VerifiedSourceError)
async def verified_source_error(request: Request, exc: verified_source.VerifiedSourceError):
    is_input = exc.code in _SOURCE_INPUT_CODES
    return _problem(
        request,
        status=422 if is_input else 503,
        code=exc.code,
        title="Verified Source Rejected" if is_input else "Verified Source Unavailable",
        detail=exc.message,
        headers={} if is_input else {"Retry-After": "2"},
    )


@app.exception_handler(RequestValidationError)
async def request_validation_error(request: Request, exc: RequestValidationError):
    errors = [
        {
            "location": [str(part) for part in item.get("loc", [])],
            "message": item.get("msg", "invalid value"),
            "type": item.get("type", "validation_error"),
        }
        for item in exc.errors()
    ]
    malformed_json = any(item["type"] == "json_invalid" for item in errors)
    return _problem(
        request,
        status=400 if malformed_json else 422,
        code="MALFORMED_JSON" if malformed_json else "REQUEST_VALIDATION_FAILED",
        title="Malformed JSON" if malformed_json else "Request Validation Failed",
        detail="request body is not valid JSON" if malformed_json else "request fields are invalid",
        errors=errors,
    )


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    malformed_body = exc.status_code == 400
    return _problem(
        request,
        status=exc.status_code,
        code="MALFORMED_JSON" if malformed_body else "HTTP_ERROR",
        title="Malformed JSON" if malformed_body else "HTTP Error",
        detail="request body is not valid JSON" if malformed_body else str(exc.detail),
    )


@app.exception_handler(Exception)
async def internal_error(request: Request, exc: Exception):
    LOGGER.error(json.dumps({
        "event": "request_failed",
        "request_id": _request_id(request),
        "error_type": type(exc).__name__,
    }, separators=(",", ":")))
    return _problem(
        request,
        status=500,
        code="INTERNAL_ERROR",
        title="Internal Server Error",
        detail="analysis failed without producing a verdict",
    )


def _canonical_request_fingerprint(payload: PreflightRequest) -> str:
    try:
        body = json.dumps(
            payload.model_dump(by_alias=True),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise preflight.PreflightInputError(
            "INVALID_REQUEST",
            "request body could not be canonically fingerprinted",
        ) from exc
    return access.fingerprint_request(body)


def _assessment_fingerprint(result: dict[str, Any]) -> str:
    """Bind the complete decision, policy, and provenance evidence."""
    try:
        body = json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise RuntimeError("assessment could not be canonically fingerprinted") from exc
    return "sha256:" + hashlib.sha256(body).hexdigest()


def _verified_source_summary(
    source: verified_source.VerifiedSourceResult,
) -> dict[str, Any]:
    return {
        "provider": "sourcify_v2",
        "chain_id": source.chain_id,
        "address": source.address,
        "block": source.block.to_dict(),
        "target": source.target.to_dict(),
        "effective_contract": source.effective_contract.to_dict(),
        "proxy_chain": [hop.to_dict() for hop in source.proxy_chain],
        "verification_match": source.verification_match,
        "abi_hash": source.abi_hash,
    }


async def _bind_verified_source(
    request_data: dict[str, Any],
    baseline: dict[str, Any],
    runtime: hosted.HostedRuntime,
) -> dict[str, Any]:
    if runtime.verified_sources is None:
        return baseline
    transaction = request_data["transaction"]
    source = await run_in_threadpool(
        runtime.verified_sources.resolve,
        transaction["chain_id"],
        transaction["to"],
    )
    if (
        source.chain_id != transaction["chain_id"]
        or source.address.lower() != transaction["to"].lower()
        or (not source.proxy_chain and source.effective_contract != source.target)
    ):
        raise verified_source.VerifiedSourceError(
            "SOURCE_IDENTITY_MISMATCH",
            "verified source evidence did not match the requested deployment",
        )
    if source.proxy_chain:
        raise verified_source.VerifiedSourceError(
            "PROXY_SEMANTICS_UNVERIFIED",
            "hosted V1 does not clear upgradeable or proxy-backed deployments",
        )
    # The caller's descriptor still supplies display rules, but the function
    # surface used for decoding and policy comes only from the bytecode-bound ABI.
    request_data["descriptor"]["context"]["contract"]["abi"] = source.abi
    result = preflight.preflight_transaction(request_data)
    result["assurance"].update({
        "abi_source": "sourcify_v2_finalized_runtime",
        "bytecode_verified": True,
        "verified_source": _verified_source_summary(source),
    })
    result["limitations"] = [
        "The descriptor's display rules remain caller-supplied and are not a provenance claim.",
        "ABI and runtime bytecode were bound through Sourcify at one finalized block.",
        "Hosted V1 clears only direct deployments; proxy-backed contracts are rejected.",
        *[
            item
            for item in result["limitations"]
            if not item.startswith("Static analysis of one caller-supplied")
            and not item.startswith("Does not inspect bytecode")
        ],
    ]
    return result


def _quota_headers(grant: access.AccessGrant) -> dict[str, str]:
    return {
        "X-RateLimit-Limit": str(grant.quota.limit),
        "X-RateLimit-Remaining": str(grant.quota.remaining),
        "X-RateLimit-Reset": str(max(0, math.ceil(grant.quota.reset_after_seconds))),
    }


def _replay_response(
    request: Request,
    cached: access.IdempotencyResponse,
    *,
    payment_signature: str | None = None,
    header_overrides: dict[str, str] | None = None,
) -> Response:
    # Preserve the cached business result and payment receipt while giving this
    # transport attempt its own trace identifier.
    body = json.loads(cached.body)
    body["request_id"] = _request_id(request)
    rendered = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = dict(cached.headers)
    expected_proof = headers.pop(_CACHED_PAYMENT_PROOF_HEADER, None)
    if expected_proof is not None:
        if payment_signature is None:
            raise payments.PaymentError(
                "PAYMENT_REPLAY_PROOF_MISMATCH",
                "paid replay requires the original payment proof",
                status=402,
            )
        payments.PaymentGateway.assert_replay_proof(payment_signature, expected_proof)
    headers["Idempotency-Replayed"] = "true"
    if header_overrides:
        headers.update(header_overrides)
    headers.setdefault("Content-Type", "application/json")
    return Response(content=rendered, status_code=cached.status_code, headers=headers)


def _payment_required(request: Request) -> JSONResponse:
    runtime: hosted.HostedRuntime = request.app.state.runtime
    if runtime.payments is None:
        raise access.AuthenticationError
    challenge = runtime.payments.challenge()
    return _problem(
        request,
        status=402,
        code="PAYMENT_REQUIRED",
        title="Payment Required",
        detail=(
            "submit an x402 v2 PAYMENT-SIGNATURE and a unique Idempotency-Key "
            "for this preflight request"
        ),
        headers={payments.PAYMENT_REQUIRED_HEADER: challenge.header_value},
    )


def _commit_terminal_payment_failure(
    request: Request,
    runtime: hosted.HostedRuntime,
    store: access.IdempotencyStore,
    reservation: access.IdempotencyReservation,
    verified_payment: payments.VerifiedPayment,
    exc: payments.PaymentError,
) -> None:
    body = json.dumps({
        "type": "about:blank",
        "title": (
            "Payment Required" if exc.status == 402 else "Payment Dependency Failed"
        ),
        "status": exc.status,
        "code": exc.code,
        "detail": exc.message,
        "request_id": _request_id(request),
    }, separators=(",", ":")).encode("utf-8")
    headers = {
        "Content-Type": "application/problem+json",
        _CACHED_PAYMENT_PROOF_HEADER: verified_payment.proof_fingerprint,
        **_payment_failure_headers(runtime, exc),
    }
    terminal = access.IdempotencyResponse.from_parts(exc.status, body, headers)
    try:
        store.commit(reservation, terminal)
    except access.AccessError:
        # Never release the reservation after settlement was attempted. A live
        # tombstone is safer than permitting a second side effect.
        LOGGER.error(json.dumps({
            "event": "payment_terminal_commit_failed",
            "request_id": _request_id(request),
            "code": exc.code,
        }, separators=(",", ":")))


def _commit_payment_claim(
    request: Request,
    store: access.IdempotencyStore,
    reservation: access.IdempotencyReservation,
) -> None:
    """Persist a non-sensitive write-ahead tombstone before settlement."""
    tombstone = access.IdempotencyResponse.from_parts(
        204,
        b"",
        {"Content-Type": "application/octet-stream"},
    )
    try:
        store.commit(reservation, tombstone)
    except access.AccessError:
        LOGGER.error(json.dumps({
            "event": "payment_claim_commit_failed",
            "request_id": _request_id(request),
        }, separators=(",", ":")))
        raise


@app.get("/", include_in_schema=False)
def index(request: Request) -> dict:
    return {
        "service": "lucent",
        "version": app.version,
        "docs": "/docs",
        "health": "/health",
        "primary_endpoint": "/v1/preflight",
        "request_id": _request_id(request),
    }


@app.get("/health", tags=["operations"])
def health(request: Request) -> dict | JSONResponse:
    identity, identity_valid = _runtime_identity()
    payload = {
        "status": "ok" if identity_valid else "unavailable",
        "service": "lucent",
        "version": app.version,
        "policy_version": preflight.POLICY_VERSION,
        **identity,
        "request_id": _request_id(request),
    }
    if not identity_valid:
        return JSONResponse(payload, status_code=503)
    return payload


def _runtime_identity() -> tuple[dict[str, str | None], bool]:
    source_commit = os.environ.get("FLEET_SOURCE_COMMIT", "")
    release_id = os.environ.get("FLEET_RELEASE_ID", "")
    railway_runtime = bool(os.environ.get("RAILWAY_ENVIRONMENT_NAME"))
    if FULL_GIT_OBJECT_ID_RE.fullmatch(source_commit) and FLEET_RELEASE_ID_RE.fullmatch(
        release_id
    ):
        return {
            "identity_status": "verified",
            "source_commit": source_commit,
            "release_id": release_id,
        }, True
    if not source_commit and not release_id and not railway_runtime:
        return {
            "identity_status": "local",
            "source_commit": None,
            "release_id": None,
        }, True
    return {
        "identity_status": "invalid",
        "source_commit": None,
        "release_id": None,
    }, False


@app.get("/ready", tags=["operations"])
def ready(request: Request) -> dict | JSONResponse:
    identity, identity_valid = _runtime_identity()
    if not identity_valid:
        return JSONResponse(
            {
                "status": "unavailable",
                "service": "lucent",
                **identity,
                "request_id": _request_id(request),
            },
            status_code=503,
        )
    runtime: hosted.HostedRuntime = request.app.state.runtime
    if runtime.settings.access_mode is hosted.AccessMode.DISABLED:
        return _problem(
            request,
            status=503,
            code="SERVICE_NOT_CONFIGURED",
            title="Service Not Configured",
            detail="select an explicit protected access mode before serving traffic",
        )
    return {
        "status": "ready",
        "service": "lucent",
        **identity,
        **runtime.readiness(),
        "request_id": _request_id(request),
    }


@app.post(
    "/v1/preflight",
    tags=["preflight"],
    response_model=PreflightResponse,
    responses=PREFLIGHT_ERROR_RESPONSES,
)
async def transaction_preflight(payload: PreflightRequest, request: Request) -> Response:
    runtime: hosted.HostedRuntime = request.app.state.runtime
    mode = runtime.settings.access_mode
    request_fingerprint = _canonical_request_fingerprint(payload)
    idempotency_key = request.headers.get("idempotency-key")
    api_key = request.headers.get("x-api-key")
    payment_signature = request.headers.get(payments.PAYMENT_SIGNATURE_HEADER)

    if mode is hosted.AccessMode.DISABLED:
        return _problem(
            request,
            status=503,
            code="SERVICE_NOT_CONFIGURED",
            title="Service Not Configured",
            detail="select an explicit protected access mode before serving traffic",
        )

    access_label = "open"
    response_headers: dict[str, str] = {"X-Lucent-Access": access_label}
    reservation: access.IdempotencyReservation | None = None
    idempotency_store: access.IdempotencyStore | None = None
    paid_request = False

    if mode is not hosted.AccessMode.OPEN:
        if api_key is not None and mode.uses_api_keys:
            assert runtime.access is not None
            tenant = runtime.access.authenticate(api_key)
            quota = runtime.access.quotas.consume(tenant.tenant_id)
            grant = access.AccessGrant(tenant=tenant, quota=quota)
            access_label = "api_key"
            response_headers = {
                "X-Lucent-Access": access_label,
                **_quota_headers(grant),
            }
            decision = runtime.access.reserve_idempotency(
                tenant,
                idempotency_key,
                request_fingerprint,
            )
            if decision.is_replay:
                assert decision.response is not None
                return _replay_response(
                    request,
                    decision.response,
                    header_overrides=response_headers,
                )
            reservation = decision.reservation
            idempotency_store = runtime.access.idempotency
            assert reservation is not None
        elif mode is hosted.AccessMode.API_KEY:
            assert runtime.access is not None
            runtime.access.authenticate(None)
        else:
            if payment_signature is None:
                return _payment_required(request)
            assert runtime.payment_idempotency is not None
            decision = runtime.payment_idempotency.reserve(
                "x402",
                idempotency_key,
                request_fingerprint,
            )
            if decision.is_replay:
                assert decision.response is not None
                return _replay_response(
                    request,
                    decision.response,
                    payment_signature=payment_signature,
                )
            reservation = decision.reservation
            idempotency_store = runtime.payment_idempotency
            assert reservation is not None
            access_label = "x402"
            response_headers = {"X-Lucent-Access": access_label}
            paid_request = True

    verified_payment: payments.VerifiedPayment | None = None
    claim_reservation: access.IdempotencyReservation | None = None
    claim_store: access.IdempotencyStore | None = None
    settlement_attempted = False
    try:
        request_data = payload.model_dump(by_alias=True)
        # This first pure pass rejects malformed descriptors/calldata without
        # consuming facilitator or provenance capacity.
        baseline = preflight.preflight_transaction(request_data)
        if paid_request:
            assert runtime.payments is not None and payment_signature is not None
            if request_data["transaction"]["chain_id"] not in verified_source.RPC_ENDPOINTS:
                raise verified_source.VerifiedSourceError(
                    "UNSUPPORTED_CHAIN",
                    "chain_id is not enabled for verified resolution",
                )
            verified_payment = await runtime.payments.verify(
                payment_signature,
                payment_identifier=idempotency_key,
            )
            assert runtime.payment_claims is not None
            claim_decision = runtime.payment_claims.reserve(
                "x402-authorization",
                verified_payment.authorization_fingerprint,
                request_fingerprint,
            )
            if claim_decision.is_replay:
                raise payments.PaymentError(
                    "PAYMENT_AUTHORIZATION_ALREADY_USED",
                    "this payment authorization has already been consumed",
                    status=409,
                    terminal=True,
                )
            claim_reservation = claim_decision.reservation
            claim_store = runtime.payment_claims
            assert claim_reservation is not None

        result = await _bind_verified_source(request_data, baseline, runtime)
        result["assessment_fingerprint"] = _assessment_fingerprint(result)
        response_model = PreflightResponse.model_validate({
            **result,
            "request_id": _request_id(request),
        })
        body = response_model.model_dump_json(
            by_alias=True,
            exclude_none=True,
        ).encode("utf-8")
        if len(body) > hosted.MAX_CACHED_RESULT_BYTES:
            raise RuntimeError("bounded preflight response exceeded cache capacity")

        if paid_request:
            assert runtime.payments is not None and verified_payment is not None
            assert claim_reservation is not None and claim_store is not None
            # Write ahead before submitting the irreversible side effect. This
            # remains complete even if task cancellation bypasses Exception
            # handlers while an underlying settlement thread continues.
            _commit_payment_claim(request, claim_store, claim_reservation)
            settlement_attempted = True
            try:
                receipt = await runtime.payments.settle(verified_payment)
            except payments.PaymentError as exc:
                assert reservation is not None and idempotency_store is not None
                _commit_terminal_payment_failure(
                    request,
                    runtime,
                    idempotency_store,
                    reservation,
                    verified_payment,
                    exc,
                )
                raise
            response_headers[payments.PAYMENT_RESPONSE_HEADER] = receipt.response_header

        response_headers["Content-Type"] = "application/json"
        cached_headers = dict(response_headers)
        if paid_request:
            assert verified_payment is not None
            cached_headers[_CACHED_PAYMENT_PROOF_HEADER] = (
                verified_payment.proof_fingerprint
            )
        cached = access.IdempotencyResponse.from_parts(200, body, cached_headers)
        if reservation is not None and idempotency_store is not None:
            try:
                idempotency_store.commit(reservation, cached)
            except access.AccessError:
                # Settlement already succeeded (or this was API-key access), so
                # return the completed result even if replay persistence expired.
                LOGGER.error(json.dumps({
                    "event": "idempotency_commit_failed",
                    "request_id": _request_id(request),
                    "access": access_label,
                    "settlement_attempted": settlement_attempted,
                }, separators=(",", ":")))
                if not settlement_attempted:
                    idempotency_store.abort(reservation)
        return Response(content=body, status_code=200, headers=response_headers)
    except Exception:
        if (
            reservation is not None
            and idempotency_store is not None
            and not settlement_attempted
        ):
            idempotency_store.abort(reservation)
        if (
            claim_reservation is not None
            and claim_store is not None
            and not settlement_attempted
        ):
            claim_store.abort(claim_reservation)
        raise
