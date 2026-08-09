"""Bound an EVM deployment to finalized bytecode and a verified Sourcify ABI.

This module is deliberately separate from the request-time preflight service.  A
successful resolution proves a narrow provenance chain:

* a module-owned JSON-RPC endpoint reported the requested chain and a finalized
  block;
* runtime bytecode and EIP-1967 implementation state were read at that block;
* Sourcify returned a runtime verification for the effective implementation;
* Sourcify's recorded on-chain bytecode exactly matched the pinned RPC bytecode.

The network transport is injectable for deterministic tests, but destinations,
timeouts, response limits, and request shapes are not caller configurable.  All
public errors are stable and redacted; upstream exception text and URLs never
become result data.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol, cast

from eth_utils import keccak

MAX_CHAIN_ID = (1 << 63) - 1
MAX_CODE_BYTES = 128 * 1024
MAX_ABI_BYTES = 1024 * 1024
MAX_ABI_ENTRIES = 1_024
MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 100_000
MAX_JSON_STRING_LENGTH = (2 * MAX_CODE_BYTES) + 2
MAX_HTTP_REQUESTS = 32
MAX_RPC_CALLS = 28
MAX_PROXY_HOPS = 4
RPC_RESPONSE_BYTES = (2 * MAX_CODE_BYTES) + (64 * 1024)
SOURCIFY_RESPONSE_BYTES = MAX_ABI_BYTES + (2 * MAX_CODE_BYTES) + (256 * 1024)
REQUEST_TIMEOUT_SECONDS = 4.0
TOTAL_TIMEOUT_SECONDS = 24.0

# Deliberately small. Adding a chain is a reviewed code change, never request or
# environment configuration. These endpoints require no credentials.
RPC_ENDPOINTS: Mapping[int, str] = MappingProxyType(
    {
        1: "https://ethereum-rpc.publicnode.com",
        8453: "https://mainnet.base.org",
    }
)

SOURCIFY_CONTRACT = (
    "https://sourcify.dev/server/v2/contract/{chain_id}/{address}"
    "?fields=abi,runtimeBytecode.onchainBytecode"
)

# keccak256("eip1967.proxy.implementation") - 1
EIP1967_IMPLEMENTATION_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
# keccak256("eip1967.proxy.beacon") - 1
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
BEACON_IMPLEMENTATION_SELECTOR = "0x5c60da1b"

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
HEX_DATA_RE = re.compile(r"^0x(?:[0-9a-fA-F]{2})*$")
HEX_QUANTITY_RE = re.compile(r"^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$")
ABI_KINDS = frozenset({"constructor", "error", "event", "fallback", "function", "receive"})
NAMED_ABI_KINDS = frozenset({"error", "event", "function"})
VERIFIED_MATCHES = frozenset({"exact_match", "match"})
UNSUPPORTED_DISPATCH_OPCODES = frozenset({0xF2, 0xF4})  # CALLCODE, DELEGATECALL
SOLIDITY_METADATA_KEYS = frozenset({"ipfs", "bzzr0", "bzzr1", "experimental", "solc"})
SOLC_PRERELEASE_RE = re.compile(rb"^[0-9][0-9A-Za-z.+-]{2,95}$")


class VerifiedSourceError(RuntimeError):
    """A fail-closed resolution error safe to return across a service boundary."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True, slots=True)
class HttpRequest:
    """One bounded request passed to an injected transport."""

    method: str
    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes | None
    timeout_seconds: float
    max_response_bytes: int


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """Minimal transport response; only headers needed for safe JSON parsing matter."""

    status: int
    headers: Mapping[str, str]
    body: bytes


class Transport(Protocol):
    def __call__(self, request: HttpRequest) -> HttpResponse: ...


@dataclass(frozen=True, slots=True)
class BlockIdentity:
    number: int
    hash: str

    def to_dict(self) -> dict[str, int | str]:
        return {"number": self.number, "hash": self.hash}


@dataclass(frozen=True, slots=True)
class CodeIdentity:
    address: str
    keccak256: str
    size_bytes: int

    def to_dict(self) -> dict[str, int | str]:
        return {
            "address": self.address,
            "keccak256": self.keccak256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True, slots=True)
class ProxyHop:
    proxy: CodeIdentity
    kind: str
    implementation_address: str
    beacon: CodeIdentity | None = None

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "proxy": self.proxy.to_dict(),
            "kind": self.kind,
            "implementation_address": self.implementation_address,
        }
        if self.beacon is not None:
            result["beacon"] = self.beacon.to_dict()
        return result


@dataclass(frozen=True, slots=True)
class VerifiedSourceResult:
    """Immutable provenance metadata with an ABI returned as a defensive copy.

    ``target`` is always the requested deployment. ``effective_contract`` is
    the final EIP-1967 implementation (or the target for a direct deployment).
    ``abi_hash`` binds the exact canonical JSON exposed through ``abi``.
    """

    chain_id: int
    address: str
    block: BlockIdentity
    target: CodeIdentity
    effective_contract: CodeIdentity
    proxy_chain: tuple[ProxyHop, ...]
    verification_match: str
    abi_hash: str
    _abi_json: bytes = field(repr=False)

    @property
    def abi(self) -> list[dict[str, Any]]:
        return cast(list[dict[str, Any]], json.loads(self._abi_json))

    @property
    def block_number(self) -> int:
        return self.block.number

    @property
    def block_hash(self) -> str:
        return self.block.hash

    @property
    def code_hash(self) -> str:
        return self.target.keccak256

    @property
    def implementation_address(self) -> str | None:
        return self.effective_contract.address if self.proxy_chain else None

    @property
    def implementation_code_hash(self) -> str | None:
        return self.effective_contract.keccak256 if self.proxy_chain else None

    @property
    def abi_address(self) -> str:
        return self.effective_contract.address

    @property
    def cache_size_bytes(self) -> int:
        """Canonical encoded size of the complete cacheable result.

        This is a stable accounting unit, not an estimate of Python object
        overhead. It includes provenance metadata and the bytecode-bound ABI
        without exposing the private canonical ABI storage to consumers.
        """

        encoded = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
        return len(encoded)

    def to_dict(self) -> dict[str, object]:
        return {
            "chain_id": self.chain_id,
            "address": self.address,
            "block": self.block.to_dict(),
            "target": self.target.to_dict(),
            "proxy_chain": [hop.to_dict() for hop in self.proxy_chain],
            "abi_binding": {
                "provider": "sourcify_v2",
                "address": self.effective_contract.address,
                "runtime_code_hash": self.effective_contract.keccak256,
                "runtime_code_size_bytes": self.effective_contract.size_bytes,
                "match": self.verification_match,
                "abi_hash": self.abi_hash,
                "abi": self.abi,
            },
        }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None


class _TransportLimitError(Exception):
    pass


# Do not inherit HTTP(S)_PROXY environment variables. Resolution destinations
# are code-owned and should not be silently replaced by process configuration.
_URL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def _stream_response(request: HttpRequest, response: Any) -> HttpResponse:
    headers = response.headers
    content_type = headers.get("Content-Type", "")
    content_length = headers.get("Content-Length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except (TypeError, ValueError):
            declared = -1
        if declared < 0 or declared > request.max_response_bytes:
            raise _TransportLimitError
    body = response.read(request.max_response_bytes + 1)
    if len(body) > request.max_response_bytes:
        raise _TransportLimitError
    return HttpResponse(
        status=int(response.status),
        headers={"content-type": content_type, "content-length": content_length or ""},
        body=body,
    )


def _urlopen_transport(request: HttpRequest) -> HttpResponse:
    req = urllib.request.Request(
        request.url,
        data=request.body,
        headers=dict(request.headers),
        method=request.method,
    )
    try:
        with _URL_OPENER.open(req, timeout=request.timeout_seconds) as response:
            return _stream_response(request, response)
    except urllib.error.HTTPError as exc:
        # Error bodies can be attacker-controlled and are not needed for a
        # fail-closed decision. Discard them rather than parsing or surfacing them.
        return HttpResponse(status=int(exc.code), headers={}, body=b"")


def _error(code: str, message: str) -> VerifiedSourceError:
    return VerifiedSourceError(code, message)


def _normalize_chain_id(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _error("INVALID_CHAIN_ID", "chain_id must be a positive integer")
    if value < 1 or value > MAX_CHAIN_ID:
        raise _error("INVALID_CHAIN_ID", "chain_id is outside the supported numeric range")
    if value not in RPC_ENDPOINTS:
        raise _error("UNSUPPORTED_CHAIN", "chain_id is not enabled for verified resolution")
    return value


def _normalize_address(value: object) -> str:
    if not isinstance(value, str) or ADDRESS_RE.fullmatch(value) is None:
        raise _error("INVALID_ADDRESS", "address must be exactly 20 hexadecimal bytes")
    return value.lower()


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == wanted:
            return value
    return None


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate_json_shape(value: object) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ValueError("JSON structure exceeds limits")
        if isinstance(item, str):
            if len(item) > MAX_JSON_STRING_LENGTH:
                raise ValueError("JSON string exceeds limit")
        elif isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("JSON object key is not text")
                stack.append((key, depth + 1))
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif item is None or isinstance(item, (bool, int)):
            continue
        elif isinstance(item, float):
            # No expected RPC or ABI field needs floating-point semantics.
            raise ValueError("floating-point JSON is not accepted")
        else:
            raise ValueError("non-JSON value")


def _load_json(body: bytes) -> object:
    try:
        value = json.loads(
            body.decode("utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_object,
        )
        _validate_json_shape(value)
        return value
    except (UnicodeDecodeError, ValueError, RecursionError, json.JSONDecodeError) as exc:
        raise _error("INVALID_UPSTREAM_RESPONSE", "upstream returned invalid bounded JSON") from exc


class _HttpClient:
    def __init__(self, transport: Transport):
        self._transport = transport
        self._deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
        self._requests = 0

    def json(
        self,
        *,
        method: str,
        url: str,
        body: bytes | None,
        max_response_bytes: int,
        not_found_code: str | None = None,
    ) -> object:
        self._requests += 1
        remaining = self._deadline - time.monotonic()
        if self._requests > MAX_HTTP_REQUESTS or remaining <= 0:
            raise _error("UPSTREAM_TIMEOUT", "verified resolution exceeded its hard deadline")
        headers = [
            ("Accept", "application/json"),
            ("User-Agent", "lucent-verified-source/0.2"),
        ]
        if body is not None:
            headers.append(("Content-Type", "application/json"))
        request = HttpRequest(
            method=method,
            url=url,
            headers=tuple(headers),
            body=body,
            timeout_seconds=min(REQUEST_TIMEOUT_SECONDS, remaining),
            max_response_bytes=max_response_bytes,
        )
        try:
            response = self._transport(request)
        except _TransportLimitError:
            raise _error(
                "UPSTREAM_RESPONSE_TOO_LARGE", "upstream response exceeded its hard size limit"
            ) from None
        except Exception:
            raise _error(
                "UPSTREAM_UNAVAILABLE", "a required upstream service was unavailable"
            ) from None

        if not isinstance(response, HttpResponse):
            raise _error("INVALID_UPSTREAM_RESPONSE", "transport returned an invalid response")
        if isinstance(response.status, bool) or not isinstance(response.status, int):
            raise _error("INVALID_UPSTREAM_RESPONSE", "transport returned an invalid status")
        if response.status == 404 and not_found_code is not None:
            raise _error(not_found_code, "no verified runtime source was found")
        if response.status != 200:
            raise _error("UPSTREAM_UNAVAILABLE", "a required upstream service was unavailable")
        if not isinstance(response.headers, Mapping) or not isinstance(response.body, bytes):
            raise _error("INVALID_UPSTREAM_RESPONSE", "transport returned an invalid response")
        if len(response.body) > max_response_bytes:
            raise _error(
                "UPSTREAM_RESPONSE_TOO_LARGE", "upstream response exceeded its hard size limit"
            )

        length = _header(response.headers, "content-length")
        if length not in (None, ""):
            try:
                declared = int(length)
            except (TypeError, ValueError):
                raise _error(
                    "INVALID_UPSTREAM_RESPONSE", "upstream returned an invalid content length"
                ) from None
            if declared < 0 or declared != len(response.body) or declared > max_response_bytes:
                raise _error(
                    "INVALID_UPSTREAM_RESPONSE", "upstream returned an invalid content length"
                )
        content_type = _header(response.headers, "content-type")
        if not isinstance(content_type, str):
            raise _error("INVALID_UPSTREAM_RESPONSE", "upstream response was not JSON")
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type != "application/json" and not media_type.endswith("+json"):
            raise _error("INVALID_UPSTREAM_RESPONSE", "upstream response was not JSON")
        return _load_json(response.body)


class _RpcClient:
    def __init__(self, chain_id: int, http: _HttpClient):
        self._endpoint = RPC_ENDPOINTS[chain_id]
        self._http = http
        self._next_id = 1
        self._calls = 0

    def call(self, method: str, params: list[object]) -> object:
        self._calls += 1
        if self._calls > MAX_RPC_CALLS:
            raise _error("RPC_CALL_LIMIT", "verified resolution exceeded its RPC call limit")
        request_id = self._next_id
        self._next_id += 1
        body = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
            separators=(",", ":"),
        ).encode()
        response = self._http.json(
            method="POST",
            url=self._endpoint,
            body=body,
            max_response_bytes=RPC_RESPONSE_BYTES,
        )
        if not isinstance(response, dict):
            raise _error("INVALID_RPC_RESPONSE", "JSON-RPC response was not an object")
        if response.get("jsonrpc") != "2.0":
            raise _error("INVALID_RPC_RESPONSE", "JSON-RPC version was invalid")
        response_id = response.get("id")
        if isinstance(response_id, bool) or response_id != request_id:
            raise _error("INVALID_RPC_RESPONSE", "JSON-RPC response id did not match")
        if "error" in response or "result" not in response:
            raise _error("RPC_REQUEST_FAILED", "a required JSON-RPC method failed")
        return response["result"]


def _quantity(value: object) -> tuple[int, str]:
    if (
        not isinstance(value, str)
        or len(value) > 66
        or HEX_QUANTITY_RE.fullmatch(value) is None
    ):
        raise _error("INVALID_RPC_RESPONSE", "JSON-RPC quantity was malformed")
    number = int(value, 16)
    return number, hex(number)


def _hash(value: object) -> str:
    if not isinstance(value, str) or HASH_RE.fullmatch(value) is None:
        raise _error("INVALID_RPC_RESPONSE", "JSON-RPC block hash was malformed")
    return value.lower()


def _data(value: object, *, max_bytes: int, field_name: str) -> bytes:
    if not isinstance(value, str) or HEX_DATA_RE.fullmatch(value) is None:
        raise _error("INVALID_RPC_RESPONSE", f"JSON-RPC {field_name} was malformed")
    raw = bytes.fromhex(value[2:])
    if len(raw) > max_bytes:
        raise _error("RPC_RESULT_TOO_LARGE", f"JSON-RPC {field_name} exceeded its size limit")
    return raw


def _finalized_block(rpc: _RpcClient) -> tuple[BlockIdentity, str]:
    value = rpc.call("eth_getBlockByNumber", ["finalized", False])
    if not isinstance(value, dict):
        raise _error("FINALIZED_BLOCK_UNAVAILABLE", "a finalized block was not available")
    try:
        number, block_tag = _quantity(value.get("number"))
        block_hash = _hash(value.get("hash"))
    except VerifiedSourceError as exc:
        raise _error("FINALIZED_BLOCK_UNAVAILABLE", "a finalized block was not available") from exc
    return BlockIdentity(number=number, hash=block_hash), block_tag


def _assert_canonical_block(rpc: _RpcClient, block: BlockIdentity, block_tag: str) -> None:
    value = rpc.call("eth_getBlockByNumber", [block_tag, False])
    if not isinstance(value, dict):
        raise _error("FINALIZED_BLOCK_CHANGED", "the pinned finalized block could not be confirmed")
    try:
        number, _normalized = _quantity(value.get("number"))
        block_hash = _hash(value.get("hash"))
    except VerifiedSourceError as exc:
        raise _error(
            "FINALIZED_BLOCK_CHANGED", "the pinned finalized block could not be confirmed"
        ) from exc
    if number != block.number or block_hash != block.hash:
        raise _error("FINALIZED_BLOCK_CHANGED", "the pinned finalized block changed")


def _code_identity(rpc: _RpcClient, address: str, block_tag: str) -> tuple[CodeIdentity, bytes]:
    raw = _data(
        rpc.call("eth_getCode", [address, block_tag]),
        max_bytes=MAX_CODE_BYTES,
        field_name="bytecode",
    )
    if not raw:
        raise _error(
            "NO_CONTRACT_CODE", "contract bytecode was not available at the finalized block"
        )
    identity = CodeIdentity(
        address=address,
        keccak256="0x" + keccak(raw).hex(),
        size_bytes=len(raw),
    )
    return identity, raw


def _slot_address(rpc: _RpcClient, address: str, slot: str, block_tag: str) -> str | None:
    raw = _data(
        rpc.call("eth_getStorageAt", [address, slot, block_tag]),
        max_bytes=32,
        field_name="storage word",
    )
    if len(raw) != 32 or any(raw[:12]):
        raise _error("INVALID_PROXY_SLOT", "an EIP-1967 address slot was malformed")
    if not any(raw[12:]):
        return None
    return "0x" + raw[12:].hex()


def _beacon_implementation(rpc: _RpcClient, beacon: str, block_tag: str) -> str:
    raw = _data(
        rpc.call(
            "eth_call",
            [{"to": beacon, "data": BEACON_IMPLEMENTATION_SELECTOR}, block_tag],
        ),
        max_bytes=32,
        field_name="beacon result",
    )
    if len(raw) != 32 or any(raw[:12]) or not any(raw[12:]):
        raise _error("INVALID_PROXY_BEACON", "the EIP-1967 beacon returned no implementation")
    return "0x" + raw[12:].hex()


def _cbor_length(value: bytes, offset: int, major_type: int) -> tuple[int, int] | None:
    """Read one minimally encoded, definite CBOR length for the expected major type."""

    if offset >= len(value):
        return None
    initial = value[offset]
    if initial >> 5 != major_type:
        return None
    additional = initial & 0x1F
    offset += 1
    if additional < 24:
        return additional, offset
    byte_count = {24: 1, 25: 2, 26: 4}.get(additional)
    if byte_count is None or offset + byte_count > len(value):
        return None
    length = int.from_bytes(value[offset : offset + byte_count])
    minimum = {1: 24, 2: 1 << 8, 4: 1 << 16}[byte_count]
    if length < minimum:
        return None
    return length, offset + byte_count


def _cbor_blob(
    value: bytes, offset: int, major_type: int
) -> tuple[bytes, int] | None:
    decoded = _cbor_length(value, offset, major_type)
    if decoded is None:
        return None
    length, content_offset = decoded
    end = content_offset + length
    if end > len(value):
        return None
    return value[content_offset:end], end


def _is_solidity_metadata(payload: bytes) -> bool:
    """Recognize the constrained CBOR map emitted by Solidity compilers."""

    map_header = _cbor_length(payload, 0, 5)
    if map_header is None:
        return False
    item_count, offset = map_header
    if not 1 <= item_count <= len(SOLIDITY_METADATA_KEYS):
        return False

    keys: set[str] = set()
    source_keys = 0
    for _ in range(item_count):
        key_item = _cbor_blob(payload, offset, 3)
        if key_item is None:
            return False
        key_bytes, offset = key_item
        try:
            key = key_bytes.decode("ascii")
        except UnicodeDecodeError:
            return False
        if key not in SOLIDITY_METADATA_KEYS or key in keys:
            return False
        keys.add(key)

        if key == "experimental":
            if offset >= len(payload) or payload[offset] != 0xF5:  # CBOR true
                return False
            offset += 1
            continue

        if key == "solc":
            version = _cbor_blob(payload, offset, 2)
            if version is not None and len(version[0]) == 3:
                _version_bytes, offset = version
                continue
            prerelease = _cbor_blob(payload, offset, 3)
            if prerelease is None or SOLC_PRERELEASE_RE.fullmatch(prerelease[0]) is None:
                return False
            _version_text, offset = prerelease
            continue

        metadata_hash = _cbor_blob(payload, offset, 2)
        if metadata_hash is None:
            return False
        hash_bytes, offset = metadata_hash
        if key == "ipfs":
            if len(hash_bytes) != 34 or not hash_bytes.startswith(b"\x12\x20"):
                return False
        elif len(hash_bytes) != 32:  # bzzr0 / bzzr1
            return False
        source_keys += 1

    return offset == len(payload) and "solc" in keys and source_keys <= 1


def _without_solidity_metadata(bytecode: bytes) -> bytes:
    """Remove only a fully validated standard Solidity CBOR trailer.

    Solidity prefixes the trailer with INVALID and ends it with a two-byte
    big-endian CBOR length. Unknown keys, indefinite or non-minimal encodings,
    invalid value shapes, missing compiler identity, or any unconsumed data keep
    the complete bytecode in the fail-closed opcode scan.
    """

    if len(bytecode) < 4:
        return bytecode
    metadata_length = int.from_bytes(bytecode[-2:])
    metadata_start = len(bytecode) - metadata_length - 2
    if metadata_length == 0 or metadata_start < 1 or bytecode[metadata_start - 1] != 0xFE:
        return bytecode
    payload = bytecode[metadata_start:-2]
    return bytecode[:metadata_start] if _is_solidity_metadata(payload) else bytecode


def _has_unsupported_dispatch(bytecode: bytes) -> bool:
    """Linearly scan code, excluding PUSH data and validated Solidity metadata."""

    bytecode = _without_solidity_metadata(bytecode)
    offset = 0
    while offset < len(bytecode):
        opcode = bytecode[offset]
        offset += 1
        if opcode in UNSUPPORTED_DISPATCH_OPCODES:
            return True
        if 0x60 <= opcode <= 0x7F:  # PUSH1 through PUSH32
            offset += opcode - 0x5F
    return False


def _resolve_proxy_chain(
    rpc: _RpcClient, address: str, block_tag: str
) -> tuple[CodeIdentity, bytes, CodeIdentity, bytes, tuple[ProxyHop, ...]]:
    visited: set[str] = set()
    hops: list[ProxyHop] = []
    current = address
    target_identity: CodeIdentity | None = None
    target_code: bytes | None = None

    while True:
        if current in visited:
            raise _error("PROXY_CYCLE", "the EIP-1967 implementation chain contained a cycle")
        visited.add(current)
        identity, code = _code_identity(rpc, current, block_tag)
        if target_identity is None:
            target_identity, target_code = identity, code

        implementation = _slot_address(
            rpc, current, EIP1967_IMPLEMENTATION_SLOT, block_tag
        )
        beacon_address = _slot_address(rpc, current, EIP1967_BEACON_SLOT, block_tag)
        if implementation is not None and beacon_address is not None:
            raise _error(
                "AMBIGUOUS_PROXY", "both EIP-1967 implementation mechanisms were populated"
            )
        if implementation is None and beacon_address is None:
            assert target_identity is not None and target_code is not None
            if not hops and _has_unsupported_dispatch(target_code):
                raise _error(
                    "UNSUPPORTED_DISPATCH",
                    "target bytecode uses an unsupported dynamic dispatch mechanism",
                )
            return target_identity, target_code, identity, code, tuple(hops)
        if len(hops) >= MAX_PROXY_HOPS:
            raise _error("PROXY_DEPTH_EXCEEDED", "the EIP-1967 proxy chain was too deep")

        beacon_identity = None
        if beacon_address is not None:
            if beacon_address in visited:
                raise _error("PROXY_CYCLE", "the EIP-1967 implementation chain contained a cycle")
            beacon_identity, _beacon_code = _code_identity(rpc, beacon_address, block_tag)
            implementation = _beacon_implementation(rpc, beacon_address, block_tag)
            if implementation == beacon_address:
                raise _error("PROXY_CYCLE", "the EIP-1967 implementation chain contained a cycle")
            kind = "eip1967_beacon"
        else:
            kind = "eip1967_implementation"
        assert implementation is not None
        hops.append(
            ProxyHop(
                proxy=identity,
                kind=kind,
                implementation_address=implementation,
                beacon=beacon_identity,
            )
        )
        current = implementation


def _validate_abi_parameter(value: object, scope: str) -> None:
    if not isinstance(value, dict):
        raise _error("INVALID_VERIFIED_ABI", f"{scope} was not an object")
    if not isinstance(value.get("name", ""), str):
        raise _error("INVALID_VERIFIED_ABI", f"{scope} name was invalid")
    abi_type = value.get("type")
    if not isinstance(abi_type, str) or not abi_type or len(abi_type) > 256:
        raise _error("INVALID_VERIFIED_ABI", f"{scope} type was invalid")
    if abi_type.startswith("tuple"):
        components = value.get("components")
        if not isinstance(components, list) or len(components) > MAX_ABI_ENTRIES:
            raise _error("INVALID_VERIFIED_ABI", f"{scope} tuple components were invalid")
        for component in components:
            _validate_abi_parameter(component, f"{scope} tuple component")


def _validate_abi(value: object) -> bytes:
    if not isinstance(value, list) or len(value) > MAX_ABI_ENTRIES:
        raise _error("INVALID_VERIFIED_ABI", "verified ABI was not a bounded array")
    for entry in value:
        if not isinstance(entry, dict):
            raise _error("INVALID_VERIFIED_ABI", "verified ABI entry was not an object")
        kind = entry.get("type")
        if not isinstance(kind, str) or kind not in ABI_KINDS:
            raise _error("INVALID_VERIFIED_ABI", "verified ABI entry type was invalid")
        if kind in NAMED_ABI_KINDS:
            name = entry.get("name")
            if not isinstance(name, str) or not name or len(name) > 512:
                raise _error("INVALID_VERIFIED_ABI", "verified ABI entry name was invalid")
        for field_name in ("inputs", "outputs"):
            if field_name not in entry:
                continue
            parameters = entry[field_name]
            if not isinstance(parameters, list) or len(parameters) > MAX_ABI_ENTRIES:
                raise _error("INVALID_VERIFIED_ABI", "verified ABI parameters were invalid")
            for parameter in parameters:
                _validate_abi_parameter(parameter, "verified ABI parameter")
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError, RecursionError) as exc:
        raise _error("INVALID_VERIFIED_ABI", "verified ABI was not canonical JSON") from exc
    if len(encoded) > MAX_ABI_BYTES:
        raise _error("INVALID_VERIFIED_ABI", "verified ABI exceeded its encoded size limit")
    return encoded


def _sourcify_binding(
    http: _HttpClient,
    chain_id: int,
    contract: CodeIdentity,
    runtime_code: bytes,
) -> tuple[str, str, bytes]:
    url = SOURCIFY_CONTRACT.format(chain_id=chain_id, address=contract.address)
    response = http.json(
        method="GET",
        url=url,
        body=None,
        max_response_bytes=SOURCIFY_RESPONSE_BYTES,
        not_found_code="SOURCE_NOT_VERIFIED",
    )
    if not isinstance(response, dict):
        raise _error("INVALID_SOURCE_RESPONSE", "verified source response was not an object")

    response_chain = response.get("chainId")
    if isinstance(response_chain, bool) or response_chain not in (chain_id, str(chain_id)):
        raise _error("SOURCE_IDENTITY_MISMATCH", "verified source chain identity did not match")
    try:
        response_address = _normalize_address(response.get("address"))
    except VerifiedSourceError as exc:
        raise _error("SOURCE_IDENTITY_MISMATCH", "verified source address did not match") from exc
    if response_address != contract.address:
        raise _error("SOURCE_IDENTITY_MISMATCH", "verified source address did not match")

    match = response.get("match")
    runtime_match = response.get("runtimeMatch")
    if (
        not isinstance(match, str)
        or match not in VERIFIED_MATCHES
        or not isinstance(runtime_match, str)
        or runtime_match not in VERIFIED_MATCHES
    ):
        raise _error("SOURCE_NOT_RUNTIME_VERIFIED", "source did not have a runtime verification")
    runtime = response.get("runtimeBytecode")
    if not isinstance(runtime, dict):
        raise _error("INVALID_SOURCE_RESPONSE", "verified runtime bytecode was missing")
    recorded_code = _data(
        runtime.get("onchainBytecode"),
        max_bytes=MAX_CODE_BYTES,
        field_name="verified runtime bytecode",
    )
    if recorded_code != runtime_code:
        raise _error(
            "SOURCE_CODE_MISMATCH", "verified source bytecode did not match the finalized runtime"
        )
    abi_json = _validate_abi(response.get("abi"))
    abi_hash = "sha256:" + hashlib.sha256(abi_json).hexdigest()
    return cast(str, runtime_match), abi_hash, abi_json


def resolve_verified_source(
    chain_id: int,
    address: str,
    *,
    transport: Callable[[HttpRequest], HttpResponse] | None = None,
) -> VerifiedSourceResult:
    """Resolve finalized runtime provenance and a bytecode-bound Sourcify ABI.

    Only chain id and address are input data. Network destinations and limits
    remain module-owned. Passing ``transport`` injects I/O behavior, not a URL,
    and is intended for offline tests or a separately sandboxed network worker.
    """

    normalized_chain = _normalize_chain_id(chain_id)
    normalized_address = _normalize_address(address)
    http = _HttpClient(transport or _urlopen_transport)
    rpc = _RpcClient(normalized_chain, http)

    reported_chain, _canonical_chain = _quantity(rpc.call("eth_chainId", []))
    if reported_chain != normalized_chain:
        raise _error("RPC_CHAIN_MISMATCH", "the allowlisted RPC reported a different chain")
    block, block_tag = _finalized_block(rpc)
    target, _target_code, effective, effective_code, proxy_chain = _resolve_proxy_chain(
        rpc, normalized_address, block_tag
    )
    verification_match, abi_hash, abi_json = _sourcify_binding(
        http, normalized_chain, effective, effective_code
    )
    _assert_canonical_block(rpc, block, block_tag)

    return VerifiedSourceResult(
        chain_id=normalized_chain,
        address=normalized_address,
        block=block,
        target=target,
        effective_contract=effective,
        proxy_chain=proxy_chain,
        verification_match=verification_match,
        abi_hash=abi_hash,
        _abi_json=abi_json,
    )


__all__ = [
    "BEACON_IMPLEMENTATION_SELECTOR",
    "EIP1967_BEACON_SLOT",
    "EIP1967_IMPLEMENTATION_SLOT",
    "BlockIdentity",
    "CodeIdentity",
    "HttpRequest",
    "HttpResponse",
    "ProxyHop",
    "RPC_ENDPOINTS",
    "VerifiedSourceError",
    "VerifiedSourceResult",
    "resolve_verified_source",
]
