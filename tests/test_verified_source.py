"""Offline tests for finalized bytecode and verified ABI provenance."""

from __future__ import annotations

import copy
import json
from urllib.parse import urlsplit

import pytest
from eth_utils import keccak

from lucent import verified_source as source

CHAIN_ID = 1
TARGET = "0x" + "11" * 20
IMPLEMENTATION = "0x" + "22" * 20
BEACON = "0x" + "33" * 20
BLOCK_NUMBER = 0x10
BLOCK_HASH = "0x" + "aa" * 32
TARGET_CODE = bytes.fromhex("60006000f3")
IMPLEMENTATION_CODE = bytes.fromhex("6001600055")
BEACON_CODE = bytes.fromhex("6002600055")
ZERO_WORD = "0x" + "00" * 32
ABI = [
    {
        "type": "function",
        "name": "ping",
        "inputs": [],
        "outputs": [],
        "stateMutability": "view",
    }
]


def _address_word(address: str) -> str:
    return "0x" + ("00" * 12) + address[2:]


def _solidity_ipfs_metadata(digest: bytes) -> bytes:
    assert len(digest) == 32
    payload = b"\xa2\x64ipfs\x58\x22\x12\x20" + digest + b"\x64solc\x43\x00\x08\x1a"
    return b"\xfe" + payload + len(payload).to_bytes(2)


def _json_response(value: object, *, status: int = 200) -> source.HttpResponse:
    body = json.dumps(value, separators=(",", ":")).encode()
    return source.HttpResponse(
        status=status,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
        body=body,
    )


class OfflineChain:
    def __init__(
        self,
        *,
        codes: dict[str, bytes] | None = None,
        verified_address: str = TARGET,
    ):
        self.codes = {key.lower(): value for key, value in (codes or {TARGET: TARGET_CODE}).items()}
        self.slots: dict[tuple[str, str], str] = {}
        self.beacon_implementations: dict[str, str] = {}
        self.verified_address = verified_address.lower()
        self.reported_chain = "0x1"
        self.confirmed_block_hash = BLOCK_HASH
        self.source_status = 200
        self.requests: list[source.HttpRequest] = []
        self.rpc_calls: list[dict] = []
        self.source_payload: object = self._default_source_payload()

    def _default_source_payload(self) -> dict:
        runtime_code = self.codes[self.verified_address]
        return {
            "chainId": str(CHAIN_ID),
            "address": self.verified_address,
            "match": "exact_match",
            "runtimeMatch": "exact_match",
            "runtimeBytecode": {"onchainBytecode": "0x" + runtime_code.hex()},
            "abi": copy.deepcopy(ABI),
        }

    def __call__(self, request: source.HttpRequest) -> source.HttpResponse:
        self.requests.append(request)
        assert 0 < request.timeout_seconds <= source.REQUEST_TIMEOUT_SECONDS
        assert request.max_response_bytes > 0

        if request.method == "GET":
            assert request.body is None
            if self.source_status != 200:
                return source.HttpResponse(status=self.source_status, headers={}, body=b"")
            return _json_response(self.source_payload)

        assert request.method == "POST"
        assert request.url == source.RPC_ENDPOINTS[CHAIN_ID]
        assert request.body is not None
        payload = json.loads(request.body)
        self.rpc_calls.append(payload)
        method = payload["method"]
        params = payload["params"]

        if method == "eth_chainId":
            result: object = self.reported_chain
        elif method == "eth_getBlockByNumber":
            block_hash = BLOCK_HASH if params[0] == "finalized" else self.confirmed_block_hash
            result = {"number": hex(BLOCK_NUMBER), "hash": block_hash}
        elif method == "eth_getCode":
            result = "0x" + self.codes.get(params[0].lower(), b"").hex()
        elif method == "eth_getStorageAt":
            result = self.slots.get((params[0].lower(), params[1]), ZERO_WORD)
        elif method == "eth_call":
            call = params[0]
            assert call["data"] == source.BEACON_IMPLEMENTATION_SELECTOR
            result = _address_word(self.beacon_implementations[call["to"].lower()])
        else:  # pragma: no cover - makes additions to the production call set explicit
            raise AssertionError(f"unexpected RPC method {method}")
        return _json_response({"jsonrpc": "2.0", "id": payload["id"], "result": result})


def _error_code(chain: OfflineChain, address: str = TARGET) -> str:
    with pytest.raises(source.VerifiedSourceError) as caught:
        source.resolve_verified_source(CHAIN_ID, address, transport=chain)
    return caught.value.code


def test_direct_contract_is_bound_to_finalized_code_and_verified_abi():
    chain = OfflineChain()

    result = source.resolve_verified_source(
        CHAIN_ID, TARGET.upper().replace("0X", "0x"), transport=chain
    )

    expected_code_hash = "0x" + keccak(TARGET_CODE).hex()
    assert result.chain_id == CHAIN_ID
    assert result.address == TARGET
    assert result.block_number == BLOCK_NUMBER
    assert result.block_hash == BLOCK_HASH
    assert result.code_hash == expected_code_hash
    assert result.target.size_bytes == len(TARGET_CODE)
    assert result.effective_contract == result.target
    assert result.implementation_address is None
    assert result.implementation_code_hash is None
    assert result.abi_address == TARGET
    assert result.proxy_chain == ()
    assert result.verification_match == "exact_match"
    assert result.abi_hash.startswith("sha256:")
    assert result.abi == ABI

    # Callers cannot mutate the ABI while retaining the original binding hash.
    changed = result.abi
    changed[0]["name"] = "changed"
    assert result.abi == ABI

    output = result.to_dict()
    rendered = json.dumps(output)
    assert output["abi_binding"]["runtime_code_hash"] == expected_code_hash
    assert "http://" not in rendered and "https://" not in rendered
    assert "publicnode" not in rendered and "mainnet.base.org" not in rendered

    canonical_cache_value = json.dumps(
        output,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    assert result.cache_size_bytes == len(canonical_cache_value)
    assert result.cache_size_bytes == result.cache_size_bytes

    source_requests = [request for request in chain.requests if request.method == "GET"]
    assert len(source_requests) == 1
    parsed_source_url = urlsplit(source_requests[0].url)
    assert parsed_source_url.scheme == "https"
    assert parsed_source_url.netloc == "sourcify.dev"
    assert parsed_source_url.path.endswith(f"/{CHAIN_ID}/{TARGET}")
    assert parsed_source_url.query == "fields=abi,runtimeBytecode.onchainBytecode"

    block_lookups = [
        call["params"]
        for call in chain.rpc_calls
        if call["method"] == "eth_getBlockByNumber"
    ]
    assert block_lookups == [["finalized", False], [hex(BLOCK_NUMBER), False]]
    for call in chain.rpc_calls:
        if call["method"] in {"eth_getCode", "eth_getStorageAt", "eth_call"}:
            assert call["params"][-1] == hex(BLOCK_NUMBER)


def test_direct_eip1967_proxy_binds_the_implementation():
    chain = OfflineChain(
        codes={TARGET: TARGET_CODE, IMPLEMENTATION: IMPLEMENTATION_CODE},
        verified_address=IMPLEMENTATION,
    )
    chain.slots[(TARGET, source.EIP1967_IMPLEMENTATION_SLOT)] = _address_word(IMPLEMENTATION)

    result = source.resolve_verified_source(CHAIN_ID, TARGET, transport=chain)

    assert result.target.address == TARGET
    assert result.implementation_address == IMPLEMENTATION
    assert result.implementation_code_hash == "0x" + keccak(IMPLEMENTATION_CODE).hex()
    assert result.abi_address == IMPLEMENTATION
    assert len(result.proxy_chain) == 1
    hop = result.proxy_chain[0]
    assert hop.kind == "eip1967_implementation"
    assert hop.implementation_address == IMPLEMENTATION
    assert hop.beacon is None
    source_request = next(request for request in chain.requests if request.method == "GET")
    assert urlsplit(source_request.url).path.endswith(f"/{CHAIN_ID}/{IMPLEMENTATION}")


def test_eip1967_beacon_is_code_checked_and_resolved_at_the_pinned_block():
    chain = OfflineChain(
        codes={
            TARGET: TARGET_CODE,
            BEACON: BEACON_CODE,
            IMPLEMENTATION: IMPLEMENTATION_CODE,
        },
        verified_address=IMPLEMENTATION,
    )
    chain.slots[(TARGET, source.EIP1967_BEACON_SLOT)] = _address_word(BEACON)
    chain.beacon_implementations[BEACON] = IMPLEMENTATION

    result = source.resolve_verified_source(CHAIN_ID, TARGET, transport=chain)

    hop = result.proxy_chain[0]
    assert hop.kind == "eip1967_beacon"
    assert hop.beacon is not None
    assert hop.beacon.address == BEACON
    assert hop.beacon.keccak256 == "0x" + keccak(BEACON_CODE).hex()
    assert hop.implementation_address == IMPLEMENTATION
    beacon_call = next(call for call in chain.rpc_calls if call["method"] == "eth_call")
    assert beacon_call["params"] == [
        {"to": BEACON, "data": source.BEACON_IMPLEMENTATION_SELECTOR},
        hex(BLOCK_NUMBER),
    ]


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        (lambda payload: payload.update(chainId="8453"), "SOURCE_IDENTITY_MISMATCH"),
        (
            lambda payload: payload.update(address="0x" + "44" * 20),
            "SOURCE_IDENTITY_MISMATCH",
        ),
        (lambda payload: payload.update(runtimeMatch=None), "SOURCE_NOT_RUNTIME_VERIFIED"),
        (lambda payload: payload.update(runtimeMatch=[]), "SOURCE_NOT_RUNTIME_VERIFIED"),
        (
            lambda payload: payload["runtimeBytecode"].update(onchainBytecode="0x6002"),
            "SOURCE_CODE_MISMATCH",
        ),
        (lambda payload: payload.update(abi=[{}]), "INVALID_VERIFIED_ABI"),
        (lambda payload: payload.update(abi=[{"type": []}]), "INVALID_VERIFIED_ABI"),
    ],
)
def test_sourcify_identity_runtime_and_abi_must_all_bind(mutation, expected_code):
    chain = OfflineChain()
    assert isinstance(chain.source_payload, dict)
    mutation(chain.source_payload)

    assert _error_code(chain) == expected_code


def test_missing_sourcify_contract_fails_closed():
    chain = OfflineChain()
    chain.source_status = 404

    assert _error_code(chain) == "SOURCE_NOT_VERIFIED"


@pytest.mark.parametrize(
    ("chain_id", "address", "expected_code"),
    [
        (True, TARGET, "INVALID_CHAIN_ID"),
        (0, TARGET, "INVALID_CHAIN_ID"),
        (137, TARGET, "UNSUPPORTED_CHAIN"),
        (1, "https://attacker.example", "INVALID_ADDRESS"),
        (1, "0x" + "11" * 19, "INVALID_ADDRESS"),
    ],
)
def test_only_allowlisted_chains_and_exact_addresses_are_accepted(
    chain_id, address, expected_code
):
    def should_not_run(_request):
        raise AssertionError("transport should not run for rejected input")

    with pytest.raises(source.VerifiedSourceError) as caught:
        source.resolve_verified_source(chain_id, address, transport=should_not_run)
    assert caught.value.code == expected_code


def test_allowlisted_endpoint_chain_identity_is_checked():
    chain = OfflineChain()
    chain.reported_chain = "0x2105"

    assert _error_code(chain) == "RPC_CHAIN_MISMATCH"
    assert {request.url for request in chain.requests} == {source.RPC_ENDPOINTS[CHAIN_ID]}


def test_empty_code_and_malformed_proxy_state_fail_closed():
    no_code = OfflineChain(codes={TARGET: b""})
    assert _error_code(no_code) == "NO_CONTRACT_CODE"

    malformed_slot = OfflineChain()
    malformed_slot.slots[(TARGET, source.EIP1967_IMPLEMENTATION_SLOT)] = "0x01" + "00" * 31
    assert _error_code(malformed_slot) == "INVALID_PROXY_SLOT"

    ambiguous = OfflineChain(
        codes={TARGET: TARGET_CODE, IMPLEMENTATION: IMPLEMENTATION_CODE, BEACON: BEACON_CODE}
    )
    ambiguous.slots[(TARGET, source.EIP1967_IMPLEMENTATION_SLOT)] = _address_word(IMPLEMENTATION)
    ambiguous.slots[(TARGET, source.EIP1967_BEACON_SLOT)] = _address_word(BEACON)
    assert _error_code(ambiguous) == "AMBIGUOUS_PROXY"


@pytest.mark.parametrize("opcode", [b"\xf2", b"\xf4"])
def test_unrecognized_executable_dispatch_opcodes_fail_before_source_lookup(opcode):
    chain = OfflineChain(codes={TARGET: (b"\x60\x00" * 5) + opcode + b"\x00"})

    assert _error_code(chain) == "UNSUPPORTED_DISPATCH"
    assert all(request.method != "GET" for request in chain.requests)


@pytest.mark.parametrize(
    "runtime_code",
    [
        b"\x60\xf4\x00",  # PUSH1 0xf4; STOP
        b"\x61\xf2\xf4\x00",  # PUSH2 0xf2f4; STOP
        b"\x7f" + (b"\xf2\xf4" * 16) + b"\x00",  # PUSH32 data; STOP
    ],
)
def test_dispatch_opcode_bytes_inside_push_data_do_not_false_positive(runtime_code):
    chain = OfflineChain(codes={TARGET: runtime_code})

    result = source.resolve_verified_source(CHAIN_ID, TARGET, transport=chain)

    assert result.proxy_chain == ()
    assert result.target.size_bytes == len(runtime_code)


def test_dispatch_bytes_inside_valid_solidity_metadata_do_not_false_positive():
    metadata = _solidity_ipfs_metadata(b"\xf2\xf4" + (b"\x11" * 30))
    runtime_code = b"\x60\x00\x00" + metadata
    chain = OfflineChain(codes={TARGET: runtime_code})

    result = source.resolve_verified_source(CHAIN_ID, TARGET, transport=chain)

    assert result.proxy_chain == ()
    assert result.target.size_bytes == len(runtime_code)


def test_executable_dispatch_before_valid_solidity_metadata_still_rejects():
    metadata = _solidity_ipfs_metadata(b"\xf2\xf4" + (b"\x11" * 30))
    chain = OfflineChain(codes={TARGET: b"\x60\x00\xf4" + metadata})

    assert _error_code(chain) == "UNSUPPORTED_DISPATCH"
    assert all(request.method != "GET" for request in chain.requests)


def test_unrecognized_cbor_cannot_hide_dispatch_from_the_scanner():
    # Structurally valid CBOR, but the unknown key prevents trailer stripping.
    payload = b"\xa2\x64evil\x41\xf4\x64solc\x43\x00\x08\x1a"
    runtime_code = b"\x60\x00\x00\xfe" + payload + len(payload).to_bytes(2)
    chain = OfflineChain(codes={TARGET: runtime_code})

    assert _error_code(chain) == "UNSUPPORTED_DISPATCH"
    assert all(request.method != "GET" for request in chain.requests)


def test_proxy_cycles_and_excessive_depth_are_rejected_before_source_lookup():
    cyclic = OfflineChain(codes={TARGET: TARGET_CODE, IMPLEMENTATION: IMPLEMENTATION_CODE})
    cyclic.slots[(TARGET, source.EIP1967_IMPLEMENTATION_SLOT)] = _address_word(IMPLEMENTATION)
    cyclic.slots[(IMPLEMENTATION, source.EIP1967_IMPLEMENTATION_SLOT)] = _address_word(TARGET)
    assert _error_code(cyclic) == "PROXY_CYCLE"
    assert all(request.method != "GET" for request in cyclic.requests)

    addresses = ["0x" + f"{number:040x}" for number in range(1, source.MAX_PROXY_HOPS + 3)]
    deep = OfflineChain(
        codes={address: TARGET_CODE for address in addresses},
        verified_address=addresses[-1],
    )
    for proxy, implementation in zip(addresses, addresses[1:], strict=False):
        deep.slots[(proxy, source.EIP1967_IMPLEMENTATION_SLOT)] = _address_word(implementation)
    assert _error_code(deep, addresses[0]) == "PROXY_DEPTH_EXCEEDED"
    assert all(request.method != "GET" for request in deep.requests)


def test_finalized_block_is_rechecked_before_a_result_is_returned():
    chain = OfflineChain()
    chain.confirmed_block_hash = "0x" + "bb" * 32

    assert _error_code(chain) == "FINALIZED_BLOCK_CHANGED"


def test_transport_exceptions_are_redacted_and_response_size_is_hard_bounded():
    secret = "https://private-rpc.example/path?api_key=hunter2"

    def raises_secret(_request):
        raise RuntimeError(secret)

    with pytest.raises(source.VerifiedSourceError) as caught:
        source.resolve_verified_source(CHAIN_ID, TARGET, transport=raises_secret)
    assert caught.value.code == "UPSTREAM_UNAVAILABLE"
    assert secret not in str(caught.value)
    assert secret not in json.dumps(caught.value.to_dict())

    def oversized(_request):
        return source.HttpResponse(
            status=200,
            headers={"Content-Type": "application/json"},
            body=b"x" * (source.RPC_RESPONSE_BYTES + 1),
        )

    with pytest.raises(source.VerifiedSourceError) as caught:
        source.resolve_verified_source(CHAIN_ID, TARGET, transport=oversized)
    assert caught.value.code == "UPSTREAM_RESPONSE_TOO_LARGE"


def test_json_rpc_envelope_and_json_content_type_are_strict():
    def wrong_media_type(_request):
        return source.HttpResponse(status=200, headers={"Content-Type": "text/html"}, body=b"{}")

    with pytest.raises(source.VerifiedSourceError) as caught:
        source.resolve_verified_source(CHAIN_ID, TARGET, transport=wrong_media_type)
    assert caught.value.code == "INVALID_UPSTREAM_RESPONSE"

    def rpc_error(request):
        assert request.body is not None
        request_id = json.loads(request.body)["id"]
        return _json_response(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"message": "secret upstream diagnostic"},
            }
        )

    with pytest.raises(source.VerifiedSourceError) as caught:
        source.resolve_verified_source(CHAIN_ID, TARGET, transport=rpc_error)
    assert caught.value.code == "RPC_REQUEST_FAILED"
    assert "secret upstream diagnostic" not in str(caught.value)


def test_rpc_response_limits_and_sourcify_response_limits_are_distinct():
    chain = OfflineChain()
    source_request_seen = False

    def observing_transport(request):
        nonlocal source_request_seen
        if request.method == "GET":
            source_request_seen = True
            assert request.max_response_bytes == source.SOURCIFY_RESPONSE_BYTES
        else:
            assert request.max_response_bytes == source.RPC_RESPONSE_BYTES
        return chain(request)

    source.resolve_verified_source(CHAIN_ID, TARGET, transport=observing_transport)
    assert source_request_seen


def test_cache_size_accounts_for_abi_growth_without_private_storage_access():
    small = source.resolve_verified_source(CHAIN_ID, TARGET, transport=OfflineChain())
    large_chain = OfflineChain()
    assert isinstance(large_chain.source_payload, dict)
    large_chain.source_payload["abi"] = [
        {
            "type": "function",
            "name": "longName" * 50,
            "inputs": [],
            "outputs": [],
            "stateMutability": "view",
        }
    ]

    large = source.resolve_verified_source(CHAIN_ID, TARGET, transport=large_chain)

    assert large.cache_size_bytes > small.cache_size_bytes
