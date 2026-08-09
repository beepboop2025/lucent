"""Fail-closed, call-scoped Clear Signing preflight analysis.

The original Lucent tools analyze an entire descriptor. That is useful for
authors, but it is the wrong boundary for a signer: one pending call must be
bound to one chain, deployment, selector and decoded calldata payload. This
module is the shared domain service used by HTTP and MCP transports.

The verdict is deliberately narrow. ``safe_to_present`` means that, relative
to the caller-supplied descriptor and ABI, Lucent found no presentation defect
that prevents showing the call to a signer. It never means that executing the
transaction is economically or operationally safe.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import audit  # noqa: E402
import common  # noqa: E402
import comprehend  # noqa: E402
import danger  # noqa: E402

API_VERSION = "v1"
POLICY_VERSION = "2026-08-09"
ANALYSIS_SCOPE = "static_selected_call"

MAX_DESCRIPTOR_BYTES = 512 * 1024
MAX_CALLDATA_BYTES = 128 * 1024
MAX_TRANSPORT_BODY_BYTES = MAX_DESCRIPTOR_BYTES + (2 * MAX_CALLDATA_BYTES) + (64 * 1024)
MAX_FORMATS = 1_024
MAX_FIELDS_PER_FORMAT = 16
MAX_JSON_DEPTH = 16
MAX_TEXT_LENGTH = 8_192
MAX_BYTES_PREVIEW = 64
UINT256_MAX = (1 << 256) - 1
ARRAY_TYPE_RE = re.compile(r"^(.*)\[[0-9]*\]$")
ALLOWED_FIELD_FORMATS = {
    "raw",
    "addressName",
    "calldata",
    "amount",
    "tokenAmount",
    "nftName",
    "date",
    "duration",
    "unit",
    "enum",
}
UNVERIFIED_FIELD_FORMATS = {"calldata", "tokenAmount", "nftName", "date", "unit", "enum"}
SOLIDITY_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")

HEX_DATA_RE = re.compile(r"^0x[0-9a-fA-F]+$")
HEX_QUANTITY_RE = re.compile(r"^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$")

LIMITATIONS = [
    "Static analysis of one caller-supplied ERC-7730 descriptor and ABI.",
    "Does not inspect bytecode, resolve proxies, or simulate runtime state changes.",
    "Does not detect economic exploits, MEV, malicious counterparties, or compromised frontends.",
    "safe_to_present describes presentation quality; it is not approval to execute or sign.",
    "V1 clears only scalar, locally-renderable formats; containers and "
    "reference-based formats block.",
]


class PreflightInputError(ValueError):
    """A deterministic client error with a stable machine-readable code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _json_depth(value: Any, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        return depth
    if isinstance(value, dict):
        return max((_json_depth(v, depth + 1) for v in value.values()), default=depth)
    if isinstance(value, (list, tuple)):
        return max((_json_depth(v, depth + 1) for v in value), default=depth)
    return depth


def _walk_text(value: Any) -> None:
    if isinstance(value, str):
        if len(value) > MAX_TEXT_LENGTH:
            raise PreflightInputError(
                "DESCRIPTOR_TEXT_TOO_LONG",
                f"descriptor strings may not exceed {MAX_TEXT_LENGTH} characters",
            )
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _walk_text(key)
            _walk_text(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _walk_text(item)


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    except (TypeError, ValueError) as exc:
        raise PreflightInputError(
            "INVALID_JSON_VALUE", "request contains a non-canonical JSON value"
        ) from exc


def _fingerprint(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def validate_descriptor(descriptor: object) -> tuple[dict, list, dict]:
    """Validate bounded descriptor structure and return descriptor, ABI, formats."""
    if not isinstance(descriptor, dict):
        raise PreflightInputError("INVALID_DESCRIPTOR", "descriptor must be a JSON object")
    raw = _canonical_json(descriptor)
    if len(raw) > MAX_DESCRIPTOR_BYTES:
        raise PreflightInputError(
            "DESCRIPTOR_TOO_LARGE",
            f"descriptor exceeds {MAX_DESCRIPTOR_BYTES} encoded bytes",
        )
    if _json_depth(descriptor) > MAX_JSON_DEPTH:
        raise PreflightInputError(
            "DESCRIPTOR_TOO_DEEP",
            f"descriptor nesting may not exceed {MAX_JSON_DEPTH} levels",
        )
    _walk_text(descriptor)
    try:
        abi = common.descriptor_abi(descriptor)
    except (KeyError, TypeError, ValueError) as exc:
        raise PreflightInputError("INVALID_DESCRIPTOR", str(exc)) from exc
    display = descriptor.get("display")
    if not isinstance(display, dict):
        raise PreflightInputError("INVALID_DESCRIPTOR", "descriptor must contain display")
    formats = display.get("formats")
    if not isinstance(formats, dict):
        raise PreflightInputError(
            "INVALID_DESCRIPTOR", "descriptor display.formats must be a JSON object"
        )
    if len(formats) > MAX_FORMATS:
        raise PreflightInputError(
            "TOO_MANY_FORMATS", f"descriptor exceeds {MAX_FORMATS} format entries"
        )
    for signature, fmt in formats.items():
        if not isinstance(signature, str) or not isinstance(fmt, dict):
            raise PreflightInputError(
                "INVALID_DESCRIPTOR", "every display format must map a signature to an object"
            )
        fields = fmt.get("fields", [])
        if not isinstance(fields, list) or any(not isinstance(field, dict) for field in fields):
            raise PreflightInputError(
                "INVALID_DESCRIPTOR", f"display format {signature!r} must contain a fields array"
            )
        if len(fields) > MAX_FIELDS_PER_FORMAT:
            raise PreflightInputError(
                "INVALID_DESCRIPTOR",
                f"display format {signature!r} exceeds {MAX_FIELDS_PER_FORMAT} fields",
            )
        paths = [field.get("path") for field in fields if field.get("path") is not None]
        if len(paths) != len(set(paths)):
            raise PreflightInputError(
                "INVALID_DESCRIPTOR", f"display format {signature!r} has duplicate field paths"
            )
        visible_labels = [
            " ".join(field.get("label", "").lower().split())
            for field in fields
            if field.get("visible") in (None, "always") and field.get("label")
        ]
        if len(visible_labels) != len(set(visible_labels)):
            raise PreflightInputError(
                "INVALID_DESCRIPTOR", f"display format {signature!r} has duplicate visible labels"
            )
        for field in fields:
            for key in ("path", "label", "format", "visible"):
                if key in field and not isinstance(field[key], str):
                    raise PreflightInputError(
                        "INVALID_DESCRIPTOR",
                        f"display format {signature!r} field {key!r} must be a string",
                    )
            if field.get("format") not in ALLOWED_FIELD_FORMATS | {None}:
                raise PreflightInputError(
                    "INVALID_DESCRIPTOR",
                    f"display format {signature!r} uses an unknown field format",
                )
            if field.get("params") is not None and not isinstance(field["params"], dict):
                raise PreflightInputError(
                    "INVALID_DESCRIPTOR",
                    f"display format {signature!r} field 'params' must be an object",
                )
            universally_visible = field.get("visible") in (None, "always")
            if universally_visible:
                if not isinstance(field.get("path"), str):
                    raise PreflightInputError(
                        "INVALID_DESCRIPTOR",
                        f"visible field in {signature!r} requires a path",
                    )
                if not isinstance(field.get("label"), str) or not field["label"].strip():
                    raise PreflightInputError(
                        "INVALID_DESCRIPTOR",
                        f"visible field in {signature!r} requires a non-empty label",
                    )
                if field.get("format") not in ALLOWED_FIELD_FORMATS:
                    raise PreflightInputError(
                        "INVALID_DESCRIPTOR",
                        f"visible field in {signature!r} requires an explicit supported format",
                    )
            field_format = field.get("format")
            params = field.get("params") or {}
            required_one_of = {
                "tokenAmount": ("token", "tokenPath"),
                "calldata": ("callee", "calleePath"),
                "nftName": ("collection", "collectionPath"),
            }
            if field_format in required_one_of:
                keys = required_one_of[field_format]
                present = [key for key in keys if params.get(key) is not None]
                if len(present) != 1:
                    raise PreflightInputError(
                        "INVALID_DESCRIPTOR",
                        f"field format {field_format!r} requires exactly one of {keys}",
                    )
            if field_format == "date" and params.get("encoding") not in (
                "timestamp",
                "blockheight",
            ):
                raise PreflightInputError(
                    "INVALID_DESCRIPTOR",
                    "field format 'date' requires timestamp or blockheight encoding",
                )
            if field_format == "unit" and not isinstance(params.get("base"), str):
                raise PreflightInputError(
                    "INVALID_DESCRIPTOR", "field format 'unit' requires a string base"
                )
            if field_format == "enum" and not isinstance(params.get("$ref"), str):
                raise PreflightInputError(
                    "INVALID_DESCRIPTOR", "field format 'enum' requires a $ref"
                )
        for key in ("intent", "interpolatedIntent"):
            if key in fmt and not isinstance(fmt[key], str):
                raise PreflightInputError(
                    "INVALID_DESCRIPTOR", f"display format {signature!r} {key} must be a string"
                )
    return descriptor, abi, formats


def parse_calldata(value: object) -> bytes:
    if not isinstance(value, str) or not HEX_DATA_RE.fullmatch(value):
        raise PreflightInputError(
            "INVALID_CALLDATA", "transaction data must be a 0x-prefixed hexadecimal string"
        )
    body = value[2:]
    if len(body) < 8:
        raise PreflightInputError(
            "INVALID_CALLDATA", "transaction data must contain a four-byte selector"
        )
    if len(body) % 2:
        raise PreflightInputError(
            "INVALID_CALLDATA", "transaction data must contain an even number of hex digits"
        )
    if len(body) // 2 > MAX_CALLDATA_BYTES:
        raise PreflightInputError(
            "CALLDATA_TOO_LARGE", f"calldata exceeds {MAX_CALLDATA_BYTES} bytes"
        )
    return bytes.fromhex(body)


def parse_value(value: object) -> int:
    if isinstance(value, bool):
        raise PreflightInputError("INVALID_VALUE", "transaction value must be a uint256")
    if isinstance(value, int):
        amount = value
    elif isinstance(value, str) and HEX_QUANTITY_RE.fullmatch(value):
        amount = int(value, 16)
    else:
        raise PreflightInputError(
            "INVALID_VALUE", "transaction value must be an integer or canonical hex quantity"
        )
    if amount < 0 or amount > UINT256_MAX:
        raise PreflightInputError("INVALID_VALUE", "transaction value exceeds uint256")
    return amount


def _deployment_matches(descriptor: dict, chain_id: int, address: str) -> bool:
    try:
        deployments = descriptor["context"]["contract"]["deployments"]
    except (KeyError, TypeError):
        return False
    if not isinstance(deployments, list):
        return False
    for deployment in deployments:
        if not isinstance(deployment, dict):
            continue
        try:
            dep_chain = common.normalize_chain_id(deployment.get("chainId"))
            dep_address = common.normalize_address(deployment.get("address"))
        except ValueError:
            continue
        if dep_chain == chain_id and dep_address == address:
            return True
    return False


def _resolve_call(abi: list, calldata: bytes) -> tuple[dict, str]:
    selector = "0x" + calldata[:4].hex()
    matches: list[tuple[dict, str]] = []
    for entry in common.signable_functions(abi):
        try:
            signature = common.signature(entry)
        except (KeyError, TypeError, ValueError) as exc:
            raise PreflightInputError("INVALID_ABI", "ABI contains a malformed function") from exc
        if common.selector(signature) == selector:
            matches.append((entry, signature))
    if not matches:
        raise PreflightInputError(
            "UNKNOWN_SELECTOR", f"selector {selector} is absent from the descriptor ABI"
        )
    unique = {signature for _, signature in matches}
    if len(matches) != 1 or len(unique) != 1:
        raise PreflightInputError(
            "SELECTOR_COLLISION", f"selector {selector} does not resolve to one unique function"
        )
    return matches[0]


def _decode_arguments(function: dict, calldata: bytes) -> list[dict]:
    inputs = function.get("inputs")
    if not isinstance(inputs, list):
        raise PreflightInputError("INVALID_ABI", "selected ABI function has invalid inputs")
    try:
        types = [common.canonical_type(item) for item in inputs]
        argument_bytes = calldata[4:]
        values = abi_decode(types, argument_bytes, strict=True)
    except Exception as exc:  # eth-abi exposes several decoder-specific exception classes
        raise PreflightInputError(
            "CALLDATA_DECODE_FAILED", "calldata does not decode against the selected ABI function"
        ) from exc
    # ``eth_abi.decode(strict=True)`` validates padding but deliberately ignores
    # trailing bytes. A contract can still inspect those bytes through msg.data,
    # so presenting only the decoded ABI arguments would hide signed input.
    if abi_encode(types, values) != argument_bytes:
        raise PreflightInputError(
            "CALLDATA_NOT_CANONICAL",
            "calldata contains trailing or non-canonical bytes outside the selected ABI arguments",
        )
    return [
        {
            "name": item.get("name") or f"arg{index}",
            "type": common.canonical_type(item),
            "value": _json_safe(value),
        }
        for index, (item, value) in enumerate(zip(inputs, values, strict=True))
    ]


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        if len(value) <= MAX_BYTES_PREVIEW:
            return "0x" + value.hex()
        return {
            "encoding": "bytes",
            "length": len(value),
            "prefix": "0x" + value[:MAX_BYTES_PREVIEW].hex(),
            "sha256": hashlib.sha256(value).hexdigest(),
            "truncated": True,
        }
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        # JSON numbers are lossy in JavaScript above 2**53-1. The adjacent ABI
        # ``type`` tells clients how to interpret this exact decimal string.
        return str(value)
    if isinstance(value, str) or value is None:
        return value
    return str(value)


def _path_target(input_abi: dict, segments: list[str]) -> dict | None:
    """Resolve the ERC-7730 path suffix to its ABI leaf or collection."""
    current = input_abi
    for segment in segments:
        abi_type = current.get("type")
        if not isinstance(abi_type, str):
            return None
        if segment == "[]":
            match = ARRAY_TYPE_RE.fullmatch(abi_type)
            if not match:
                return None
            current = {**current, "type": match.group(1)}
            continue
        if not abi_type.startswith("tuple"):
            return None
        components = current.get("components")
        if not isinstance(components, list):
            return None
        match = next(
            (
                component
                for component in components
                if isinstance(component, dict) and component.get("name") == segment
            ),
            None,
        )
        if match is None:
            return None
        current = match
    return current


def _format_matches_abi(abi_type: str, field_format: str | None) -> bool:
    """Reject category-confused renderers while permitting an explicit raw view."""
    if field_format is None:
        field_format = "raw"
    if field_format not in ALLOWED_FIELD_FORMATS:
        return False
    if ARRAY_TYPE_RE.fullmatch(abi_type) or abi_type.startswith("tuple"):
        return field_format in ("raw", "calldata")
    if abi_type == "address":
        return field_format in ("raw", "addressName")
    if abi_type == "bool":
        return field_format in ("raw", "enum")
    if abi_type.startswith(("uint", "int")):
        return field_format in (
            "raw",
            "amount",
            "tokenAmount",
            "nftName",
            "date",
            "duration",
            "unit",
            "enum",
        )
    if abi_type.startswith("bytes"):
        return field_format in ("raw", "calldata")
    if abi_type == "string":
        return field_format in ("raw", "enum")
    return field_format == "raw"


def _abi_leaf_paths(input_abi: dict, prefix: tuple[str, ...]) -> list[tuple[str, ...]]:
    """Enumerate every independently signed ABI leaf below an input path."""
    abi_type = input_abi.get("type")
    if not isinstance(abi_type, str):
        return [prefix]
    array_match = ARRAY_TYPE_RE.fullmatch(abi_type)
    if array_match:
        return _abi_leaf_paths({**input_abi, "type": array_match.group(1)}, (*prefix, "[]"))
    if abi_type.startswith("tuple"):
        components = input_abi.get("components")
        if not isinstance(components, list) or not components:
            return [prefix]
        leaves: list[tuple[str, ...]] = []
        for index, component in enumerate(components):
            if not isinstance(component, dict):
                leaves.append((*prefix, f"component{index}"))
                continue
            name = component.get("name") or f"component{index}"
            leaves.extend(_abi_leaf_paths(component, (*prefix, name)))
        return leaves
    return [prefix]


def _validate_selected_function(function: dict) -> None:
    """Require stable names so descriptor paths cannot alias signed positions."""
    name = function.get("name")
    if not isinstance(name, str) or not SOLIDITY_IDENTIFIER_RE.fullmatch(name):
        raise PreflightInputError("UNBINDABLE_ABI", "selected function has an invalid name")

    def validate_inputs(items: object, scope: str) -> None:
        if not isinstance(items, list):
            raise PreflightInputError("UNBINDABLE_ABI", f"{scope} inputs must be an array")
        names: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                raise PreflightInputError("UNBINDABLE_ABI", f"{scope} input must be an object")
            input_name = item.get("name")
            if not isinstance(input_name, str) or not SOLIDITY_IDENTIFIER_RE.fullmatch(
                input_name
            ):
                raise PreflightInputError(
                    "UNBINDABLE_ABI", f"{scope} inputs require unique Solidity identifiers"
                )
            names.append(input_name)
            abi_type = item.get("type")
            if not isinstance(abi_type, str):
                raise PreflightInputError("UNBINDABLE_ABI", f"{scope} input type is invalid")
            if abi_type.startswith("tuple"):
                validate_inputs(item.get("components"), f"{scope}.{input_name}")
        if len(names) != len(set(names)):
            raise PreflightInputError(
                "UNBINDABLE_ABI", f"{scope} inputs contain duplicate names"
            )

    validate_inputs(function.get("inputs"), name)


ROLE_LABELS = {
    "recipient": {"to", "recipient", "destination", "receiver"},
    "amount": {"amount", "value", "quantity"},
    "spender": {"spender"},
    "operator": {"operator"},
    "approved": {"approved", "approval", "enabled"},
    "token_id": {"token id", "tokenid", "id"},
    "sender": {"from", "sender"},
    "contract": {"to", "contract", "destination"},
    "native_value": {"amount", "value", "eth amount", "native value"},
}


def _label_matches_role(role: str, label: str) -> bool:
    normalized = " ".join(label.lower().replace("_", " ").split())
    return normalized in ROLE_LABELS[role]


def _expected_input_roles(function: dict) -> dict[str, str]:
    """Assign deterministic roles only for call patterns Lucent classifies."""
    inputs = function.get("inputs", [])
    name = function.get("name", "").lower()
    roles: dict[str, str] = {}

    def candidates(prefix: str) -> list[dict]:
        return [
            item
            for item in inputs
            if isinstance(item, dict) and item.get("type", "").startswith(prefix)
        ]

    def choose(items: list[dict], hints: tuple[str, ...]) -> dict | None:
        return next(
            (
                item
                for item in items
                if any(hint in item.get("name", "").lower().strip("_") for hint in hints)
            ),
            items[0] if items else None,
        )

    if "transfer" in name or name in ("send", "withdraw") or (
        function.get("stateMutability") == "payable"
    ):
        recipient = choose(
            candidates("address"), ("to", "recipient", "receiver", "destination", "dst")
        )
        amount = choose(candidates("uint"), ("amount", "value", "quantity", "qty"))
        if recipient:
            roles[recipient["name"]] = "recipient"
        if amount:
            roles[amount["name"]] = "amount"
    if name == "setapprovalforall":
        operator = choose(candidates("address"), ("operator", "spender"))
        approved = choose(candidates("bool"), ("approved", "enabled", "allow"))
        if operator:
            roles[operator["name"]] = "operator"
        if approved:
            roles[approved["name"]] = "approved"
    elif name == "approve":
        address = choose(candidates("address"), ("spender", "to", "operator"))
        numeric = choose(candidates("uint"), ("amount", "allowance", "tokenid", "token_id"))
        nft = numeric and "tokenid" in numeric.get("name", "").lower().replace("_", "")
        if address:
            roles[address["name"]] = "recipient" if nft else "spender"
        if numeric:
            roles[numeric["name"]] = "token_id" if nft else "amount"
    return roles


def _normalize_ui_text(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _intent_matches_known_action(
    function: dict,
    fmt: dict,
    decoded: list[dict] | None,
) -> bool:
    """Bind known-action prose to a small, deterministic template set.

    Prefix checks are not enough here: ``Send 0 tokens`` starts with ``send``
    but can contradict calldata carrying a non-zero amount. Lucent therefore
    accepts only exact, policy-owned action text and exact placeholders for the
    roles it can classify. Unknown functions are handled by the comprehension
    gate and never become clear merely because caller prose sounds reassuring.
    """
    name = function.get("name", "").lower()
    roles = _expected_input_roles(function)
    by_role = {role: input_name for input_name, role in roles.items()}
    decoded_by_name = {
        item.get("name"): item.get("value")
        for item in (decoded or [])
        if isinstance(item, dict)
    }
    allowed_intents: set[str]
    allowed_interpolated: set[str]

    if "transfer" in name or name == "send":
        recipient = by_role.get("recipient")
        amount = by_role.get("amount")
        if not recipient or not amount:
            return False
        allowed_intents = {"send tokens", "transfer tokens"}
        allowed_interpolated = {
            f"send {{{amount}}} to {{{recipient}}}",
            f"transfer {{{amount}}} to {{{recipient}}}",
        }
    elif name == "approve":
        if "token_id" in by_role:
            recipient = by_role.get("recipient")
            token_id = by_role.get("token_id")
            if not recipient or not token_id:
                return False
            allowed_intents = {"approve nft"}
            allowed_interpolated = {
                f"approve {{{recipient}}} for token {{{token_id}}}",
            }
        else:
            spender = by_role.get("spender")
            amount = by_role.get("amount")
            if not spender or not amount:
                return False
            is_revocation = decoded_by_name.get(amount) == "0" if decoded is not None else None
            grant_intents = {"approve token spending", "set allowance"}
            revoke_intents = {"revoke token spending", "revoke allowance"}
            grant_interpolated = {
                f"approve {{{spender}}} to spend {{{amount}}}",
                f"set {{{spender}}} allowance to {{{amount}}}",
            }
            revoke_interpolated = {
                f"revoke {{{spender}}} allowance",
                f"revoke {{{spender}}} token allowance",
            }
            if is_revocation is True:
                allowed_intents = revoke_intents
                allowed_interpolated = revoke_interpolated
            elif is_revocation is False:
                allowed_intents = grant_intents
                allowed_interpolated = grant_interpolated
            else:
                allowed_intents = grant_intents | revoke_intents
                allowed_interpolated = grant_interpolated | revoke_interpolated
    elif name == "setapprovalforall":
        operator = by_role.get("operator")
        approved = by_role.get("approved")
        if not operator or not approved:
            return False
        is_revocation = decoded_by_name.get(approved) is False if decoded is not None else None
        grant_intents = {"set operator", "approve operator"}
        revoke_intents = {"revoke operator"}
        grant_interpolated = {
            f"approve {{{operator}}} as operator",
            f"set {{{operator}}} as operator",
        }
        revoke_interpolated = {f"revoke {{{operator}}} as operator"}
        if is_revocation is True:
            allowed_intents = revoke_intents
            allowed_interpolated = revoke_interpolated
        elif is_revocation is False:
            allowed_intents = grant_intents
            allowed_interpolated = grant_interpolated
        else:
            allowed_intents = grant_intents | revoke_intents
            allowed_interpolated = grant_interpolated | revoke_interpolated
    else:
        return True

    intent = fmt.get("intent")
    if not isinstance(intent, str) or _normalize_ui_text(intent) not in allowed_intents:
        return False
    interpolated = fmt.get("interpolatedIntent")
    return interpolated is None or (
        isinstance(interpolated, str)
        and _normalize_ui_text(interpolated) in allowed_interpolated
    )


def _presentation_binding(
    function: dict,
    fmt: dict | None,
    value: int,
    decoded: list[dict] | None = None,
) -> dict:
    """Prove that visible fields resolve to, and cover, the signed call values."""
    if not isinstance(fmt, dict):
        return {"complete": False, "findings": []}
    inputs = function.get("inputs", [])
    by_name = {
        item.get("name"): item
        for item in inputs
        if isinstance(item, dict) and isinstance(item.get("name"), str) and item.get("name")
    }
    visible_paths: set[tuple[str, ...]] = set()
    visible_value_fields: list[dict] = []
    findings: list[dict] = []
    expected_roles = _expected_input_roles(function)

    if not _intent_matches_known_action(function, fmt, decoded):
        findings.append({
            "severity": "CRITICAL",
            "code": "INTENT_ACTION_MISMATCH",
            "issue": "descriptor intent is not bound to the classified call action and values",
        })

    for field in fmt.get("fields", []):
        path = field.get("path")
        visible = field.get("visible") not in ("never",) and field.get("visible") in (
            None,
            "always",
        )
        if path in ("@.from", "@.to"):
            if visible and field.get("format") != "addressName":
                findings.append({
                    "severity": "CRITICAL",
                    "code": "FIELD_FORMAT_MISMATCH",
                    "abi_type": "address",
                    "format": field.get("format"),
                    "issue": "sender and destination must use the addressName display format",
                })
            role = "sender" if path == "@.from" else "contract"
            if visible and not _label_matches_role(role, field["label"]):
                findings.append({
                    "severity": "CRITICAL",
                    "code": "ROLE_LABEL_MISMATCH",
                    "issue": "container field label contradicts its transaction role",
                })
            continue
        if path == "@.value":
            if visible and field.get("format") != "amount":
                findings.append({
                    "severity": "CRITICAL",
                    "code": "FIELD_FORMAT_MISMATCH",
                    "path": path,
                    "abi_type": "uint256",
                    "format": field.get("format"),
                    "issue": "native value must use the amount display format",
                })
            elif visible:
                visible_value_fields.append(field)
                if not _label_matches_role("native_value", field["label"]):
                    findings.append({
                        "severity": "CRITICAL",
                        "code": "ROLE_LABEL_MISMATCH",
                        "issue": "native-value label contradicts its transaction role",
                    })
            continue
        if not isinstance(path, str) or not path.startswith("#."):
            findings.append({
                "severity": "CRITICAL",
                "code": "UNSUPPORTED_FIELD_PATH",
                "path": path,
                "issue": "display field path is outside the supported call/value namespaces",
            })
            continue
        segments = path[2:].split(".")
        root = segments[0] if segments else ""
        input_abi = by_name.get(root)
        target = _path_target(input_abi, segments[1:]) if input_abi is not None else None
        if not root or target is None:
            findings.append({
                "severity": "CRITICAL",
                "code": "FIELD_PATH_UNRESOLVED",
                "path": path,
                "issue": "display field path does not resolve against the selected ABI",
            })
            continue
        target_type = target.get("type")
        if visible and (
            not isinstance(target_type, str)
            or not _format_matches_abi(target_type, field.get("format"))
        ):
            findings.append({
                "severity": "CRITICAL",
                "code": "FIELD_FORMAT_MISMATCH",
                "path": path,
                "abi_type": target_type,
                "format": field.get("format"),
                "issue": "display field format is incompatible with the selected ABI value",
            })
            continue
        if visible and target_type == "address" and field.get("format") != "addressName":
            findings.append({
                "severity": "CRITICAL",
                "code": "RAW_ADDRESS_PRESENTATION",
                "argument": ".".join(segments),
                "issue": "an address value is not rendered with addressName",
            })
            continue
        if visible and field.get("format") in UNVERIFIED_FIELD_FORMATS:
            findings.append({
                "severity": "CRITICAL",
                "code": "FORMAT_ASSURANCE_UNSUPPORTED",
                "argument": ".".join(segments),
                "format": field.get("format"),
                "issue": "this formatter requires resolution semantics outside the v1 profile",
            })
            continue
        if visible and field.get("params"):
            findings.append({
                "severity": "CRITICAL",
                "code": "FORMAT_ASSURANCE_UNSUPPORTED",
                "argument": ".".join(segments),
                "format": field.get("format"),
                "issue": "formatter parameters are outside the deterministic v1 profile",
            })
            continue
        expected_role = expected_roles.get(root) if len(segments) == 1 else None
        if visible and expected_role and not _label_matches_role(expected_role, field["label"]):
            findings.append({
                "severity": "CRITICAL",
                "code": "ROLE_LABEL_MISMATCH",
                "argument": ".".join(segments),
                "issue": "field label contradicts the ABI argument's transaction role",
            })
            continue
        if visible:
            visible_paths.add(tuple(segments))

    for item in inputs:
        name = item.get("name") if isinstance(item, dict) else None
        required_paths = _abi_leaf_paths(item, (name,)) if name else [(None,)]
        for required_path in required_paths:
            covered = required_path in visible_paths
            if covered:
                if len(required_path) == 1:
                    continue
                findings.append({
                    "severity": "CRITICAL",
                    "code": (
                        "COLLECTION_NOT_EXPANDED"
                        if "[]" in required_path
                        else "STRUCTURED_VALUE_UNSUPPORTED"
                    ),
                    "argument": ".".join(part for part in required_path if part),
                    "issue": "container rendering does not prove every signed leaf is visible",
                })
                continue
            findings.append({
                "severity": "CRITICAL",
                "code": "ARGUMENT_NOT_VISIBLE",
                "argument": ".".join(part for part in required_path if part) or None,
                "issue": "a signed ABI value has no universally visible display field",
            })

    if value > 0 and not any(
        field.get("visible") == "always" and field.get("format") == "amount"
        for field in visible_value_fields
    ):
        findings.append({
            "severity": "CRITICAL",
            "code": "VALUE_NOT_VISIBLE",
            "path": "@.value",
            "issue": "nonzero native value is not rendered as an always-visible amount",
        })
    if decoded is not None:
        for item in decoded:
            stack = [item.get("value")]
            while stack:
                rendered = stack.pop()
                if isinstance(rendered, list):
                    stack.extend(rendered)
                elif isinstance(rendered, dict) and rendered.get("truncated") is True:
                    findings.append({
                        "severity": "CRITICAL",
                        "code": "OPAQUE_VALUE_TRUNCATED",
                        "argument": item.get("name"),
                        "issue": "a signed byte value exceeds the bounded human-readable preview",
                    })
                elif isinstance(rendered, str) and len(rendered) > 256:
                    findings.append({
                        "severity": "CRITICAL",
                        "code": "OPAQUE_VALUE_TOO_LONG",
                        "argument": item.get("name"),
                        "issue": "a signed string value is too long for complete human review",
                    })
    return {"complete": not findings, "findings": findings}


def _selected_descriptor(function: dict, signature: str, fmt: dict | None) -> dict:
    formats = {signature: fmt} if isinstance(fmt, dict) else {}
    return {
        "context": {"contract": {"abi": [function]}},
        "display": {"formats": formats},
    }


def _severity_present(findings: list[dict], *levels: str) -> bool:
    wanted = set(levels)
    return any(finding.get("severity") in wanted for finding in findings)


def overall_verdict(audit_r: dict, danger_r: dict, comp_r: dict) -> dict:
    """Descriptor-wide compatibility policy used by the legacy MCP tool.

    Findings, not aggregate grades, drive the gate. Aggregate grades are
    contract-size-sensitive and previously allowed a CRITICAL presentation
    failure to return ``safe_to_present``.
    """
    if danger_r.get("signable_functions", 0) == 0:
        return {
            "gate": "block",
            "code": "NO_SIGNABLE_FUNCTIONS",
            "reason": "the ABI contains no transaction function Lucent can assess",
        }
    audit_findings = audit_r.get("findings") or []
    danger_findings = danger_r.get("danger_findings") or []
    if _severity_present(audit_findings, "CRITICAL"):
        return {
            "gate": "block",
            "code": "PRESENTATION_CRITICAL",
            "reason": "a CRITICAL presentation defect hides information required to sign",
        }
    if _severity_present(danger_findings, "CRITICAL"):
        return {
            "gate": "block",
            "code": "DANGER_CRITICAL",
            "reason": "the ABI exposes a CRITICAL structural danger primitive",
        }
    if _severity_present(audit_findings, "HIGH", "MEDIUM"):
        return {
            "gate": "review",
            "code": "PRESENTATION_REVIEW",
            "reason": "the descriptor has presentation findings requiring human review",
        }
    if comp_r.get("worst_tier") in ("CRITICAL", "HIGH"):
        return {
            "gate": "review",
            "code": "COMPREHENSION_REVIEW",
            "reason": "at least one function has a high-consequence authorization",
        }
    if _severity_present(danger_findings, "HIGH", "MEDIUM"):
        return {
            "gate": "review",
            "code": "DANGER_REVIEW",
            "reason": "the ABI exposes a structural capability requiring human review",
        }
    return {
        "gate": "safe_to_present",
        "code": "PRESENTATION_CLEAR",
        "reason": "no blocking presentation defect or known ABI-pattern danger was found",
    }


def _call_verdict(
    audit_r: dict,
    comprehension_r: dict,
    danger_findings: list[dict],
    *,
    has_format: bool,
) -> dict:
    if not has_format:
        return {
            "gate": "block",
            "code": "MISSING_CLEAR_SIGNING_FORMAT",
            "reason": "the selected function has no exact clear-signing format",
        }
    audit_findings = audit_r.get("findings") or []
    if _severity_present(audit_findings, "CRITICAL"):
        return {
            "gate": "block",
            "code": "PRESENTATION_CRITICAL",
            "reason": "the selected screen hides information required to sign",
        }
    if _severity_present(danger_findings, "CRITICAL"):
        return {
            "gate": "block",
            "code": "DANGER_CRITICAL",
            "reason": "the selected function exposes a CRITICAL ABI-pattern danger",
        }
    if comprehension_r.get("tier") in ("CRITICAL", "HIGH"):
        code = (
            "UNLIMITED_APPROVAL"
            if comprehension_r.get("unlimited_approval")
            else "COMPREHENSION_REVIEW"
        )
        return {
            "gate": "review",
            "code": code,
            "reason": comprehension_r.get("reason") or "high-consequence authorization",
        }
    if _severity_present(audit_findings, "HIGH", "MEDIUM"):
        return {
            "gate": "review",
            "code": "PRESENTATION_REVIEW",
            "reason": "the selected screen has presentation findings requiring review",
        }
    if _severity_present(danger_findings, "HIGH", "MEDIUM"):
        return {
            "gate": "review",
            "code": "DANGER_REVIEW",
            "reason": "the selected function has a structural capability requiring review",
        }
    return {
        "gate": "safe_to_present",
        "code": "PRESENTATION_CLEAR",
        "reason": "the selected call is clear enough to present to a signer",
    }


def _binding_verdict(binding_r: dict) -> dict | None:
    if not binding_r["findings"]:
        return None
    return {
        "gate": "block",
        "code": "PRESENTATION_UNBOUND",
        "reason": "the selected screen does not visibly bind every signed call value",
    }


def _value_verdict(function: dict, value: int) -> dict | None:
    """Block native value that the selected ABI does not declare payable."""
    if value == 0:
        return None
    mutability = function.get("stateMutability")
    is_payable = mutability == "payable" if mutability is not None else (
        function.get("payable") is True
    )
    if is_payable:
        return None
    return {
        "gate": "block",
        "code": "NONPAYABLE_WITH_VALUE",
        "reason": "the transaction sends native value to a function not declared payable",
    }


def _apply_call_dependent_comprehension(
    function: dict, decoded: list[dict], comprehension_r: dict
) -> dict:
    """Refine ABI-level prose with revocation/grant values from exact calldata."""
    name = function.get("name", "").lower()
    by_name = {item["name"].lower(): item for item in decoded}
    if name == "setapprovalforall":
        approved = next(
            (item for item in decoded if item["type"] == "bool"),
            None,
        )
        if approved and approved["value"] is False:
            operator = next(
                (item["name"] for item in decoded if item["type"] == "address"),
                "operator",
            )
            return {
                **comprehension_r,
                "tier": "LOW",
                "revocation": True,
                "reason": "removes an operator's collection-wide transfer authority",
                "sentence": f"You revoke {{{operator}}}'s authority over all tokens.",
            }
        return comprehension_r
    if name != "approve":
        return comprehension_r
    amount = next(
        (item for item in decoded if item["type"].startswith("uint")),
        None,
    )
    if amount is None or "tokenid" in amount["name"].lower():
        return comprehension_r
    if amount["value"] == "0":
        spender = by_name.get("spender") or next(
            (item for item in decoded if item["type"] == "address"),
            {"name": "spender"},
        )
        return {
            **comprehension_r,
            "tier": "LOW",
            "revocation": True,
            "reason": "sets the fungible-token allowance to zero, revoking future spending",
            "sentence": f"You revoke {{{spender['name']}}}'s token allowance.",
        }
    if amount["value"] != str(UINT256_MAX):
        return comprehension_r
    return {
        **comprehension_r,
        "tier": "CRITICAL",
        "unlimited_approval": True,
        "reason": "the calldata grants the maximum uint256 allowance, allowing the spender "
                  "to pull tokens until the approval is changed or revoked",
    }


def _apply_call_dependent_danger(
    function: dict, decoded: list[dict], findings: list[dict]
) -> list[dict]:
    if function.get("name", "").lower() != "setapprovalforall":
        return findings
    approved = next((item for item in decoded if item["type"] == "bool"), None)
    if approved and approved["value"] is False:
        return [
            finding
            for finding in findings
            if finding.get("primitive") != "unbounded-delegation"
        ]
    return findings


def check_descriptor(args: dict) -> dict:
    """Compatibility analysis for descriptor-authoring and the existing MCP tool."""
    if not isinstance(args, dict) or "descriptor" not in args:
        raise PreflightInputError("MISSING_DESCRIPTOR", "descriptor is required")
    descriptor, abi, formats = validate_descriptor(args["descriptor"])
    audit_r = audit.audit(descriptor)
    comp_r = comprehend.comprehend(descriptor)
    danger_r = danger.scan(descriptor)
    binding_functions = []
    for function in common.signable_functions(abi):
        signature = common.signature(function)
        try:
            _validate_selected_function(function)
            potential_value = 1 if (
                function.get("stateMutability") == "payable"
                or function.get("payable") is True
            ) else 0
            binding = _presentation_binding(
                function, formats.get(signature), potential_value
            )
        except PreflightInputError as exc:
            binding = {
                "complete": False,
                "findings": [{
                    "severity": "CRITICAL",
                    "code": exc.code,
                    "issue": exc.message,
                }],
            }
        binding_functions.append({"function": signature, **binding})
    binding_findings = [
        finding
        for function_result in binding_functions
        for finding in function_result["findings"]
    ]
    verdict = overall_verdict(audit_r, danger_r, comp_r)
    if binding_findings:
        verdict = {
            "gate": "block",
            "code": "PRESENTATION_UNBOUND",
            "reason": "at least one function does not visibly bind every signed ABI value",
        }
    return {
        "api_version": API_VERSION,
        "policy_version": POLICY_VERSION,
        "analysis_scope": "static_full_descriptor",
        "verdict": verdict,
        "audit": {
            "grade": audit_r["grade"],
            "score": audit_r["score"],
            "findings": audit_r["findings"],
        },
        "comprehension": {
            "grade": comp_r["comprehension_grade"],
            "worst_tier": comp_r["worst_tier"],
            "functions": comp_r["functions"],
        },
        "danger": danger_r,
        "presentation_binding": {
            "complete": not binding_findings,
            "functions": binding_functions,
        },
        "assurance": {
            "descriptor_source": "caller_supplied",
            "abi_source": "caller_supplied_or_local_cache",
            "transaction_bound": False,
            "bytecode_verified": False,
            "runtime_simulated": False,
        },
        "limitations": LIMITATIONS,
    }


def explain_signature(args: dict) -> dict:
    if not isinstance(args, dict):
        raise PreflightInputError("INVALID_REQUEST", "arguments must be a JSON object")
    descriptor, _abi, _formats = validate_descriptor(args.get("descriptor"))
    signature = args.get("signature")
    function_name = args.get("function")
    comp_r = comprehend.comprehend(descriptor)
    if signature:
        matches = [item for item in comp_r["functions"] if item["signature"] == signature]
    else:
        matches = [item for item in comp_r["functions"] if item["function"] == function_name]
    if len(matches) > 1:
        return {
            "found": False,
            "reason": "function name is overloaded; provide the full canonical signature",
            "available": [item["signature"] for item in matches],
        }
    if not matches:
        return {
            "found": False,
            "reason": "no matching signable function in the descriptor",
            "available": [item["signature"] for item in comp_r["functions"]],
        }
    return {"found": True, **matches[0], "descriptor_text_is_untrusted": True}


def scan_contract(args: dict) -> dict:
    if not isinstance(args, dict):
        raise PreflightInputError("INVALID_REQUEST", "arguments must be a JSON object")
    try:
        chain_id = common.normalize_chain_id(args.get("chain_id", 1))
        address = common.normalize_address(args.get("address"))
    except ValueError as exc:
        raise PreflightInputError("INVALID_CONTRACT", str(exc)) from exc
    try:
        abi = common.sourcify_abi(chain_id, address)
    except Exception:  # network details and URLs are intentionally not exposed
        return {
            "matched": False,
            "chain_id": chain_id,
            "address": address,
            "reason": "verified ABI source is temporarily unavailable",
        }
    if not abi:
        return {
            "matched": False,
            "chain_id": chain_id,
            "address": address,
            "reason": "no verified ABI on Sourcify for this address",
        }
    try:
        abi = common.validate_abi(abi)
    except ValueError:
        return {
            "matched": False,
            "chain_id": chain_id,
            "address": address,
            "reason": "verified ABI source returned an invalid ABI",
        }
    descriptor = {"context": {"contract": {"abi": abi}}, "display": {"formats": {}}}
    danger_r = danger.scan(descriptor)
    return {
        "matched": True,
        "chain_id": chain_id,
        "address": address,
        "abi_source": "sourcify_verified_metadata",
        **danger_r,
    }


def preflight_transaction(args: dict) -> dict:
    """Analyze exactly one unsigned EVM call and bind the result to its bytes."""
    if not isinstance(args, dict):
        raise PreflightInputError("INVALID_REQUEST", "request must be a JSON object")
    unknown_request_fields = set(args) - {"transaction", "descriptor"}
    if unknown_request_fields:
        raise PreflightInputError(
            "UNKNOWN_REQUEST_FIELD",
            f"unsupported request field: {sorted(unknown_request_fields)[0]}",
        )
    transaction = args.get("transaction")
    if not isinstance(transaction, dict):
        raise PreflightInputError("INVALID_TRANSACTION", "transaction must be a JSON object")
    unknown_transaction_fields = set(transaction) - {
        "chain_id",
        "from",
        "to",
        "data",
        "value",
    }
    if unknown_transaction_fields:
        raise PreflightInputError(
            "UNKNOWN_TRANSACTION_FIELD",
            f"unsupported transaction field: {sorted(unknown_transaction_fields)[0]}",
        )
    try:
        chain_id = common.normalize_chain_id(transaction.get("chain_id"))
        sender = common.normalize_address(transaction.get("from"))
        address = common.normalize_address(transaction.get("to"))
    except ValueError as exc:
        raise PreflightInputError("INVALID_TRANSACTION", str(exc)) from exc
    calldata = parse_calldata(transaction.get("data"))
    value = parse_value(transaction.get("value", "0x0"))
    descriptor, abi, formats = validate_descriptor(args.get("descriptor"))

    contract = descriptor.get("context", {}).get("contract", {})
    if not isinstance(contract, dict) or not isinstance(contract.get("abi"), list):
        raise PreflightInputError(
            "INLINE_ABI_REQUIRED",
            "v1 transaction preflight requires context.contract.abi inline",
        )

    if not _deployment_matches(descriptor, chain_id, address):
        raise PreflightInputError(
            "DEPLOYMENT_MISMATCH",
            "descriptor deployments do not bind to transaction chain_id and to address",
        )

    function, signature = _resolve_call(abi, calldata)
    _validate_selected_function(function)
    decoded = _decode_arguments(function, calldata)
    fmt = formats.get(signature)
    selected = _selected_descriptor(function, signature, fmt)
    audit_r = audit.audit(selected)
    comprehension_r = comprehend.classify(function, fmt if isinstance(fmt, dict) else None)
    comprehension_r = _apply_call_dependent_comprehension(function, decoded, comprehension_r)
    danger_findings = danger.assess(function)
    danger_findings = _apply_call_dependent_danger(function, decoded, danger_findings)
    danger_findings.sort(key=lambda finding: danger.SEV_ORDER.index(finding["severity"]))
    binding_r = _presentation_binding(function, fmt, value, decoded)
    analyzer_verdict = _call_verdict(
        audit_r,
        comprehension_r,
        danger_findings,
        has_format=isinstance(fmt, dict),
    )
    verdict = _value_verdict(function, value)
    if verdict is None and analyzer_verdict["gate"] == "block":
        verdict = analyzer_verdict
    if verdict is None:
        verdict = _binding_verdict(binding_r) or analyzer_verdict

    normalized_request = {
        "transaction": {
            "chain_id": chain_id,
            "from": sender,
            "to": address,
            "data": "0x" + calldata.hex(),
            "value": hex(value),
        },
        "descriptor": descriptor,
    }
    selector = "0x" + calldata[:4].hex()
    return {
        "api_version": API_VERSION,
        "policy_version": POLICY_VERSION,
        "analysis_scope": ANALYSIS_SCOPE,
        "call_fingerprint": _fingerprint(normalized_request),
        "call": {
            "chain_id": chain_id,
            "from": sender,
            "to": address,
            "selector": selector,
            "function": signature,
            "value": hex(value),
            "decoded_arguments": decoded,
        },
        "verdict": verdict,
        "presentation": {
            "sentence_template": comprehension_r["sentence"],
            "tier": comprehension_r["tier"],
            "reason": comprehension_r["reason"],
            "source": "lucent_policy_generated",
            "descriptor_prose_included": False,
            "descriptor_text_is_untrusted": True,
        },
        "checks": {
            "audit": {
                "grade": audit_r["grade"],
                "score": audit_r["score"],
                "findings": audit_r["findings"],
            },
            "comprehension": comprehension_r,
            "presentation_binding": binding_r,
            "danger": {
                "worst_severity": danger_findings[0]["severity"] if danger_findings else None,
                "findings": danger_findings,
            },
        },
        "assurance": {
            "descriptor_source": "caller_supplied",
            "abi_source": "caller_supplied_inline",
            "descriptor_semantics_verified": False,
            "deployment_match": True,
            "sender_bound": True,
            "selector_and_calldata_decoded": True,
            "bytecode_verified": False,
            "runtime_simulated": False,
        },
        "limitations": LIMITATIONS,
    }
