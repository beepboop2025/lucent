"""Shared helpers: verified-source clients (Sourcify, Etherscan) and ABI utilities."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from eth_abi import is_encodable_type
from eth_utils import keccak

ROOT = Path(__file__).resolve().parent.parent
ABI_CACHE = ROOT / "abi_cache"
ZERO_ADDRESS = "0x" + "0" * 40

SOURCIFY = "https://sourcify.dev/server/v2/contract/{chain}/{address}?fields=abi"
ETHERSCAN = "https://api.etherscan.io/v2/api"

VIEW = ("view", "pure")
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
SOLIDITY_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
MAX_CHAIN_ID = (1 << 63) - 1
MAX_ABI_ENTRIES = 1_024
MAX_REMOTE_BYTES = 4 * 1024 * 1024
DEFAULT_REMOTE_TIMEOUT_SECONDS = 10.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A fixed upstream must not redirect analysis into an unexpected network."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        return None


JSON_OPENER = urllib.request.build_opener(_NoRedirect)


def normalize_chain_id(value: object) -> int:
    """Return a bounded positive EVM chain id.

    Chain ids and addresses are used in both remote URLs and cache filenames, so
    validation belongs at the shared boundary rather than in individual callers.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("chain id must be a positive integer")
    chain_id = value
    if chain_id < 1 or chain_id > MAX_CHAIN_ID:
        raise ValueError(f"chain id must be between 1 and {MAX_CHAIN_ID}")
    return chain_id


def normalize_address(value: object) -> str:
    """Validate and lowercase one EVM address without resolving names."""
    if not isinstance(value, str) or not ADDRESS_RE.fullmatch(value):
        raise ValueError("address must be 0x followed by exactly 40 hexadecimal characters")
    return value.lower()


def validate_abi(value: object) -> list:
    """Validate the cheap structural properties needed before analysis.

    Full ABI-schema validation remains the descriptor linter's job. These
    bounds protect hosted and MCP surfaces from surprising types and unbounded
    analyzer work.
    """
    if not isinstance(value, list):
        raise ValueError("contract ABI must be a JSON array")
    if len(value) > MAX_ABI_ENTRIES:
        raise ValueError(f"contract ABI exceeds {MAX_ABI_ENTRIES} entries")
    if any(not isinstance(entry, dict) for entry in value):
        raise ValueError("every contract ABI entry must be a JSON object")
    try:
        encoded = json.dumps(value, separators=(",", ":"), allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise ValueError("contract ABI must contain only finite JSON values") from exc
    if len(encoded) > MAX_REMOTE_BYTES:
        raise ValueError("contract ABI exceeds encoded size limit")

    def validate_inputs(items: object, scope: str) -> None:
        if not isinstance(items, list):
            raise ValueError(f"{scope} inputs must be a JSON array")
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"{scope} input must be a JSON object")
            if not isinstance(item.get("name", ""), str):
                raise ValueError(f"{scope} input name must be a string")
            abi_type = item.get("type")
            if not isinstance(abi_type, str):
                raise ValueError(f"{scope} input type must be a string")
            scalar_type = re.sub(r"(?:\[[0-9]*\])+$", "", abi_type)
            if scalar_type in ("uint", "int", "fixed", "ufixed", "byte"):
                raise ValueError(
                    f"{scope} input type must use its canonical EVM ABI spelling"
                )
            if abi_type.startswith("tuple"):
                validate_inputs(item.get("components"), f"{scope} tuple")
            try:
                encoded_type = canonical_type(item)
            except (KeyError, TypeError, ValueError, AttributeError) as exc:
                raise ValueError(f"{scope} input type is malformed") from exc
            if not is_encodable_type(encoded_type):
                raise ValueError(f"{scope} input type {encoded_type!r} is not an EVM ABI type")

    for entry in value:
        if entry.get("type") != "function":
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not SOLIDITY_IDENTIFIER_RE.fullmatch(name):
            raise ValueError("ABI function name must be a Solidity identifier")
        validate_inputs(entry.get("inputs"), f"ABI function {name!r}")
        mutability = entry.get("stateMutability")
        if mutability is not None and mutability not in ("pure", "view", "nonpayable", "payable"):
            raise ValueError(f"ABI function {name!r} has invalid stateMutability")
        legacy_payable = entry.get("payable")
        if legacy_payable is not None and not isinstance(legacy_payable, bool):
            raise ValueError(f"ABI function {name!r} has invalid payable flag")
        if mutability is not None and legacy_payable is not None:
            if legacy_payable is not (mutability == "payable"):
                raise ValueError(f"ABI function {name!r} has conflicting mutability fields")
    return value


def rel(path) -> str:
    """Path relative to the repo root, or the absolute path if outside it."""
    try:
        return str(Path(path).relative_to(ROOT))
    except ValueError:
        return str(path)


def _get_json(url: str) -> dict:
    try:
        timeout = float(os.environ.get(
            "LUCENT_REMOTE_TIMEOUT_SECONDS", DEFAULT_REMOTE_TIMEOUT_SECONDS,
        ))
    except ValueError:
        timeout = DEFAULT_REMOTE_TIMEOUT_SECONDS
    timeout = min(30.0, max(1.0, timeout))
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "lucent/0.2 (+https://github.com/beepboop2025/lucent)",
    })
    with JSON_OPENER.open(req, timeout=timeout) as resp:
        media_type = (resp.headers.get_content_type() or "").lower()
        if media_type != "application/json" and not media_type.endswith("+json"):
            raise ValueError("remote response is not JSON")
        length = resp.headers.get("Content-Length")
        try:
            declared_length = int(length) if length else None
        except (TypeError, ValueError):
            declared_length = None
        if declared_length is not None and declared_length > MAX_REMOTE_BYTES:
            raise ValueError("remote JSON response exceeds size limit")
        raw = resp.read(MAX_REMOTE_BYTES + 1)
        if len(raw) > MAX_REMOTE_BYTES:
            raise ValueError("remote JSON response exceeds size limit")
        return json.loads(raw)


# --- verified-source clients ------------------------------------------------

def sourcify_contract(chain_id: int, address: str) -> dict:
    """Raw Sourcify response (abi + match status). Raises on HTTP error."""
    chain_id = normalize_chain_id(chain_id)
    address = normalize_address(address)
    return _get_json(SOURCIFY.format(chain=chain_id, address=address.lower()))


def sourcify_abi(chain_id: int, address: str) -> list | None:
    """Verified ABI, or None if the contract is not verified on Sourcify.
    Verification is required before the registry accepts a descriptor."""
    try:
        abi = sourcify_contract(chain_id, address).get("abi")
        return validate_abi(abi) if abi is not None else None
    except urllib.error.HTTPError as e:
        if e.code in (400, 404):
            return None
        raise


def etherscan(**params) -> dict:
    """Call the Etherscan v2 unified API. Requires ETHERSCAN_API_KEY."""
    params["apikey"] = os.environ["ETHERSCAN_API_KEY"]
    return _get_json(ETHERSCAN + "?" + urllib.parse.urlencode(params))


def etherscan_abi(chain_id: int, address: str) -> list | None:
    """ABI from Etherscan (the source erc7730 lint uses); None if unverified."""
    chain_id = normalize_chain_id(chain_id)
    address = normalize_address(address)
    resp = etherscan(chainid=chain_id, module="contract", action="getabi", address=address)
    if resp.get("status") != "1":
        return None
    try:
        return json.loads(resp["result"])
    except json.JSONDecodeError:
        return None


# --- ABI utilities ----------------------------------------------------------

def canonical_type(inp: dict) -> str:
    t = inp["type"]
    if t.startswith("tuple"):
        inner = ",".join(canonical_type(c) for c in inp.get("components", []))
        return f"({inner}){t[len('tuple'):]}"
    return t


def signature(fn: dict) -> str:
    return f'{fn["name"]}({",".join(canonical_type(i) for i in fn["inputs"])})'


def selector(sig: str) -> str:
    return "0x" + keccak(text=sig)[:4].hex()


def signable_functions(abi: list) -> list[dict]:
    """Function entries a user can sign (excludes view/pure)."""
    return [e for e in abi if e.get("type") == "function"
            and e.get("stateMutability") not in VIEW]


def selector_index(abi: list) -> dict:
    """selector -> (signature, inputs) for every function in the ABI."""
    idx = {}
    for fn in abi:
        if fn.get("type") == "function":
            idx[selector(signature(fn))] = (signature(fn), fn["inputs"])
    return idx


def descriptor_abi(desc: dict) -> list:
    """ABI for a descriptor: inline if present, else the cached Sourcify copy
    (registry-form descriptors reference the ABI via deployments)."""
    if not isinstance(desc, dict):
        raise ValueError("descriptor must be a JSON object")
    try:
        contract = desc["context"]["contract"]
    except (KeyError, TypeError) as exc:
        raise ValueError("descriptor must contain context.contract") from exc
    if not isinstance(contract, dict):
        raise ValueError("descriptor context.contract must be a JSON object")
    if isinstance(contract.get("abi"), list):
        return validate_abi(contract["abi"])
    deployments = contract.get("deployments")
    if not isinstance(deployments, list) or not deployments:
        raise ValueError("descriptor must contain an inline ABI or at least one deployment")
    dep = deployments[0]
    if not isinstance(dep, dict):
        raise ValueError("descriptor deployment must be a JSON object")
    chain_id = normalize_chain_id(dep.get("chainId"))
    address = normalize_address(dep.get("address"))
    cached = ABI_CACHE / f"{chain_id}-{address}.abi.json"
    try:
        return validate_abi(json.loads(cached.read_text()))
    except FileNotFoundError as exc:
        raise ValueError(
            f"verified ABI is not cached for deployment {chain_id}:{address}"
        ) from exc
