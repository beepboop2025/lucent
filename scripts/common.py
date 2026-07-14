"""Shared helpers: verified-source clients (Sourcify, Etherscan) and ABI utilities."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from eth_utils import keccak

ROOT = Path(__file__).resolve().parent.parent
ABI_CACHE = ROOT / "abi_cache"
ZERO_ADDRESS = "0x" + "0" * 40

SOURCIFY = "https://sourcify.dev/server/v2/contract/{chain}/{address}?fields=abi"
ETHERSCAN = "https://api.etherscan.io/v2/api"

VIEW = ("view", "pure")


def rel(path) -> str:
    """Path relative to the repo root, or the absolute path if outside it."""
    try:
        return str(Path(path).relative_to(ROOT))
    except ValueError:
        return str(path)


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


# --- verified-source clients ------------------------------------------------

def sourcify_contract(chain_id: int, address: str) -> dict:
    """Raw Sourcify response (abi + match status). Raises on HTTP error."""
    return _get_json(SOURCIFY.format(chain=chain_id, address=address.lower()))


def sourcify_abi(chain_id: int, address: str) -> list | None:
    """Verified ABI, or None if the contract is not verified on Sourcify.
    Verification is required before the registry accepts a descriptor."""
    try:
        return sourcify_contract(chain_id, address).get("abi")
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
    contract = desc["context"]["contract"]
    if isinstance(contract.get("abi"), list):
        return contract["abi"]
    dep = contract["deployments"][0]
    cached = ABI_CACHE / f'{dep["chainId"]}-{dep["address"].lower()}.abi.json'
    return json.loads(cached.read_text())
