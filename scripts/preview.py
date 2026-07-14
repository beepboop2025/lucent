#!/usr/bin/env python3
"""Render the on-device Clear Signing screen for a transaction, using a
hardened ERC-7730 descriptor. Also emits registry-format test vectors.

This is the "prove what the user sees" stage of the pipeline. It decodes
calldata against the contract ABI, then applies the descriptor's intents,
labels, formats and visibility exactly as a compatible wallet would, so we
can eyeball the signer screen before submitting a PR.

Local rendering is intentionally faithful but not a full wallet: addressName
shows the raw address (no registry name lookup offline), which is the
worst-case the user could see.

Usage:
    python scripts/preview.py            # render built-in samples + write tests
"""

from __future__ import annotations

import json
from pathlib import Path

from eth_abi import decode as abi_decode, encode as abi_encode
from eth_utils import keccak, to_checksum_address
from eth_account import Account

ROOT = Path(__file__).resolve().parent.parent
DESC = ROOT / "registry/ens/calldata-ETHRegistrarController.json"
# Synthetic samples go to a scratch file; the CANONICAL tests file is owned by
# fetch_tx.py (real historical transactions) and must not be clobbered here.
TESTS = ROOT / "registry/ens/tests/_samples.tests.json"

# A well-known throwaway test key (Hardhat account #0). Signs synthetic
# vectors; never holds funds. Real PRs replace these with historical txs.
TEST_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


# ---- formatting helpers (mirror ERC-7730 field formats) --------------------

def fmt_amount_wei(wei: int) -> str:
    eth = wei / 10**18
    return f"{eth:.6f}".rstrip("0").rstrip(".") + " ETH"


def fmt_duration(secs: int) -> str:
    years, rem = divmod(secs, 365 * 86400)
    days, rem = divmod(rem, 86400)
    parts = []
    if years:
        parts.append(f"{years} year" + ("s" if years != 1 else ""))
    if days:
        parts.append(f"{days} day" + ("s" if days != 1 else ""))
    if not parts:
        parts.append(f"{secs} sec")
    return ", ".join(parts)


def fmt_raw(value) -> str:
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return f"{len(value)} item" + ("s" if len(value) != 1 else "")
    return str(value)


def apply_format(fmt: str, value) -> str:
    if fmt == "amount":
        return fmt_amount_wei(int(value))
    if fmt == "duration":
        return fmt_duration(int(value))
    if fmt == "addressName":
        return to_checksum_address(value)
    return fmt_raw(value)


# ---- descriptor plumbing ---------------------------------------------------

def load_descriptor(path=DESC) -> dict:
    return json.loads(Path(path).read_text())


def build_selector_index(abi: list) -> dict:
    """selector(hex) -> (canonical_signature, input list)."""
    idx = {}
    for e in abi:
        if e.get("type") != "function":
            continue
        types = ",".join(_canonical_type(i) for i in e["inputs"])
        sig = f'{e["name"]}({types})'
        sel = "0x" + keccak(text=sig)[:4].hex()
        idx[sel] = (sig, e["inputs"])
    return idx


def _canonical_type(inp: dict) -> str:
    t = inp["type"]
    if t.startswith("tuple"):
        inner = ",".join(_canonical_type(c) for c in inp.get("components", []))
        return f"({inner}){t[len('tuple'):]}"
    return t


def encode_call(inputs: list, args: list) -> bytes:
    types = [_canonical_type(i) for i in inputs]
    return abi_encode(types, args)


def resolve_field_value(path: str, value: int, decoded: dict):
    """Map an ERC-7730 path to a concrete value."""
    if path == "@.value":
        return value
    if path.startswith("#."):
        leaf = path[2:]
        if leaf.endswith(".[]"):
            leaf = leaf[:-3]
        return decoded.get(leaf)
    return None


def descriptor_abi(desc: dict) -> list:
    """ABI for rendering: inline if present, else the Sourcify cache.

    Registry-form descriptors reference the ABI via deployments (no inline
    copy), so fall back to abi_cache/<chain>-<address>.abi.json.
    """
    contract = desc["context"]["contract"]
    if isinstance(contract.get("abi"), list):
        return contract["abi"]
    dep = contract["deployments"][0]
    cached = ROOT / "abi_cache" / f'{dep["chainId"]}-{dep["address"].lower()}.abi.json'
    return json.loads(cached.read_text())


def render(desc: dict, to: str, value: int, data: bytes) -> tuple[str, list[str]]:
    """Return (screen_text, expected_substrings)."""
    abi = descriptor_abi(desc)
    sel_index = build_selector_index(abi)
    selector = "0x" + data[:4].hex()
    sig, inputs = sel_index[selector]
    types = [_canonical_type(i) for i in inputs]
    values = abi_decode(types, data[4:])
    decoded = {i["name"]: v for i, v in zip(inputs, values)}

    fmt = desc["display"]["formats"][sig]

    # Intent line (interpolate {field} / {@.value}).
    intent = fmt.get("interpolatedIntent") or fmt.get("intent", sig)
    for i in inputs:
        token = "{" + i["name"] + "}"
        if token in intent:
            intent = intent.replace(token, fmt_raw(decoded[i["name"]]))
    intent = intent.replace("{@.value}", fmt_amount_wei(value))

    lines = [f"┌─ {intent}"]
    expected = [fmt.get("intent", "")]
    for field in fmt.get("fields", []):
        if field.get("visible") == "never":
            continue
        raw = resolve_field_value(field["path"], value, decoded)
        if raw is None:
            continue
        shown = apply_format(field.get("format", "raw"), raw)
        lines.append(f"│  {field['label']}: {shown}")
        expected += [field["label"], shown]
    lines.append("└─ [ Reject ]   [ Sign ]")
    return "\n".join(lines), [e for e in expected if e]


# ---- built-in sample transactions ------------------------------------------

VITALIK = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
ENS_RESOLVER = "0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63"


def samples(desc: dict):
    abi = descriptor_abi(desc)
    to = to_checksum_address(desc["context"]["contract"]["deployments"][0]["address"])
    byname = {e["name"]: e["inputs"] for e in abi if e.get("type") == "function"}

    reg_args = ["vitalik-test", VITALIK, 31536000,
                b"\x00" * 31 + b"\x01", ENS_RESOLVER, [], True, 0]
    reg_data = keccak(text="register(string,address,uint256,bytes32,address,bytes[],bool,uint16)")[:4] \
        + encode_call(byname["register"], reg_args)

    renew_args = ["vitalik-test", 63072000]
    renew_data = keccak(text="renew(string,uint256)")[:4] + encode_call(byname["renew"], renew_args)

    commit_args = [b"\xab" * 32]
    commit_data = keccak(text="commit(bytes32)")[:4] + encode_call(byname["commit"], commit_args)

    return to, [
        ("Register vitalik-test.eth for 1 year", to, 5 * 10**15, reg_data),
        ("Renew vitalik-test.eth for 2 years", to, 10 * 10**15, renew_data),
        ("Commit (opaque hash — honest handling)", to, 0, commit_data),
    ]


def signed_raw_tx(to: str, value: int, data: bytes, nonce: int) -> str:
    tx = {
        "type": 2, "chainId": 1, "nonce": nonce,
        "maxPriorityFeePerGas": 1_000_000_000, "maxFeePerGas": 30_000_000_000,
        "gas": 300_000, "to": to_checksum_address(to), "value": value,
        "data": "0x" + data.hex(),
    }
    signed = Account.sign_transaction(tx, TEST_KEY)
    return signed.raw_transaction.hex()


def main() -> int:
    desc = load_descriptor()
    to, txs = samples(desc)
    vectors = []
    print("=" * 62)
    print(" ON-DEVICE PREVIEW — ENS ETHRegistrarController (Clear Signing)")
    print("=" * 62)
    for i, (title, to_, value, data) in enumerate(txs):
        screen, expected = render(desc, to_, value, data)
        print(f"\n### {title}\n")
        print(screen)
        raw = signed_raw_tx(to_, value, data, nonce=i)
        vectors.append({
            "description": title,
            "rawTx": raw if raw.startswith("0x") else "0x" + raw,
            "expectedTexts": expected,
        })

    TESTS.parent.mkdir(parents=True, exist_ok=True)
    TESTS.write_text(json.dumps(
        {"$schema": "../../../specs/erc7730-tests.schema.json", "tests": vectors},
        indent=2))
    print(f"\nwrote {len(vectors)} test vectors -> {TESTS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
