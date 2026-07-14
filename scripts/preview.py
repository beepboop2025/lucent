#!/usr/bin/env python3
"""Render the on-device Clear Signing screen for a transaction, and emit sample
registry test vectors.

Decodes calldata against the contract ABI and applies the descriptor's intents,
labels, formats, and visibility the way a wallet would, so the signer screen can
be checked before submission. addressName shows the raw address (no registry
name lookup offline), which is the worst case a user could see.

    preview.py <descriptor.json>     (default: the ENS controller descriptor)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_utils import keccak, to_checksum_address

import common

DEFAULT_DESC = common.ROOT / "registry/ens/calldata-ETHRegistrarController.json"
SAMPLES_OUT = common.ROOT / "registry/ens/tests/_samples.tests.json"

# Hardhat account #0 — signs synthetic sample vectors only, never holds funds.
TEST_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
VITALIK = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
ENS_RESOLVER = "0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63"


def load_descriptor(path=DEFAULT_DESC) -> dict:
    return json.loads(Path(path).read_text())


def fmt_amount_wei(wei: int) -> str:
    return f"{wei / 10**18:.6f}".rstrip("0").rstrip(".") + " ETH"


def fmt_duration(secs: int) -> str:
    years, rem = divmod(secs, 365 * 86400)
    days, _ = divmod(rem, 86400)
    parts = []
    if years:
        parts.append(f"{years} year" + ("s" if years != 1 else ""))
    if days:
        parts.append(f"{days} day" + ("s" if days != 1 else ""))
    return ", ".join(parts) or f"{secs} sec"


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


def _resolve(path: str, value: int, decoded: dict):
    if path == "@.value":
        return value
    if path.startswith("#."):
        leaf = path[2:]
        if leaf.endswith(".[]"):
            leaf = leaf[:-3]
        return decoded.get(leaf)
    return None


def render(desc: dict, to: str, value: int, data: bytes) -> tuple[str, list[str]]:
    """Return the rendered screen and the list of expected on-screen strings."""
    abi = common.descriptor_abi(desc)
    sig, inputs = common.selector_index(abi)["0x" + data[:4].hex()]
    values = abi_decode([common.canonical_type(i) for i in inputs], data[4:])
    decoded = dict(zip([i["name"] for i in inputs], values))
    fmt = desc["display"]["formats"][sig]

    intent = fmt.get("interpolatedIntent") or fmt.get("intent", sig)
    for i in inputs:
        token = "{" + i["name"] + "}"
        if token in intent:
            intent = intent.replace(token, fmt_raw(decoded[i["name"]]))
    intent = intent.replace("{@.value}", fmt_amount_wei(value))

    lines = [f"| {intent}"]
    expected = [fmt.get("intent", "")]
    for field in fmt.get("fields", []):
        if field.get("visible") == "never":
            continue
        raw = _resolve(field["path"], value, decoded)
        if raw is None:
            continue
        shown = apply_format(field.get("format", "raw"), raw)
        lines.append(f"|   {field['label']}: {shown}")
        expected += [field["label"], shown]
    lines.append("| [ Reject ]   [ Sign ]")
    return "\n".join(lines), [e for e in expected if e]


def _encode(inputs: list, args: list) -> bytes:
    return abi_encode([common.canonical_type(i) for i in inputs], args)


def samples(desc: dict):
    abi = common.descriptor_abi(desc)
    to = to_checksum_address(desc["context"]["contract"]["deployments"][0]["address"])
    inputs = {e["name"]: e["inputs"] for e in abi if e.get("type") == "function"}

    reg = _encode(inputs["register"],
                  ["vitalik-test", VITALIK, 31536000, b"\x00" * 31 + b"\x01",
                   ENS_RESOLVER, [], True, 0])
    reg_data = keccak(text=common.signature({"name": "register", "inputs": inputs["register"]}))[:4] + reg
    renew_data = keccak(text=common.signature({"name": "renew", "inputs": inputs["renew"]}))[:4] \
        + _encode(inputs["renew"], ["vitalik-test", 63072000])
    commit_data = keccak(text="commit(bytes32)")[:4] + _encode(inputs["commit"], [b"\xab" * 32])

    return [
        ("Register vitalik-test.eth for 1 year", to, 5 * 10**15, reg_data),
        ("Renew vitalik-test.eth for 2 years", to, 10 * 10**15, renew_data),
        ("Commit", to, 0, commit_data),
    ]


def signed_raw_tx(to: str, value: int, data: bytes, nonce: int) -> str:
    tx = {"type": 2, "chainId": 1, "nonce": nonce,
          "maxPriorityFeePerGas": 1_000_000_000, "maxFeePerGas": 30_000_000_000,
          "gas": 300_000, "to": to_checksum_address(to), "value": value,
          "data": "0x" + data.hex()}
    raw = Account.sign_transaction(tx, TEST_KEY).raw_transaction.hex()
    return raw if raw.startswith("0x") else "0x" + raw


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("descriptor", nargs="?", default=DEFAULT_DESC)
    args = ap.parse_args()

    desc = load_descriptor(args.descriptor)
    vectors = []
    for i, (title, to, value, data) in enumerate(samples(desc)):
        screen, expected = render(desc, to, value, data)
        print(f"\n{title}\n{screen}")
        vectors.append({"description": title, "rawTx": signed_raw_tx(to, value, data, i),
                        "expectedTexts": expected})

    SAMPLES_OUT.parent.mkdir(parents=True, exist_ok=True)
    SAMPLES_OUT.write_text(json.dumps(
        {"$schema": "../../../specs/erc7730-tests.schema.json", "tests": vectors}, indent=2))
    print(f"\nwrote {len(vectors)} sample vectors {common.rel(SAMPLES_OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
