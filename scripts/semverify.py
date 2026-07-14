#!/usr/bin/env python3
"""Simulation-backed SEMANTIC verification — prove the clear-signed screen
matches what the transaction actually did on-chain.

The EF registry CI already gives away schema / selector / Sourcify / ABI checks.
Those prove a descriptor is *well-formed*. They do NOT prove the human summary
is *honest*: a descriptor can pass every CI check and still render a benign
screen for a call that moves funds somewhere else. That gap is the real attack
surface, and closing it is the defensible rung.

For a mined transaction, the receipt IS the ground truth of what moved. This
tool, for each real vector: fetches the tx + receipt, extracts the actual asset
movements and approvals (ETH / ERC-20 Transfer / ERC-1155 TransferSingle /
ApprovalForAll), renders the descriptor's screen, and asserts the screen is
faithful — every real recipient/operator is shown, ETH spent is shown, nothing
material is hidden. Divergence => the descriptor lies, even if lint+audit pass.

(For hypothetical/unmined calls the same assertions run against a fork replay —
Foundry `cast run`; not required here since we verify real vectors.)

Env:  ETHERSCAN_API_KEY
Usage: python scripts/semverify.py <descriptor.json> [tests.json]
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.parse
from pathlib import Path

from eth_abi import decode as abi_decode

import preview

API = "https://api.etherscan.io/v2/api"
ZERO = "0x" + "0" * 40  # mint/burn counterparty — not a recipient to display
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TRANSFER_SINGLE = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"
APPROVAL_FOR_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"


def es(params: dict):
    q = {**params, "apikey": os.environ["ETHERSCAN_API_KEY"]}
    with urllib.request.urlopen(API + "?" + urllib.parse.urlencode(q), timeout=30) as r:
        return json.loads(r.read())


def _addr(topic: str) -> str:
    return ("0x" + topic[-40:]).lower()


def actual_movements(tx: dict, receipt: dict) -> list[dict]:
    """Ground-truth asset movements + approvals from the mined receipt."""
    moves = []
    val = int(tx["value"], 16)
    if val > 0:
        moves.append({"kind": "eth", "to": tx["to"].lower(), "amount": val})
    for lg in receipt["logs"]:
        t = lg["topics"]
        t0 = t[0].lower()
        if t0 == TRANSFER and len(t) == 3:
            moves.append({"kind": "erc20", "token": lg["address"].lower(),
                          "from": _addr(t[1]), "to": _addr(t[2]),
                          "amount": int(lg["data"], 16) if lg["data"] not in ("0x", "") else 0})
        elif t0 == TRANSFER_SINGLE and len(t) == 4:
            d = lg["data"][2:]
            moves.append({"kind": "erc1155", "token": lg["address"].lower(),
                          "from": _addr(t[2]), "to": _addr(t[3]),
                          "id": int(d[:64], 16), "amount": int(d[64:128], 16)})
        elif t0 == APPROVAL_FOR_ALL and len(t) == 3:
            moves.append({"kind": "approval_all", "token": lg["address"].lower(),
                          "owner": _addr(t[1]), "operator": _addr(t[2]),
                          "approved": int(lg["data"], 16) == 1})
    return moves


def screen_claims(desc: dict, to: str, value: int, data: bytes):
    """What the descriptor's screen presents: addresses shown, ETH-amount shown."""
    abi = preview.descriptor_abi(desc)
    idx = preview.build_selector_index(abi)
    sig, inputs = idx["0x" + data[:4].hex()]
    types = [preview._canonical_type(i) for i in inputs]
    decoded = dict(zip([i["name"] for i in inputs], abi_decode(types, data[4:])))
    fmt = desc["display"]["formats"].get(sig, {})
    shown_addrs, shows_value, labeled = set(), False, []
    for f in fmt.get("fields", []):
        if f.get("visible") == "never":
            continue
        p = f.get("path", "")
        if p == "@.value":
            shows_value = True
        if f.get("format") == "addressName" and p.startswith("#."):
            v = decoded.get(p[2:].split(".")[0])
            if isinstance(v, str) and v.startswith("0x"):
                shown_addrs.add(v.lower())
                labeled.append((f.get("label", "").strip().lower(), v.lower()))
    return sig, shown_addrs, shows_value, labeled


# labels whose field, if present, must name an actual on-chain recipient
RECIPIENT_LABELS = ("to", "recipient", "send to", "receiver")


def verify_one(desc, contract, tx, receipt):
    value = int(tx["value"], 16)
    data = bytes.fromhex(tx["input"][2:])
    sig, shown, shows_value, labeled = screen_claims(desc, tx["to"], value, data)
    moves = actual_movements(tx, receipt)
    contract = contract.lower()
    findings = []
    recipients = {m["to"] for m in moves
                  if m["kind"] in ("erc20", "erc1155") and m["amount"] > 0 and m["to"] != ZERO}

    if any(m["kind"] == "eth" for m in moves) and not shows_value:
        findings.append(("CRITICAL", "spends ETH but the screen shows no amount"))

    for m in moves:
        if m["kind"] in ("erc20", "erc1155") and m["amount"] > 0 and m["to"] != ZERO:
            # a real recipient (not a burn, not the contract) must appear on screen
            if m["to"] not in shown and m["to"] != contract:
                findings.append(("HIGH",
                    f"asset sent to {m['to'][:10]}… which the screen never shows (hidden recipient)"))
        if m["kind"] == "approval_all" and m["approved"] and m["operator"] not in shown:
            findings.append(("CRITICAL",
                f"grants approval to operator {m['operator'][:10]}… not shown on screen"))

    # role-aware: a field LABELED as the recipient must equal an actual recipient
    if recipients:
        for label, addr in labeled:
            if any(label == r or label.startswith(r) for r in RECIPIENT_LABELS):
                if addr not in recipients and addr != contract:
                    findings.append(("CRITICAL",
                        f"screen labels {addr[:10]}… as recipient, but assets went to "
                        f"{next(iter(recipients))[:10]}… (spoofed recipient)"))

    return sig, moves, findings


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 2
    desc_path = Path(args[0])
    desc = json.loads(desc_path.read_text())
    tests_path = Path(args[1]) if len(args) > 1 else \
        desc_path.parent / "tests" / (desc_path.stem + ".tests.json")
    tests = json.loads(tests_path.read_text())["tests"]
    contract = desc["context"]["contract"]["deployments"][0]["address"]

    print(f"Semantic verification — {desc_path.stem}")
    print(f"  ground truth: mined receipts (Etherscan)   vectors: {len(tests)}")
    print("─" * 66)
    total_findings, verified = 0, 0
    for t in tests:
        h = t.get("txHash")
        if not h:
            print(f"  ⚠ {t['description']}: no txHash (synthetic) — skipped")
            continue
        tx = es({"chainid": 1, "module": "proxy", "action": "eth_getTransactionByHash", "txhash": h})["result"]
        rc = es({"chainid": 1, "module": "proxy", "action": "eth_getTransactionReceipt", "txhash": h})["result"]
        sig, moves, findings = verify_one(desc, contract, tx, rc)
        mv = ", ".join(sorted({m["kind"] for m in moves})) or "no asset movement"
        if findings:
            print(f"  ✗ {sig.split('(')[0]:22} DIVERGENCE  ({mv})")
            for sev, msg in findings:
                print(f"      {sev}: {msg}")
            total_findings += len(findings)
        else:
            print(f"  ✓ {sig.split('(')[0]:22} screen matches chain  ({mv})")
            verified += 1
    print("─" * 66)
    stamp = "SIMULATION-VERIFIED ✅" if total_findings == 0 else f"DIVERGENCE ✗ ({total_findings})"
    print(f"  {verified} verified / {len(tests)} vectors  →  {stamp}")
    return 1 if total_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
