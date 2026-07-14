#!/usr/bin/env python3
"""Verify a descriptor's screen against what its transactions actually did on-chain.

`erc7730 lint` proves a descriptor is well-formed; this proves the human summary
is faithful. For each real test vector it fetches the mined receipt (the ground
truth of what moved), extracts the asset movements and approvals, renders the
screen, and asserts every real recipient/operator is shown, ETH spent is shown,
and the field labelled as the recipient matches the address that received the
asset. A divergence means the screen misrepresents the transaction.

    semverify.py <descriptor.json> [tests.json]   (needs ETHERSCAN_API_KEY)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from eth_abi import decode as abi_decode

import common

TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TRANSFER_SINGLE = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"
APPROVAL_FOR_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"
RECIPIENT_LABELS = ("to", "recipient", "send to", "receiver")


def _tx(h: str) -> dict:
    return common.etherscan(chainid=1, module="proxy",
                            action="eth_getTransactionByHash", txhash=h)["result"]


def _receipt(h: str) -> dict:
    return common.etherscan(chainid=1, module="proxy",
                            action="eth_getTransactionReceipt", txhash=h)["result"]


def _addr(topic: str) -> str:
    return ("0x" + topic[-40:]).lower()


def movements(tx: dict, receipt: dict) -> list[dict]:
    """Asset movements and approvals realised by the transaction."""
    out = []
    value = int(tx["value"], 16)
    if value > 0:
        out.append({"kind": "eth", "to": tx["to"].lower(), "amount": value})
    for log in receipt["logs"]:
        topics = log["topics"]
        t0 = topics[0].lower()
        if t0 == TRANSFER and len(topics) == 3:
            out.append({"kind": "erc20", "from": _addr(topics[1]), "to": _addr(topics[2]),
                        "amount": int(log["data"], 16) if log["data"] not in ("0x", "") else 0})
        elif t0 == TRANSFER_SINGLE and len(topics) == 4:
            data = log["data"][2:]
            out.append({"kind": "erc1155", "from": _addr(topics[2]), "to": _addr(topics[3]),
                        "id": int(data[:64], 16), "amount": int(data[64:128], 16)})
        elif t0 == APPROVAL_FOR_ALL and len(topics) == 3:
            out.append({"kind": "approval", "owner": _addr(topics[1]),
                        "operator": _addr(topics[2]), "approved": int(log["data"], 16) == 1})
    return out


def screen_claims(desc: dict, data: bytes):
    """(signature, shown addresses, shows @.value, [(label, address)]) for the screen."""
    abi = common.descriptor_abi(desc)
    sig, inputs = common.selector_index(abi)["0x" + data[:4].hex()]
    decoded = dict(zip([i["name"] for i in inputs],
                       abi_decode([common.canonical_type(i) for i in inputs], data[4:])))
    fmt = desc["display"]["formats"].get(sig, {})
    shown, shows_value, labelled = set(), False, []
    for f in fmt.get("fields", []):
        if f.get("visible") == "never":
            continue
        path = f.get("path", "")
        if path == "@.value":
            shows_value = True
        if f.get("format") == "addressName" and path.startswith("#."):
            v = decoded.get(path[2:].split(".")[0])
            if isinstance(v, str) and v.startswith("0x"):
                shown.add(v.lower())
                labelled.append((f.get("label", "").strip().lower(), v.lower()))
    return sig, shown, shows_value, labelled


def verify_one(desc: dict, contract: str, tx: dict, receipt: dict):
    data = bytes.fromhex(tx["input"][2:])
    sig, shown, shows_value, labelled = screen_claims(desc, data)
    moves = movements(tx, receipt)
    contract = contract.lower()
    recipients = {m["to"] for m in moves
                  if m["kind"] in ("erc20", "erc1155") and m["amount"] > 0
                  and m["to"] != common.ZERO_ADDRESS}
    findings = []

    if any(m["kind"] == "eth" for m in moves) and not shows_value:
        findings.append(("CRITICAL", "spends ETH but the screen shows no amount"))
    for m in moves:
        if m["kind"] in ("erc20", "erc1155") and m["to"] in recipients \
                and m["to"] not in shown and m["to"] != contract:
            findings.append(("HIGH", f"asset sent to {m['to'][:10]}... not shown on screen"))
        if m["kind"] == "approval" and m["approved"] and m["operator"] not in shown:
            findings.append(("CRITICAL", f"approves operator {m['operator'][:10]}... not shown"))
    if recipients:
        for label, addr in labelled:
            if any(label == r or label.startswith(r) for r in RECIPIENT_LABELS) \
                    and addr not in recipients and addr != contract:
                findings.append(("CRITICAL",
                    f"screen labels {addr[:10]}... as recipient, but assets went elsewhere"))
    return sig, moves, findings


def evaluate(descriptor, tests=None) -> dict:
    descriptor = Path(descriptor)
    desc = json.loads(descriptor.read_text())
    tests_path = Path(tests) if tests else descriptor.parent / "tests" / (descriptor.stem + ".tests.json")
    vectors = json.loads(tests_path.read_text())["tests"]
    contract = desc["context"]["contract"]["deployments"][0]["address"]

    rows, divergences = [], 0
    for v in vectors:
        h = v.get("txHash")
        if not h:
            continue
        sig, moves, findings = verify_one(desc, contract, _tx(h), _receipt(h))
        rows.append({"sig": sig, "txHash": h, "ok": not findings,
                     "movements": sorted({m["kind"] for m in moves}), "findings": findings})
        divergences += len(findings)
    return {"total": len(rows), "verified": sum(1 for r in rows if r["ok"]),
            "divergences": divergences, "txHashes": [r["txHash"] for r in rows], "rows": rows}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("descriptor")
    ap.add_argument("tests", nargs="?")
    args = ap.parse_args()

    r = evaluate(args.descriptor, args.tests)
    print(f"{Path(args.descriptor).stem}: {r['total']} vectors")
    for row in r["rows"]:
        moves = ", ".join(row["movements"]) or "no asset movement"
        if row["ok"]:
            print(f"  ok   {row['sig'].split('(')[0]:24} ({moves})")
        else:
            print(f"  FAIL {row['sig'].split('(')[0]:24} ({moves})")
            for severity, msg in row["findings"]:
                print(f"       {severity}: {msg}")
    verdict = "verified" if r["divergences"] == 0 and r["total"] else f"divergence ({r['divergences']})"
    print(f"  {r['verified']}/{r['total']} -> {verdict}")
    return 1 if r["divergences"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
