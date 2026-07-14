#!/usr/bin/env python3
"""Pull REAL historical transactions for the target contract and build
registry-format test vectors from them.

Registry review prefers real on-chain transactions over synthetic ones. This
queries Etherscan for the contract's recent txs, keeps the ones our descriptor
covers, fetches each as a raw signed tx, and renders expectedTexts with the
same logic a wallet uses (reused from preview.py).

Also reports the contract's most recent activity, which tells us whether this
deployment is still the active one.

Env:  ETHERSCAN_API_KEY   (free key, https://etherscan.io/apis)
Usage: python scripts/fetch_tx.py <chain_id> <address> <descriptor.json> [max_per_fn]
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from eth_utils import keccak

import preview  # sibling module: render(), load_descriptor()

ROOT = Path(__file__).resolve().parent.parent
API = "https://api.etherscan.io/v2/api"
MAX_TOTAL = 8  # keep the vector file focused


def wanted_selectors(desc: dict) -> dict:
    """Map selector -> function name for every function the descriptor covers."""
    out = {}
    for sig in desc["display"]["formats"]:
        out["0x" + keccak(text=sig)[:4].hex()] = sig.split("(")[0]
    return out


def api_get(params: dict) -> dict:
    params = {**params, "apikey": os.environ["ETHERSCAN_API_KEY"]}
    url = API + "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read())


def recent_txs(chain_id: int, address: str, page_size: int = 100) -> list[dict]:
    resp = api_get({"chainid": chain_id, "module": "account", "action": "txlist",
                    "address": address, "startblock": 0, "endblock": 99999999,
                    "page": 1, "offset": page_size, "sort": "desc"})
    if resp.get("status") != "1":
        print(f"  txlist: {resp.get('message')} — {resp.get('result')}")
        return []
    return resp["result"]


def raw_tx(chain_id: int, tx_hash: str) -> str | None:
    resp = api_get({"chainid": chain_id, "module": "proxy",
                    "action": "eth_getRawTransactionByHash", "txhash": tx_hash})
    return resp.get("result")


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    chain_id, address, desc_path = int(sys.argv[1]), sys.argv[2], Path(sys.argv[3]).resolve()
    max_per_fn = int(sys.argv[4]) if len(sys.argv) > 4 else 2

    desc = preview.load_descriptor(desc_path)
    WANTED = wanted_selectors(desc)
    tests_out = desc_path.parent / "tests" / (desc_path.stem + ".tests.json")

    txs = recent_txs(chain_id, address)
    if not txs:
        return 1

    newest = int(txs[0]["timeStamp"])
    age_days = (time.time() - newest) / 86400
    print(f"most recent tx: {datetime.fromtimestamp(newest, timezone.utc):%Y-%m-%d %H:%M UTC} "
          f"({age_days:.0f} days ago) -> {'ACTIVE' if age_days < 30 else 'likely superseded'}")

    counts, vectors = {}, []
    for tx in txs:
        sel = tx["input"][:10].lower()
        fn = WANTED.get(sel)
        if not fn or counts.get(fn, 0) >= max_per_fn:
            continue
        if tx.get("isError") == "1" or tx.get("txreceipt_status") == "0":
            continue
        data = bytes.fromhex(tx["input"][2:])
        value = int(tx["value"])
        try:
            _, expected = preview.render(desc, tx["to"], value, data)
        except Exception as e:
            print(f"  skip {tx['hash'][:12]} ({fn}): render failed: {e}")
            continue
        raw = raw_tx(chain_id, tx["hash"])
        if not raw:
            continue
        counts[fn] = counts.get(fn, 0) + 1
        vectors.append({
            "description": f"{fn} — real tx {tx['hash'][:10]}",
            "rawTx": raw,
            "txHash": tx["hash"],
            "expectedTexts": expected,
        })
        print(f"  + {fn:9} {tx['hash']}")
        if len(vectors) >= MAX_TOTAL:
            break
        time.sleep(0.25)  # be gentle on the free-tier rate limit

    if not vectors:
        print("no covered transactions found in the recent window.")
        return 1

    tests_out.parent.mkdir(parents=True, exist_ok=True)
    tests_out.write_text(json.dumps(
        {"$schema": "../../../specs/erc7730-tests.schema.json", "tests": vectors},
        indent=2))
    print(f"\nwrote {len(vectors)} REAL test vectors -> {tests_out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
