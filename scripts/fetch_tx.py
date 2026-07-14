#!/usr/bin/env python3
"""Build registry test vectors from a contract's real historical transactions.

Queries Etherscan for the contract's recent transactions, keeps those the
descriptor covers, fetches each as a raw signed transaction, and renders its
expected on-screen strings. Writes tests next to the descriptor. Also reports
the most recent activity, which indicates whether the deployment is still active.

    fetch_tx.py <chain_id> <address> <descriptor.json> [max_per_fn]
    (needs ETHERSCAN_API_KEY)
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import common
import preview

MAX_TOTAL = 8


def wanted_selectors(desc: dict) -> dict:
    return {common.selector(sig): sig.split("(")[0] for sig in desc["display"]["formats"]}


def recent_txs(chain_id: int, address: str, limit: int = 100) -> list[dict]:
    resp = common.etherscan(chainid=chain_id, module="account", action="txlist",
                            address=address, startblock=0, endblock=99999999,
                            page=1, offset=limit, sort="desc")
    if resp.get("status") != "1":
        print(f"  txlist: {resp.get('message')} — {resp.get('result')}")
        return []
    return resp["result"]


def raw_tx(chain_id: int, tx_hash: str) -> str | None:
    return common.etherscan(chainid=chain_id, module="proxy",
                            action="eth_getRawTransactionByHash", txhash=tx_hash).get("result")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("chain_id", type=int)
    ap.add_argument("address")
    ap.add_argument("descriptor")
    ap.add_argument("max_per_fn", nargs="?", type=int, default=2)
    args = ap.parse_args()

    desc_path = Path(args.descriptor).resolve()
    desc = preview.load_descriptor(desc_path)
    wanted = wanted_selectors(desc)
    tests_out = desc_path.parent / "tests" / (desc_path.stem + ".tests.json")

    txs = recent_txs(args.chain_id, args.address)
    if not txs:
        return 1

    newest = int(txs[0]["timeStamp"])
    age_days = (time.time() - newest) / 86400
    print(f"most recent tx {datetime.fromtimestamp(newest, timezone.utc):%Y-%m-%d} "
          f"({age_days:.0f}d ago, {'active' if age_days < 30 else 'likely superseded'})")

    counts, vectors = {}, []
    for tx in txs:
        fn = wanted.get(tx["input"][:10].lower())
        if not fn or counts.get(fn, 0) >= args.max_per_fn:
            continue
        if tx.get("isError") == "1" or tx.get("txreceipt_status") == "0":
            continue
        try:
            _, expected = preview.render(desc, tx["to"], int(tx["value"]),
                                         bytes.fromhex(tx["input"][2:]))
        except Exception as e:
            print(f"  skip {tx['hash'][:12]} ({fn}): {e}")
            continue
        raw = raw_tx(args.chain_id, tx["hash"])
        if not raw:
            continue
        counts[fn] = counts.get(fn, 0) + 1
        vectors.append({"description": f"{fn} — real tx {tx['hash'][:10]}",
                        "rawTx": raw, "txHash": tx["hash"], "expectedTexts": expected})
        print(f"  + {fn:9} {tx['hash']}")
        if len(vectors) >= MAX_TOTAL:
            break
        time.sleep(0.25)

    if not vectors:
        print("no covered transactions in the recent window")
        return 1

    tests_out.parent.mkdir(parents=True, exist_ok=True)
    tests_out.write_text(json.dumps(
        {"$schema": "../../../specs/erc7730-tests.schema.json", "tests": vectors}, indent=2))
    print(f"wrote {len(vectors)} vectors {common.rel(tests_out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
