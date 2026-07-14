#!/usr/bin/env python3
"""Fetch a contract's verified ABI from Sourcify and cache it.

Sourcify verification is required before the registry accepts a descriptor, so a
successful fetch both provides the ABI and confirms the contract is verified.

    fetch_abi.py <chain_id> <address>
"""

from __future__ import annotations

import argparse
import json
import urllib.error

import common


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("chain_id", type=int)
    ap.add_argument("address")
    args = ap.parse_args()

    try:
        data = common.sourcify_contract(args.chain_id, args.address)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"not verified on Sourcify: chain {args.chain_id} {args.address}")
            return 2
        print(f"HTTP {e.code} fetching {args.address}: {e.reason}")
        return 3
    except Exception as e:
        print(f"error fetching {args.address}: {e}")
        return 3

    abi = data.get("abi")
    if not abi:
        print(f"no ABI for {args.address} (proxy without implementation ABI?)")
        return 2

    common.ABI_CACHE.mkdir(exist_ok=True)
    out = common.ABI_CACHE / f"{args.chain_id}-{args.address.lower()}.abi.json"
    out.write_text(json.dumps(abi, indent=2))

    match = data.get("match") or "unknown"
    signable = len(common.signable_functions(abi))
    print(f"chain={args.chain_id} {args.address}")
    print(f"  match={match} entries={len(abi)} signable={signable}")
    print(f"  cached {common.rel(out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
