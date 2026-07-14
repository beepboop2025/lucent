#!/usr/bin/env python3
"""Fetch a contract's verified ABI, keyless, from Sourcify.

Sourcify verification is a hard requirement for the ERC-7730 registry, so a
successful fetch here does double duty: it gives us the ABI *and* proves the
contract is verified on the source the registry trusts. We cache the ABI on
disk so descriptor generation is reproducible and offline from then on.

Usage:
    python scripts/fetch_abi.py <chain_id> <address>

Exit codes:
    0  verified ABI written to abi_cache/<chain>-<address>.abi.json
    2  contract not found / not verified on Sourcify (registry will reject it)
    3  network or unexpected error
"""

from __future__ import annotations

import json
import sys
import urllib.request
import urllib.error
from pathlib import Path

# fields=abi already returns match/matchId/verifiedAt alongside the ABI.
SOURCIFY = "https://sourcify.dev/server/v2/contract/{chain}/{address}?fields=abi"
CACHE_DIR = Path(__file__).resolve().parent.parent / "abi_cache"


def fetch(chain_id: int, address: str) -> dict:
    url = SOURCIFY.format(chain=chain_id, address=address)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 3
    chain_id = int(sys.argv[1])
    address = sys.argv[2]

    try:
        data = fetch(chain_id, address)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"NOT VERIFIED on Sourcify: chain {chain_id} {address}")
            print("  -> The ERC-7730 registry requires Sourcify verification. "
                  "This contract cannot be submitted until it is verified.")
            return 2
        print(f"HTTP error {e.code} fetching {address}: {e.reason}")
        return 3
    except Exception as e:  # network, json, etc.
        print(f"ERROR fetching {address}: {e}")
        return 3

    abi = data.get("abi")
    if not abi:
        print(f"NO ABI in Sourcify response for {address} (proxy without impl ABI?)")
        return 2

    # "match" is "exact_match" | "match" (partial) | None.
    match = data.get("match") or data.get("matchStatus") or "unknown"

    CACHE_DIR.mkdir(exist_ok=True)
    out = CACHE_DIR / f"{chain_id}-{address.lower()}.abi.json"
    out.write_text(json.dumps(abi, indent=2))

    funcs = [e for e in abi if e.get("type") == "function"
             and e.get("stateMutability") not in ("view", "pure")]
    print(f"OK  chain={chain_id} {address}")
    print(f"    sourcify_match={match}  abi_entries={len(abi)}  "
          f"state-changing functions={len(funcs)}")
    print(f"    cached -> {out.relative_to(CACHE_DIR.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
