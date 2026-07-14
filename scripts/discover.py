#!/usr/bin/env python3
"""Classify candidate contracts by whether they can take a Clear Signing descriptor.

Each candidate is checked against three requirements: verified on Sourcify, has
state-changing functions, and not already in the registry. A candidate meeting
all three is a gap worth writing a descriptor for.

    discover.py [candidates.json]        (default: seeds/candidates.json)
"""

from __future__ import annotations

import argparse
import json
import subprocess

import common

REGISTRY = "ethereum/clear-signing-erc7730-registry"

# A contract whose only signable functions are these is a proxy shell; the real
# ABI lives at the implementation (see resolve_proxy.py).
PROXY_ONLY = {"upgradeTo", "upgradeToAndCall", "changeAdmin", "admin",
              "implementation", "initialize"}

RANK = {"gap": 0, "gap?": 1, "proxy": 2, "covered": 3, "no-signable": 4, "unverified": 5}


def in_registry(address: str) -> bool | None:
    """Whether the address appears in the registry; None if the search failed."""
    try:
        out = subprocess.run(
            ["gh", "api", "-X", "GET", "search/code",
             "-f", f"q={address} repo:{REGISTRY}", "--jq", ".total_count"],
            capture_output=True, text=True, timeout=30)
        return int(out.stdout.strip()) > 0 if out.returncode == 0 else None
    except Exception:
        return None


def classify(c: dict) -> dict:
    abi = common.sourcify_abi(c["chainId"], c["address"])
    if abi is None:
        return {**c, "verdict": "unverified", "detail": "not on Sourcify"}
    names = [f["name"] for f in common.signable_functions(abi)]
    if not names:
        return {**c, "verdict": "no-signable", "detail": "view-only"}
    if set(names) <= PROXY_ONLY:
        return {**c, "verdict": "proxy", "detail": "resolve implementation"}
    covered = in_registry(c["address"])
    if covered:
        return {**c, "verdict": "covered", "detail": "already in registry"}
    verdict = "gap" if covered is False else "gap?"
    suffix = "" if covered is False else " (coverage check inconclusive)"
    return {**c, "verdict": verdict, "detail": f"{len(names)} signable functions{suffix}"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("candidates", nargs="?", default=common.ROOT / "seeds/candidates.json")
    args = ap.parse_args()

    candidates = json.loads(open(args.candidates).read())
    rows = sorted((classify(c) for c in candidates), key=lambda r: RANK.get(r["verdict"], 9))

    print(f"{'verdict':12} {'contract':30} detail")
    print("-" * 78)
    for r in rows:
        print(f"{r['verdict']:12} {r['name'][:30]:30} {r['detail']}")

    leads = [r["name"] for r in rows if r["verdict"].startswith("gap")]
    print(f"\n{len(leads)} lead(s): {', '.join(leads)}" if leads else "\nno gaps in this batch")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
