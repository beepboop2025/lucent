#!/usr/bin/env python3
"""Find descriptor-able GAPS: contracts worth a Clear Signing descriptor that
don't have one yet.

For each candidate it checks the three things that decide whether we can sell a
descriptor for it:

  1. Verified on Sourcify?      -> required; the registry rejects unverified.
  2. Has signable functions?    -> a proxy shell or view-only contract is no use.
  3. Already in the registry?   -> if covered, skip it.

A candidate that is verified + signable + uncovered is a GAP: a lead. This runs
on a seed list today; point it at the output of the scraper infra (high-usage
uncovered contracts) to industrialise the top of the funnel.

Usage: python scripts/discover.py [seeds/candidates.json]
"""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCIFY = "https://sourcify.dev/server/v2/contract/{chain}/{address}?fields=abi"
REGISTRY = "ethereum/clear-signing-erc7730-registry"

# If a contract's only signable functions are these, it's a proxy shell — the
# real ABI lives at the implementation address (handle separately).
PROXY_ONLY = {"upgradeTo", "upgradeToAndCall", "changeAdmin", "admin",
              "implementation", "initialize"}


def sourcify_abi(chain: int, address: str):
    # Lowercase avoids EIP-55 checksum rejections (400) on the batch.
    url = SOURCIFY.format(chain=chain, address=address.lower())
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return json.loads(r.read()).get("abi")
    except urllib.error.HTTPError:
        return None  # 404 unverified / 400 bad address -> not descriptor-able here


def signable(abi: list) -> list[str]:
    return [e["name"] for e in abi
            if e.get("type") == "function"
            and e.get("stateMutability") not in ("view", "pure")]


def in_registry(address: str) -> bool | None:
    """True/False if known, None if the search was inconclusive."""
    q = f"{address} repo:{REGISTRY}"
    try:
        out = subprocess.run(
            ["gh", "api", "-X", "GET", "search/code",
             "-f", f"q={q}", "--jq", ".total_count"],
            capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            return None
        return int(out.stdout.strip()) > 0
    except Exception:
        return None


def classify(c: dict) -> dict:
    abi = sourcify_abi(c["chainId"], c["address"])
    if abi is None:
        return {**c, "verdict": "not-verified", "detail": "not on Sourcify"}
    funcs = signable(abi)
    if not funcs:
        return {**c, "verdict": "no-signable", "detail": "view-only / no state-changing fns"}
    if set(funcs) <= PROXY_ONLY:
        return {**c, "verdict": "proxy-shell",
                "detail": f"proxy ({', '.join(funcs[:3])}…) — resolve implementation"}
    covered = in_registry(c["address"])
    if covered is True:
        return {**c, "verdict": "covered", "detail": "already in registry"}
    if covered is None:
        return {**c, "verdict": "GAP?", "detail": f"{len(funcs)} signable fns (coverage check inconclusive)"}
    return {**c, "verdict": "GAP", "detail": f"{len(funcs)} signable fns, no registry coverage"}


RANK = {"GAP": 0, "GAP?": 1, "proxy-shell": 2, "covered": 3, "no-signable": 4, "not-verified": 5}
ICON = {"GAP": "🎯", "GAP?": "🔎", "proxy-shell": "🧅", "covered": "✅", "no-signable": "—", "not-verified": "✗"}


def main() -> int:
    seed = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "seeds/candidates.json"
    candidates = json.loads(seed.read_text())
    rows = sorted((classify(c) for c in candidates), key=lambda r: RANK.get(r["verdict"], 9))

    print(f"{'':2} {'verdict':12} {'contract':30} detail")
    print("-" * 96)
    for r in rows:
        print(f"{ICON.get(r['verdict'],'?'):2} {r['verdict']:12} {r['name'][:30]:30} {r['detail']}")

    leads = [r for r in rows if r["verdict"].startswith("GAP")]
    print(f"\n{len(leads)} lead(s): " + ", ".join(r["name"] for r in leads) if leads
          else "\nno gaps in this batch.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
