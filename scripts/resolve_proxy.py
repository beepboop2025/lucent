#!/usr/bin/env python3
"""Resolve a proxy's implementation and cache the REAL ABI under the proxy
address.

Most high-value DeFi contracts are proxies: Sourcify returns only the proxy
shell (`upgradeTo`, `admin`, …), which is useless for Clear Signing. The
functions users actually sign (`supply`, `borrow`, `repay`, …) live at the
implementation address, but a descriptor must bind to the *proxy* address the
user interacts with.

This finds the implementation two ways (first that works wins):
  1. Etherscan `getsourcecode` -> "Implementation" field (verified proxies).
  2. EIP-1967 implementation storage slot via `eth_getStorageAt`.
then fetches the implementation's ABI from Sourcify and writes it to
abi_cache/<chain>-<proxyAddress>.abi.json — so every downstream tool
(generate / lint / preview) uses the real ABI but keeps the proxy address.

Env:  ETHERSCAN_API_KEY
Usage: python scripts/resolve_proxy.py <chain_id> <proxy_address>
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "abi_cache"
ETHERSCAN = "https://api.etherscan.io/v2/api"
SOURCIFY = "https://sourcify.dev/server/v2/contract/{chain}/{address}?fields=abi"
# EIP-1967: keccak256("eip1967.proxy.implementation") - 1
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

ZERO = "0x" + "0" * 40


def etherscan(params: dict):
    params = {**params, "apikey": os.environ["ETHERSCAN_API_KEY"]}
    url = ETHERSCAN + "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read())


def impl_from_sourcecode(chain: int, address: str) -> str | None:
    resp = etherscan({"chainid": chain, "module": "contract",
                      "action": "getsourcecode", "address": address})
    if resp.get("status") != "1":
        return None
    impl = (resp["result"][0].get("Implementation") or "").strip()
    return impl if impl and impl.lower() != ZERO else None


def impl_from_storage(chain: int, address: str) -> str | None:
    resp = etherscan({"chainid": chain, "module": "proxy",
                      "action": "eth_getStorageAt",
                      "address": address, "position": EIP1967_IMPL_SLOT, "tag": "latest"})
    word = resp.get("result")
    if not word or len(word) < 66:
        return None
    addr = "0x" + word[-40:]
    return None if addr.lower() == ZERO else addr


def sourcify_abi(chain: int, address: str):
    url = SOURCIFY.format(chain=chain, address=address)
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return json.loads(r.read()).get("abi")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def etherscan_abi(chain: int, address: str):
    """Fallback: Etherscan getabi (this is what erc7730 lint uses too)."""
    resp = etherscan({"chainid": chain, "module": "contract",
                      "action": "getabi", "address": address})
    if resp.get("status") != "1":
        return None
    try:
        return json.loads(resp["result"])
    except json.JSONDecodeError:
        return None


def impl_abi(chain: int, address: str) -> tuple[list | None, str]:
    abi = sourcify_abi(chain, address)
    if abi:
        return abi, "sourcify"
    abi = etherscan_abi(chain, address)
    if abi:
        return abi, "etherscan"
    return None, "none"


def signable(abi: list) -> list[str]:
    return [e["name"] for e in abi if e.get("type") == "function"
            and e.get("stateMutability") not in ("view", "pure")]


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    chain, proxy = int(sys.argv[1]), sys.argv[2]

    impl = impl_from_sourcecode(chain, proxy)
    src = "getsourcecode"
    if not impl:
        impl, src = impl_from_storage(chain, proxy), "eip1967-storage"
    if not impl:
        print(f"no implementation found for {proxy} — not an EIP-1967 proxy?")
        return 1
    print(f"implementation: {impl}  (via {src})")

    abi, abi_src = impl_abi(chain, impl)
    if not abi:
        print(f"implementation {impl} is not verified on Sourcify or Etherscan — cannot use.")
        return 1
    if abi_src == "etherscan":
        print("note: impl verified on Etherscan, not Sourcify — fine for lint, "
              "confirm Sourcify status before a registry PR.")

    funcs = signable(abi)
    CACHE.mkdir(exist_ok=True)
    # Cache under the PROXY address: descriptor binds to the proxy, uses impl ABI.
    out = CACHE / f"{chain}-{proxy.lower()}.abi.json"
    out.write_text(json.dumps(abi, indent=2))
    print(f"cached impl ABI under proxy address -> {out.relative_to(ROOT)}")
    print(f"signable functions ({len(funcs)}): {', '.join(funcs[:12])}"
          + (" …" if len(funcs) > 12 else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
