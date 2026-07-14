#!/usr/bin/env python3
"""Resolve a proxy's implementation and cache the real ABI under the proxy address.

Sourcify returns only the proxy shell (`upgradeTo`, `admin`, ...) for a proxy
contract; the functions users sign live at the implementation. This finds the
implementation (Etherscan `Implementation` field, else the EIP-1967 storage
slot), fetches its ABI, and caches it under the proxy address so the rest of the
pipeline uses the real ABI while the descriptor still binds to the proxy.

    resolve_proxy.py <chain_id> <proxy_address>   (needs ETHERSCAN_API_KEY)
"""

from __future__ import annotations

import argparse
import json

import common

# keccak256("eip1967.proxy.implementation") - 1
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


def impl_from_sourcecode(chain_id: int, address: str) -> str | None:
    resp = common.etherscan(chainid=chain_id, module="contract",
                            action="getsourcecode", address=address)
    if resp.get("status") != "1":
        return None
    impl = (resp["result"][0].get("Implementation") or "").strip()
    return impl if impl and impl.lower() != common.ZERO_ADDRESS else None


def impl_from_storage(chain_id: int, address: str) -> str | None:
    resp = common.etherscan(chainid=chain_id, module="proxy", action="eth_getStorageAt",
                            address=address, position=EIP1967_IMPL_SLOT, tag="latest")
    word = resp.get("result")
    if not word or len(word) < 66:
        return None
    addr = "0x" + word[-40:]
    return None if addr.lower() == common.ZERO_ADDRESS else addr


def implementation(chain_id: int, address: str) -> str | None:
    return impl_from_sourcecode(chain_id, address) or impl_from_storage(chain_id, address)


def impl_abi(chain_id: int, address: str) -> tuple[list | None, str]:
    """Implementation ABI, preferring Sourcify (registry-verifiable), then Etherscan."""
    abi = common.sourcify_abi(chain_id, address)
    if abi:
        return abi, "sourcify"
    abi = common.etherscan_abi(chain_id, address)
    if abi:
        return abi, "etherscan"
    return None, "none"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("chain_id", type=int)
    ap.add_argument("proxy_address")
    args = ap.parse_args()

    impl = implementation(args.chain_id, args.proxy_address)
    if not impl:
        print(f"no implementation found for {args.proxy_address} (not an EIP-1967 proxy?)")
        return 1
    print(f"implementation {impl}")

    abi, src = impl_abi(args.chain_id, impl)
    if not abi:
        print(f"implementation {impl} not verified on Sourcify or Etherscan")
        return 1
    if src == "etherscan":
        print("  note: verified on Etherscan, not Sourcify; confirm before a registry PR")

    common.ABI_CACHE.mkdir(exist_ok=True)
    out = common.ABI_CACHE / f"{args.chain_id}-{args.proxy_address.lower()}.abi.json"
    out.write_text(json.dumps(abi, indent=2))
    names = [f["name"] for f in common.signable_functions(abi)]
    print(f"  cached {common.rel(out)}")
    print(f"  signable ({len(names)}): {', '.join(names[:12])}{' ...' if len(names) > 12 else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
