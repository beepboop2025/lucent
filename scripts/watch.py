#!/usr/bin/env python3
"""Monitor registry descriptors for drift against the live contract.

A descriptor is verified against a contract as it exists when written. Proxies
upgrade and ABIs change, which can silently invalidate a merged descriptor. For
each descriptor this compares the live implementation and signable-function set
against a recorded baseline and reports drift. Baselines live in
watch_state.json; the first run records them. CRITICAL/HIGH drift exits non-zero
for cron alerting.

    watch.py [--init] [--json] [descriptor.json ...]   (ETHERSCAN_API_KEY optional)
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from eth_utils import keccak

import common
import resolve_proxy

STATE = common.ROOT / "watch_state.json"

POLICY = {
    "IMPL_CHANGED": "CRITICAL",   # screens were verified against code that is gone
    "NEW_UNCOVERED": "HIGH",      # users blind-sign the new function
    "STALE_ENTRY": "MEDIUM",      # dead entry / selector-reuse risk
    "ABI_TOUCHED": "LOW",         # same surface, changed bytes
}
FAILING = ("CRITICAL", "HIGH")


def signable_sigs(abi: list) -> set[str]:
    return {common.signature(f) for f in common.signable_functions(abi)}


def abi_fingerprint(abi: list) -> str:
    return "0x" + keccak(json.dumps(abi, sort_keys=True, separators=(",", ":")).encode()).hex()


def live_state(chain_id: int, address: str, has_key: bool) -> dict | None:
    impl = resolve_proxy.implementation(chain_id, address) if has_key else None
    abi = common.sourcify_abi(chain_id, impl or address)
    if abi is None and has_key:
        abi, _ = resolve_proxy.impl_abi(chain_id, impl or address)
    if abi is None:
        return None
    return {"impl": impl.lower() if impl else None,
            "abiHash": abi_fingerprint(abi), "signable": sorted(signable_sigs(abi))}


def diff(baseline: dict, live: dict, covered: set[str]) -> list[dict]:
    events = []
    def ev(kind, detail):
        events.append({"kind": kind, "severity": POLICY[kind], "detail": detail})

    if baseline.get("impl") and live.get("impl") and baseline["impl"] != live["impl"]:
        ev("IMPL_CHANGED", f"{baseline['impl'][:10]}... -> {live['impl'][:10]}...")
    live_sigs = set(live["signable"])
    for sig in sorted(live_sigs - covered):
        ev("NEW_UNCOVERED", f"live signable `{sig}` has no descriptor entry")
    for sig in sorted(covered - live_sigs):
        ev("STALE_ENTRY", f"descriptor covers `{sig}` which the live ABI lacks")
    if not events and baseline["abiHash"] != live["abiHash"]:
        ev("ABI_TOUCHED", "ABI bytes changed (same signable surface)")
    return events


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("descriptors", nargs="*")
    ap.add_argument("--init", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    has_key = bool(os.environ.get("ETHERSCAN_API_KEY"))
    paths = [Path(p) for p in args.descriptors] or \
        sorted((common.ROOT / "registry").glob("*/calldata-*.json"))
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    report, failed = [], False

    for path in paths:
        desc = json.loads(path.read_text())
        dep = desc["context"]["contract"]["deployments"][0]
        chain, addr = dep["chainId"], dep["address"].lower()
        key = f"eip155:{chain}:{addr}"
        covered = set(desc.get("display", {}).get("formats", {}))

        live = live_state(chain, addr, has_key)
        if live is None:
            report.append({"descriptor": path.name, "status": "UNRESOLVABLE", "events": []})
            continue
        if args.init or key not in state:
            state[key] = {**live, "descriptor": path.name}
            report.append({"descriptor": path.name, "status": "BASELINE", "events": []})
            continue
        events = diff(state[key], live, covered)
        failed |= any(e["severity"] in FAILING for e in events)
        report.append({"descriptor": path.name,
                       "status": "DRIFT" if events else "OK", "events": events})

    STATE.write_text(json.dumps(state, indent=2) + "\n")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for r in report:
            print(f"  {r['status']:12} {r['descriptor']}")
            for e in r["events"]:
                print(f"       {e['severity']}: [{e['kind']}] {e['detail']}")
        drifted = sum(1 for r in report if r["status"] == "DRIFT")
        print(f"{len(report)} watched, {drifted} drifted")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
