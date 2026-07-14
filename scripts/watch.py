#!/usr/bin/env python3
"""Descriptor drift monitor — the recurring half of the business ("Lucent
Watch").

A descriptor is verified against a contract *as it exists today*. Proxies
upgrade, and the moment the implementation changes, a merged+attested
descriptor can silently become a confident lie — worse than hex, and nobody in
the clear-signing stack re-checks. This tool is that re-check, designed to run
from cron:

  For every descriptor under registry/:
    · resolve the live implementation (EIP-1967 slot / Etherscan), compare to
      the recorded baseline           -> IMPL_CHANGED   descriptor may now lie
    · fetch the live ABI, diff signable functions vs the descriptor:
        live fn the descriptor omits  -> NEW_UNCOVERED  users blind-sign it
        descriptor fn gone from ABI   -> STALE_ENTRY    dead weight / selector reuse
        ABI bytes changed, same set   -> ABI_TOUCHED    re-verification hygiene

Baselines live in watch_state.json (committed — the state IS the audit trail).
First run per contract records the baseline; later runs diff against it.
Any CRITICAL/HIGH drift exits 1, so cron alerting is just the exit code — and
the correct response is: re-run semverify, re-attest (attest.py), and revoke
the stale attestation.

Severity policy is deliberately centralized in POLICY below — it is a product
decision (what wakes a client at 3am vs lands in a weekly digest), not a
technical one.

Env:  ETHERSCAN_API_KEY  (proxy resolution + ABI fallback; without it,
      Sourcify-only mode: ABI/coverage checks still run, impl checks skipped)
Usage:
    python scripts/watch.py [--init] [--json] [descriptor.json ...]
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from eth_utils import keccak

import preview
import resolve_proxy

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / "watch_state.json"

# What each drift class means for the client. CRITICAL/HIGH fail the run.
POLICY = {
    "IMPL_CHANGED": "CRITICAL",   # screens were verified against code that is gone
    "NEW_UNCOVERED": "HIGH",      # users blind-sign the new function today
    "STALE_ENTRY": "MEDIUM",      # confusing at best, selector-reuse risk at worst
    "ABI_TOUCHED": "LOW",         # same surface, changed bytes — re-verify when convenient
}
FAILING = ("CRITICAL", "HIGH")


def canon_sig(fn: dict) -> str:
    types = ",".join(preview._canonical_type(i) for i in fn["inputs"])
    return f'{fn["name"]}({types})'


def signable_sigs(abi: list) -> set[str]:
    return {canon_sig(e) for e in abi if e.get("type") == "function"
            and e.get("stateMutability") not in ("view", "pure")}


def abi_fingerprint(abi: list) -> str:
    canon = json.dumps(abi, sort_keys=True, separators=(",", ":"))
    return "0x" + keccak(canon.encode()).hex()


def live_state(chain: int, address: str, has_key: bool) -> dict | None:
    """Snapshot of the contract as it exists right now."""
    impl = None
    if has_key:
        impl = resolve_proxy.impl_from_sourcecode(chain, address) \
            or resolve_proxy.impl_from_storage(chain, address)
    abi = resolve_proxy.sourcify_abi(chain, impl or address)
    if abi is None and has_key:
        abi, _ = resolve_proxy.impl_abi(chain, impl or address)
    if abi is None:
        return None
    return {"impl": impl.lower() if impl else None,
            "abiHash": abi_fingerprint(abi),
            "signable": sorted(signable_sigs(abi))}


def diff(baseline: dict, live: dict, covered: set[str]) -> list[dict]:
    events = []
    def ev(kind, detail):
        events.append({"kind": kind, "severity": POLICY[kind], "detail": detail})

    if baseline.get("impl") and live.get("impl") and baseline["impl"] != live["impl"]:
        ev("IMPL_CHANGED",
           f"implementation {baseline['impl'][:10]}… -> {live['impl'][:10]}…")

    live_sigs = set(live["signable"])
    for sig in sorted(live_sigs - covered):
        ev("NEW_UNCOVERED", f"live signable `{sig}` has no descriptor entry")
    for sig in sorted(covered - live_sigs):
        ev("STALE_ENTRY", f"descriptor covers `{sig}` which the live ABI lacks")

    if not events and baseline["abiHash"] != live["abiHash"]:
        ev("ABI_TOUCHED", "ABI bytes changed (same signable surface)")
    return events


def descriptors(args: list[str]) -> list[Path]:
    if args:
        return [Path(a) for a in args]
    return sorted((ROOT / "registry").glob("*/calldata-*.json"))


def main() -> int:
    init = "--init" in sys.argv
    as_json = "--json" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    has_key = bool(os.environ.get("ETHERSCAN_API_KEY"))
    if not has_key:
        print("⚠ no ETHERSCAN_API_KEY — Sourcify-only mode, proxy impl checks skipped",
              file=sys.stderr)

    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    report, failed = [], False

    for path in descriptors(args):
        desc = json.loads(path.read_text())
        dep = desc["context"]["contract"]["deployments"][0]
        chain, addr = dep["chainId"], dep["address"].lower()
        key = f"eip155:{chain}:{addr}"
        covered = set(desc.get("display", {}).get("formats", {}))

        live = live_state(chain, addr, has_key)
        if live is None:
            report.append({"descriptor": path.name, "contract": key,
                           "status": "UNRESOLVABLE", "events": []})
            continue

        if init or key not in state:
            state[key] = {**live, "descriptor": path.name}
            report.append({"descriptor": path.name, "contract": key,
                           "status": "BASELINE", "events": []})
            continue

        events = diff(state[key], live, covered)
        status = "DRIFT" if events else "OK"
        failed |= any(e["severity"] in FAILING for e in events)
        report.append({"descriptor": path.name, "contract": key,
                       "status": status, "events": events})

    STATE.write_text(json.dumps(state, indent=2) + "\n")

    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print("Lucent Watch — descriptor drift report")
        print("─" * 66)
        icon = {"OK": "✓", "BASELINE": "◎", "DRIFT": "✗", "UNRESOLVABLE": "?"}
        for r in report:
            print(f"  {icon[r['status']]} {r['descriptor']:44} {r['status']}")
            for e in r["events"]:
                print(f"      {e['severity']}: [{e['kind']}] {e['detail']}")
        print("─" * 66)
        n_drift = sum(1 for r in report if r["status"] == "DRIFT")
        print(f"  {len(report)} watched · {n_drift} drifted"
              + ("  →  RE-VERIFY, RE-ATTEST, REVOKE STALE" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
