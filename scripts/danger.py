#!/usr/bin/env python3
"""Flag the DANGER SURFACE of a contract's signable functions — structural
primitives that can do something catastrophic no matter how the descriptor
labels them.

Three lenses now sit over a descriptor:
  audit.py      — does the on-device screen SHOW the right fields?
  comprehend.py — will the human UNDERSTAND what they authorize?
  danger.py     — can this function, BY CONSTRUCTION, do something a clear
                  screen still can't make safe?

The last is the one a clear-signing pipeline most needs and neither of the
others gives: a descriptor can render a perfectly honest sentence for
`execute(address target, bytes data)` — "Call {target} with {data}" — and that
call can still drain the wallet, because the *primitive itself* is unbounded.
Runtime systems catch this by instrumenting transaction-trace properties
(arXiv:2408.14621: arbitrary CALL/DELEGATECALL/SELFDESTRUCT in the trace);
here we lift the same property set to STATIC ABI analysis so the danger is
named before a user ever signs.

Detected primitives (severity -> the trace property it stands in for):
  CRITICAL arbitrary external call: (address,bytes) — an unbounded CALL; the
           canonical drainer primitive (execute / multicall / forward).
  CRITICAL delegatecall exposure: a target + calldata on a function whose name
           or shape implies DELEGATECALL — runs foreign code in this context.
  CRITICAL self-destruct / kill: SELFDESTRUCT reachable from a signable entry.
  CRITICAL upgrade-and-execute: upgradeToAndCall — swaps the code AND runs a
           call in one signature.
  HIGH     unbounded delegation: setApprovalForAll — operator over all assets.
  HIGH     authority transfer: ownership / admin / role grants.
  MEDIUM   unbounded value sweep: withdraw/sweep to a caller-supplied address.

A descriptor for a CRITICAL-danger function is not "bad" — some contracts must
expose these — but the pipeline must SAY SO loudly and never let such a call
hide behind a benign sentence. `--strict` exits non-zero on any CRITICAL.

    danger.py <descriptor.json> [--json] [--strict]
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import common

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM"]

# Function names whose whole job is to make an arbitrary call. Matched as a
# WORD (not substring) so "renew" doesn't match "run" and "increaseAllowance"
# doesn't match "call".
_CALL_FN = re.compile(
    r"^(execute|exec|multicall|aggregate|tryaggregate|forward|proxy|call|"
    r"functioncall|delegatecall|dispatch|relay|batch)", re.IGNORECASE)
_DELEGATE_FN = re.compile(r"delegatecall|delegate", re.IGNORECASE)
_SWEEP_HINT = re.compile(r"withdraw|sweep|drain|rescue|recover|skim|collect", re.IGNORECASE)
_ADMIN_HINT = re.compile(
    r"transferownership|setadmin|setowner|grantrole|renounce|setimplementation", re.IGNORECASE)
# Parameter-name signals: a target address + an opaque calldata blob. bytes
# appears in countless BENIGN roles (names, signatures, merkle proofs, receiver
# hooks), so the NAME is what distinguishes calldata from data-as-content.
# "to" is deliberately EXCLUDED: it is a recipient in transfers, not a call
# target. A genuine arbitrary-call names its callee target/dest/callee/impl.
_TARGET_NAME = re.compile(r"^(target|dest|destination|callee|impl|implementation)$", re.IGNORECASE)
_CALLDATA_NAME = re.compile(r"^(data|calldata|payload|_data|callback|bytecode)$", re.IGNORECASE)
# Standard ERC token-receiver hooks: (…, bytes data) where data is a fixed,
# bounded hook payload passed to a known interface — NOT arbitrary calldata.
_RECEIVER_HOOKS = {"onerc721received", "onerc1155received", "onerc1155batchreceived",
                   "tokensreceived", "safetransferfrom", "safebatchtransferfrom"}


def _types(fn: dict) -> list[str]:
    return [common.canonical_type(i) for i in fn.get("inputs", [])]


def _named_target_and_calldata(fn: dict) -> bool:
    """True only when an address input is NAMED like a call target AND a bytes
    input is NAMED like calldata — the (target, calldata) arbitrary-call shape,
    not merely any address-plus-bytes function."""
    has_target = any(i.get("type", "").startswith("address") and _TARGET_NAME.match(i.get("name", ""))
                     for i in fn.get("inputs", []))
    has_calldata = any(i.get("type") == "bytes" and _CALLDATA_NAME.match(i.get("name", ""))
                       for i in fn.get("inputs", []))
    return has_target and has_calldata


def _is_call_fn(fn: dict) -> bool:
    """The function's own name declares it an arbitrary-call primitive."""
    return bool(_CALL_FN.match(fn.get("name", "")))


def _multicall(fn: dict) -> bool:
    """A bytes[] batch on a function whose name says it aggregates calls."""
    name = fn.get("name", "").lower()
    return any(t == "bytes[]" for t in _types(fn)) and \
        any(k in name for k in ("multicall", "aggregate", "batch", "execute"))


def assess(fn: dict) -> list[dict]:
    """Return danger findings for one signable function (may be several)."""
    name = fn.get("name", "")
    lname = name.lower()
    ts = _types(fn)
    out: list[dict] = []

    def flag(sev, primitive, why):
        out.append({"severity": sev, "function": name, "primitive": primitive, "why": why})

    # ── arbitrary external call: the (target, calldata) drainer primitive ──
    if lname in _RECEIVER_HOOKS:
        pass  # a standard receiver hook's bytes is a bounded payload, not calldata
    elif _is_call_fn(fn) or _named_target_and_calldata(fn):
        flag("CRITICAL", "arbitrary-external-call",
             "declares an unbounded external call (call-family name or a "
             "target-address + calldata-blob signature) — the signer cannot bound "
             "its effect by reading the screen; the canonical wallet-drainer "
             "primitive. A clear sentence cannot make it safe.")
    elif _multicall(fn):
        flag("CRITICAL", "multicall",
             "aggregates a bytes[] batch of raw calls — the combined effect is "
             "unbounded and cannot be summarised on one screen.")

    # ── delegatecall exposure ────────────────────────────────────────────────
    if _DELEGATE_FN.search(lname) and "delegate" in lname \
            and any(t.startswith("address") for t in ts):
        flag("CRITICAL", "delegatecall",
             "name implies DELEGATECALL — runs foreign code in this contract's own "
             "storage/authority context; a compromised or swapped target owns everything.")

    # ── self-destruct / kill switch ──────────────────────────────────────────
    if lname in ("selfdestruct", "kill", "destroy", "destruct") or "selfdestruct" in lname:
        flag("CRITICAL", "self-destruct",
             "reachable SELFDESTRUCT — can delete the contract and force-send its "
             "balance; irreversible.")

    # ── upgrade-and-execute ──────────────────────────────────────────────────
    if lname == "upgradetoandcall" or ("upgrade" in lname and _named_target_and_calldata(fn)):
        flag("CRITICAL", "upgrade-and-execute",
             "swaps the contract's code AND runs a call in one signature — the single "
             "most powerful action a proxy exposes.")

    # ── unbounded delegation ─────────────────────────────────────────────────
    if lname == "setapprovalforall":
        flag("HIGH", "unbounded-delegation",
             "grants an operator control over ALL of the signer's assets in this "
             "contract until revoked.")

    # ── authority transfer ───────────────────────────────────────────────────
    if _ADMIN_HINT.search(lname):
        flag("HIGH", "authority-transfer",
             "changes who controls the contract (ownership/admin/role) — affects every "
             "user, not just the signer's funds.")

    # ── unbounded value sweep to a caller-supplied address ──────────────────
    if _SWEEP_HINT.search(lname) and any(t.startswith("address") for t in ts):
        flag("MEDIUM", "value-sweep-to-arbitrary-address",
             "moves held value to a caller-supplied address — verify the destination "
             "is not attacker-controlled.")

    return out


def scan(desc: dict) -> dict:
    abi = common.descriptor_abi(desc)
    findings: list[dict] = []
    for fn in common.signable_functions(abi):
        findings.extend(assess(fn))
    findings.sort(key=lambda f: SEV_ORDER.index(f["severity"]))
    worst = findings[0]["severity"] if findings else None
    return {
        "danger_findings": findings,
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "worst_severity": worst,
        "signable_functions": len(common.signable_functions(abi)),
    }


def report(name: str, r: dict) -> None:
    n = r["danger_findings"]
    if not n:
        print(f"{name}: no dangerous primitives among {r['signable_functions']} "
              f"signable functions")
        return
    print(f"{name}: {r['critical']} critical danger primitive(s), worst "
          f"{r['worst_severity']}")
    for f in n:
        print(f"  {f['severity']:8} [{f['function']}] {f['primitive']}")
        print(f"      {f['why']}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("descriptor")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    r = scan(json.loads(Path(args.descriptor).read_text()))
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        report(Path(args.descriptor).stem, r)
    return 1 if args.strict and r["critical"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
