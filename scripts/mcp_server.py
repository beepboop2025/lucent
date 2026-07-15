#!/usr/bin/env python3
"""Lucent MCP server — a pre-sign transaction-safety check for signing agents.

An AI agent about to sign a blockchain transaction faces exactly the problem
Lucent's pipeline solves offline: is this call safe, and does the screen it
would show a human actually describe what it does? This server exposes that
check over MCP so an agent can call it BEFORE it signs.

Three tools, built on the same analysis the pipeline uses:

  check_descriptor   Given an ERC-7730 descriptor, return a combined safety
                     read: the audit grade (does the screen show the right
                     fields), the comprehension grade (will a human understand
                     it) with a plain-language consequence sentence per
                     function, and the danger scan (structural primitives a
                     clear screen can't make safe). One overall verdict an agent
                     can gate on.
  explain_signature  Given a descriptor and one function, return the single
                     actor->action->object consequence sentence + risk tier +
                     the reason — what a wallet should show before this signature.
  scan_contract      Given a chain id + contract address (no descriptor needed),
                     fetch the verified ABI and run the danger scan over every
                     signable function — so an agent can assess a contract it is
                     about to interact with even when no descriptor exists yet.

stdlib-only JSON-RPC 2.0 over stdio (the same transport shape as the sibling
Groundcheck/Seiche servers); no framework, no new deps. Honest degradation: a
missing ABI or an unreachable Sourcify is reported, never guessed around.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import audit  # noqa: E402
import comprehend  # noqa: E402
import common  # noqa: E402
import danger  # noqa: E402

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "lucent"
SERVER_VERSION = "0.1.0"

TOOLS = [
    {
        "name": "check_descriptor",
        "description": (
            "Pre-sign safety check for an ERC-7730 Clear Signing descriptor. Call "
            "BEFORE signing or approving a transaction whose descriptor you have. "
            "Returns a combined read you can GATE ON:\n"
            "• audit: does the on-device screen show the right fields (grade A-F).\n"
            "• comprehension: will a human understand what they authorize — a "
            "plain-language consequence sentence per function ('You let X spend up to "
            "Y of your tokens…') and a risk tier WITH the reason it earned.\n"
            "• danger: structural 'loaded gun' primitives a clear screen still can't "
            "make safe — arbitrary external call, delegatecall, self-destruct, "
            "upgrade-and-execute, unbounded delegation. CRITICAL danger means do not "
            "sign blind no matter how benign the sentence reads.\n"
            "• verdict: overall safe_to_present / review / block, so you can branch."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "descriptor": {"type": "object",
                               "description": "The ERC-7730 descriptor JSON (inline)."},
            },
            "required": ["descriptor"],
        },
    },
    {
        "name": "explain_signature",
        "description": (
            "Explain ONE function of a descriptor the way a wallet should show it "
            "before signing: an actor->action->object consequence sentence, a risk "
            "tier, and the specific reason. Use to render a human-readable, "
            "risk-annotated confirmation for a single pending signature."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "descriptor": {"type": "object", "description": "The ERC-7730 descriptor JSON."},
                "function": {"type": "string",
                             "description": "Function name to explain (e.g. 'approve')."},
            },
            "required": ["descriptor", "function"],
        },
    },
    {
        "name": "scan_contract",
        "description": (
            "Danger-scan a deployed contract by address — no descriptor needed. "
            "Fetches the verified ABI (Sourcify) and flags every signable function "
            "that is a structural danger primitive (arbitrary call, delegatecall, "
            "self-destruct, upgrade-and-execute, unbounded delegation, authority "
            "transfer). Use to assess a contract an agent is about to interact with "
            "before any transaction is built. Returns matched=false honestly when the "
            "ABI cannot be fetched."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "chain_id": {"type": "integer", "description": "EVM chain id (1 = mainnet).",
                             "default": 1},
                "address": {"type": "string", "description": "0x contract address."},
            },
            "required": ["address"],
        },
    },
]


# ── tool implementations ────────────────────────────────────────────────────────

def _overall_verdict(audit_r: dict, danger_r: dict, comp_r: dict) -> dict:
    """Fold the three lenses into one gate. Danger dominates: a CRITICAL
    primitive blocks regardless of a clean screen; else the weaker of audit /
    comprehension grade decides."""
    if danger_r.get("critical", 0) > 0:
        return {"gate": "block",
                "reason": f"{danger_r['critical']} CRITICAL danger primitive(s) — a "
                          "clear screen cannot make this safe to sign blind"}
    worst_comp = comp_r.get("worst_tier")
    if worst_comp == "CRITICAL":
        return {"gate": "review",
                "reason": "a function carries CRITICAL comprehension risk (e.g. operator "
                          "grant, admin/upgrade authority) — present with a prominent warning"}
    if audit_r.get("grade") in ("D", "F"):
        return {"gate": "review",
                "reason": f"descriptor audit grade {audit_r.get('grade')} — the screen "
                          "may not show the right fields"}
    return {"gate": "safe_to_present",
            "reason": "no critical danger primitive; the screen audits and reads clearly"}


def check_descriptor(args: dict) -> dict:
    desc = args["descriptor"]
    audit_r = audit.audit(desc)
    comp_r = comprehend.comprehend(desc)
    danger_r = danger.scan(desc)
    return {
        "verdict": _overall_verdict(audit_r, danger_r, comp_r),
        "audit": {"grade": audit_r["grade"], "score": audit_r["score"],
                  "findings": audit_r["findings"]},
        "comprehension": {"grade": comp_r["comprehension_grade"],
                          "worst_tier": comp_r["worst_tier"],
                          "functions": comp_r["functions"]},
        "danger": danger_r,
    }


def explain_signature(args: dict) -> dict:
    desc = args["descriptor"]
    want = args["function"]
    comp_r = comprehend.comprehend(desc)
    match = next((f for f in comp_r["functions"] if f["function"] == want), None)
    if match is None:
        return {"found": False,
                "reason": f"no signable function named {want!r} in the descriptor",
                "available": [f["function"] for f in comp_r["functions"]]}
    return {"found": True, **match}


def scan_contract(args: dict) -> dict:
    chain_id = int(args.get("chain_id", 1))
    address = args["address"]
    try:
        abi = common.sourcify_abi(chain_id, address)
    except Exception as exc:  # noqa: BLE001 — network/HTTP failure degrades honestly
        return {"matched": False, "chain_id": chain_id, "address": address,
                "reason": f"could not fetch ABI: {type(exc).__name__}: {exc}"}
    if not abi:
        return {"matched": False, "chain_id": chain_id, "address": address,
                "reason": "no verified ABI on Sourcify for this address"}
    desc = {"context": {"contract": {"abi": abi}}, "display": {"formats": {}}}
    danger_r = danger.scan(desc)
    return {"matched": True, "chain_id": chain_id, "address": address, **danger_r}


HANDLERS = {
    "check_descriptor": check_descriptor,
    "explain_signature": explain_signature,
    "scan_contract": scan_contract,
}


# ── JSON-RPC plumbing ────────────────────────────────────────────────────────────

def _result(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _text(mid, payload, is_error=False):
    return _result(mid, {"content": [{"type": "text",
                                      "text": json.dumps(payload, indent=2, default=str)}],
                         "isError": is_error})


def dispatch(msg: dict) -> dict | None:
    """Handle one JSON-RPC message; None for notifications (no id)."""
    method = msg.get("method")
    mid = msg.get("id")
    if method == "initialize":
        return _result(mid, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "Pre-sign safety checks for signing agents. check_descriptor grades a "
                "descriptor (audit + comprehension + danger) into one gate; "
                "explain_signature renders the human sentence + risk for one function; "
                "scan_contract danger-scans a deployed contract by address. Gate your "
                "signature on verdict.gate: block on CRITICAL danger primitives no "
                "matter how benign the screen reads."),
        })
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "tools/list":
        return _result(mid, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        handler = HANDLERS.get(name)
        if handler is None:
            return _error(mid, -32601, f"unknown tool {name!r}")
        try:
            return _text(mid, handler(params.get("arguments") or {}))
        except KeyError as exc:
            return _text(mid, {"error": f"missing required argument: {exc}"}, is_error=True)
        except Exception as exc:  # noqa: BLE001 — report, never crash the server
            return _text(mid, {"error": f"{type(exc).__name__}: {exc}"}, is_error=True)
    if mid is not None:
        return _error(mid, -32601, f"unknown method {method!r}")
    return None


def main() -> None:
    """stdio JSON-RPC loop: one message per line in, one response per line out."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = dispatch(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
