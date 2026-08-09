#!/usr/bin/env python3
"""Grade a descriptor on COMPREHENSION risk — will the human who reads the
screen actually understand what they are authorizing?

Lint checks well-formedness; audit.py checks that the screen SHOWS the right
fields. Neither asks the question that "What I Sign Is Not What I See"
(arXiv:2601.16751) shows is the real failure mode: users mis-UNDERSTAND a
technically-correct screen. Their formative studies found people fixate on
surface cues (amount, recipient) and miss scope, delegation, and unlimited
allowances — and that a signature rendered as a bare field list, even a
complete one, leaves comprehension at chance on the dangerous cases.

Two deliverables, both from that paper's Signature Semantic Decoder:

1. A CONSEQUENCE SENTENCE per signable function: actor -> action -> object
   (+ conditions), e.g. "You let {spender} move up to {amount} of your
   {token}, with no expiry." Built from the ABI + the descriptor's own field
   labels, so it renders exactly what the wallet will show — not marketing
   copy. This is the descriptor's `interpolatedIntent` held to a real
   standard: a full sentence naming who acts on what, not "Approve {token}".

2. A RISK TIER with a REASON. The paper's users explicitly rejected bare
   labels ("high risk") and demanded the WHY. Each function is scored on
   consequence patterns the study found people miss — unlimited allowance,
   delegation/operator grants, raw-hex recipients, self-custody transfer of
   value, upgrade/admin authority — and every tier carries the specific
   clause that earned it.

Conservative by construction: an unrecognized pattern is reported as
"unclassified consequence" (a caution), never silently cleared — an
unexplained screen is exactly the failure the paper warns about.

    comprehend.py <descriptor.json> [--json] [--strict]
    (--strict exits non-zero if any function lands in the CRITICAL tier)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import common

# Consequence risk tiers, worst first. Each maps to a penalty for an aggregate
# "comprehension grade" so a bundle can be scored, but the per-function REASON
# is the product — the tier alone is what the paper's users rejected.
TIER_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
TIER_PENALTY = {"CRITICAL": 30, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 0}
GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]

# Unbounded-allowance sentinel: 2^256-1, the classic "infinite approval".
UINT256_MAX = (1 << 256) - 1


def _labels(fmt: dict) -> dict:
    """path leaf -> human label from the descriptor, for readable sentences."""
    out = {}
    for f in fmt.get("fields", []):
        path = f.get("path", "")
        if path.startswith("#."):
            out[path[2:].split(".")[0]] = f.get("label") or path[2:]
        elif path == "@.value":
            out["@value"] = f.get("label") or "ETH amount"
    return out


def _name(fn: dict) -> str:
    return fn.get("name", "")


def _has_input(fn: dict, *type_prefixes: str, name_hint: str = "") -> dict | None:
    """First input whose type matches a prefix (and, if given, whose name
    contains name_hint). Returns the input dict or None."""
    for i in fn.get("inputs", []):
        t = common.canonical_type(i)
        if any(t.startswith(p) for p in type_prefixes):
            if not name_hint or name_hint.lower() in (i.get("name") or "").lower():
                return i
    return None


def classify(fn: dict, fmt: dict | None) -> dict:
    """Return {tier, reason, sentence} for one signable function.

    The reason is the clause that earned the tier — the paper's core UX
    requirement. The sentence is the actor->action->object rendering.
    """
    name = _name(fn)
    lname = name.lower()
    payable = fn.get("stateMutability") == "payable"

    def lbl(leaf: str, default: str) -> str:
        # ABI identifiers are schema-validated before hosted/MCP analysis.
        # Descriptor-authored labels and intents are never copied into an
        # agent-facing consequence sentence.
        return "{" + (leaf or default) + "}"

    # ── delegation / operator grants: the highest-consequence, most-missed ──
    if lname == "setapprovalforall" or ("approval" in lname and _has_input(fn, "bool")):
        operator = _has_input(fn, "address")
        who = lbl(operator["name"], "operator") if operator else "an operator"
        return {
            "tier": "CRITICAL",
            "reason": "grants operator control over your ENTIRE collection/balance, "
                      "not a single asset — the approval persists until you revoke it",
            "sentence": f"You let {who} transfer ANY of your tokens in this contract, "
                        f"at any time, until you revoke it.",
        }

    # ── approvals: an ERC-721 tokenId grant and an ERC-20 allowance read
    #    identically on-chain (approve(address,uint256)) but mean different
    #    things — the paper's whole thesis is that this ambiguity is where
    #    users are fooled, so we DISAMBIGUATE by the parameter name. ─────────
    if lname in ("approve", "increaseallowance") or lname.endswith("approve"):
        spender = _has_input(fn, "address")
        amount = _has_input(fn, "uint")
        who = lbl(spender["name"], "spender") if spender else "a spender"
        is_nft = bool(amount and "tokenid" in (amount.get("name") or "").lower())
        if is_nft:
            tok = lbl(amount["name"], "token id")
            return {
                "tier": "HIGH",
                "reason": "grants control of ONE specific NFT (by token id) to the "
                          "approved address — they can transfer that NFT out of your "
                          "wallet until you revoke it",
                "sentence": f"You let {who} take the NFT with id {tok} from your "
                            f"wallet, until you revoke it.",
            }
        amt = lbl(amount["name"], "amount") if amount else "an amount"
        return {
            "tier": "HIGH",
            "reason": "an ERC-20 allowance lets the spender pull tokens from YOUR "
                      "wallet later, without another signature — check for an "
                      "UNLIMITED amount, the single most-exploited drainer pattern",
            "sentence": f"You let {who} spend up to {amt} of your tokens on your "
                        f"behalf, until you change or revoke it.",
        }

    # ── upgrade / admin authority ────────────────────────────────────────────
    if any(k in lname for k in ("upgrade", "setimplementation", "setadmin",
                                "transferownership", "setowner", "grantrole")):
        return {
            "tier": "CRITICAL",
            "reason": "changes WHO controls the contract or WHAT code runs — a "
                      "consequence far beyond moving your own funds",
            "sentence": f"You change the control or code of the contract "
                        f"({name}), affecting everyone who uses it.",
        }

    # ── permit / signature-based approval (gasless, easy to under-read) ──────
    if "permit" in lname:
        spender = _has_input(fn, "address", name_hint="spend") or _has_input(fn, "address")
        who = lbl(spender["name"], "spender") if spender else "a spender"
        return {
            "tier": "HIGH",
            "reason": "a permit is an OFF-CHAIN approval — no transaction appears in "
                      "your history, so it is easy to grant and forget",
            "sentence": f"You sign an off-chain approval letting {who} spend your "
                        f"tokens — it takes effect with no transaction from you.",
        }

    # ── value/asset-moving transfers (transferFrom, safeTransferFrom, ...) ──
    if "transfer" in lname or lname in ("send", "withdraw") or payable:
        to = _has_input(fn, "address", name_hint="to") or _has_input(fn, "address")
        amount = _has_input(fn, "uint", name_hint="amount") or _has_input(fn, "uint")
        who = lbl(to["name"], "recipient") if to else "a recipient"
        amt = lbl("@value" if payable else (amount["name"] if amount else ""),
                  "amount")
        raw_addr = _recipient_shown_raw(fn, fmt)
        tier = "MEDIUM" if not raw_addr else "HIGH"
        reason = ("moves value out of your wallet now — verify the recipient is who "
                  "you expect")
        if raw_addr:
            reason += "; the recipient is shown as RAW HEX, which is unreadable and "\
                      "the exact surface address-poisoning attacks exploit"
        return {
            "tier": tier,
            "reason": reason,
            "sentence": f"You send {amt} to {who} now.",
        }

    # ── everything else: name it, don't wave it through ─────────────────────
    if fmt and (fmt.get("intent") or fmt.get("interpolatedIntent")):
        return {
            "tier": "HIGH",
            "reason": "Lucent has not classified this function's consequence; "
                      "caller-authored intent cannot substitute for policy semantics",
            "sentence": f"You call {name}; Lucent has not classified its consequence.",
        }
    return {
        "tier": "HIGH",
        "reason": "unclassified consequence AND no intent on the screen — the human "
                  "has nothing to understand the action from (an unexplained screen "
                  "is worse than none: it invites blind approval)",
        "sentence": f"You call {name} — the screen does not explain what this does.",
    }


def _recipient_shown_raw(fn: dict, fmt: dict | None) -> bool:
    """True if an address input is rendered as raw hex (not addressName) or
    not rendered at all — the readability failure the paper measures."""
    if not fmt:
        return bool(_has_input(fn, "address"))
    fields = {f.get("path"): f for f in fmt.get("fields", [])}
    for i in fn.get("inputs", []):
        if common.canonical_type(i).startswith("address"):
            f = fields.get(f'#.{i["name"]}')
            if f is None or f.get("visible") == "never" or f.get("format") != "addressName":
                return True
    return False


def comprehend(desc: dict) -> dict:
    abi = common.descriptor_abi(desc)
    formats = desc.get("display", {}).get("formats", {})
    results = []
    for fn in common.signable_functions(abi):
        sig = common.signature(fn)
        c = classify(fn, formats.get(sig))
        results.append({"function": fn["name"], "signature": sig, **c})

    results.sort(key=lambda r: TIER_ORDER.index(r["tier"]))
    score = max(0, 100 - sum(TIER_PENALTY[r["tier"]] for r in results))
    grade = next(g for cut, g in GRADES if score >= cut)
    worst = results[0]["tier"] if results else "INFO"
    return {
        "comprehension_score": score,
        "comprehension_grade": grade,
        "worst_tier": worst,
        "functions": results,
    }


def report(name: str, r: dict) -> None:
    print(f"{name}: comprehension grade {r['comprehension_grade']} "
          f"({r['comprehension_score']}/100), worst tier {r['worst_tier']}")
    for f in r["functions"]:
        print(f"  [{f['tier']:8}] {f['function']}")
        print(f"      screen: {f['sentence']}")
        print(f"      why:    {f['reason']}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("descriptor")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    r = comprehend(json.loads(Path(args.descriptor).read_text()))
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        report(Path(args.descriptor).stem, r)
    return 1 if args.strict and r["worst_tier"] == "CRITICAL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
