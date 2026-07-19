#!/usr/bin/env python3
"""Score a descriptor on whether its on-device screen is trustworthy, beyond
what `erc7730 lint` checks for well-formedness.

Checks (severity -> penalty): a payable function that never shows @.value or a
tokenAmount with unknown units (CRITICAL); a signable function with no intent, a
function with inputs but nothing displayable, an address shown as raw hex, a
signable function missing entirely, or a format entry keyed non-canonically
(parameter names embedded, so no wallet lookup ever matches it) (HIGH);
device-limit truncation (MEDIUM); a value-moving function without an
interpolated summary, or a format entry matching no ABI function (LOW).
Reports a letter grade; --strict exits non-zero below grade B.

    audit.py <descriptor.json> [--json] [--strict]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import common

PENALTY = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 2}
GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]
INTENT_MAX, LABEL_MAX = 30, 20


def _split_top(params: str) -> list[str]:
    """Split a parameter list on commas at paren depth zero."""
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(params):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(params[start:i])
            start = i + 1
    tail = params[start:]
    if tail.strip() or parts:
        parts.append(tail)
    return [p.strip() for p in parts if p.strip()]


def _canonical_key(key: str) -> str:
    """Canonicalize a format key that embeds parameter names, e.g.
    'transfer(address to, uint256 amount)' -> 'transfer(address,uint256)'.
    Wallets look formats up by the canonical signature, so a named key never
    matches at render time. Tuple components keep their parenthesized group;
    the name, if any, follows the group and is dropped the same way."""
    if "(" not in key or not key.endswith(")"):
        return key
    name, params = key.split("(", 1)
    params = params[:-1]

    def canon_component(c: str) -> str:
        if c.startswith("("):
            depth, i = 0, 0
            for i, ch in enumerate(c):
                depth += ch == "("
                depth -= ch == ")"
                if depth == 0:
                    break
            inner = "(" + ",".join(canon_component(x) for x in _split_top(c[1:i])) + ")"
            rest = c[i + 1:]
            suffix = rest.split()[0] if rest[:1] == "[" else ""
            return inner + suffix
        return c.split()[0]

    return name + "(" + ",".join(canon_component(c) for c in _split_top(params)) + ")"


def audit(desc: dict) -> dict:
    abi = common.descriptor_abi(desc)
    formats = desc.get("display", {}).get("formats", {})
    signable = {common.signature(f): f for f in common.signable_functions(abi)}

    findings = []
    def flag(severity, sig, issue):
        findings.append({"severity": severity, "function": sig.split("(")[0], "issue": issue})

    # A format entry keyed with embedded parameter names never matches the
    # canonical signature a wallet looks up, so the function blind-signs even
    # though an entry exists. Map canonical -> original key to say so precisely.
    noncanonical = {}
    for key in formats:
        canon = _canonical_key(key)
        if canon != key and canon in signable:
            noncanonical[canon] = key
    for key in formats:
        canon = _canonical_key(key)
        if key not in signable and canon not in signable:
            flag("LOW", key, "format entry matches no signable function in the ABI (orphan)")

    for sig, fn in signable.items():
        fmt = formats.get(sig)
        if fmt is None:
            if sig in noncanonical:
                flag("HIGH", sig,
                     f"format entry keyed non-canonically as '{noncanonical[sig]}' - "
                     "wallets match the canonical signature, so this entry never "
                     "renders (blind-signs as submitted)")
            else:
                flag("HIGH", sig, "signable function has no descriptor entry (blind-signs)")
            continue

        fields = fmt.get("fields", [])
        inputs = fn["inputs"]
        input_types = {i["name"]: i["type"] for i in inputs if i["name"]}

        if not fmt.get("intent") and not fmt.get("interpolatedIntent"):
            flag("HIGH", sig, "no intent")

        value_field = next((f for f in fields if f.get("path") == "@.value"), None)
        if fn.get("stateMutability") == "payable" and value_field is None:
            flag("CRITICAL", sig, "payable but never displays the ETH amount (@.value)")

        visible = [f for f in fields if f.get("visible") != "never"]
        if inputs and not visible:
            flag("HIGH", sig, "no visible field, blind-signs despite a descriptor")
        if value_field is not None and value_field.get("visible") != "always":
            flag("LOW", sig, "payable amount not pinned visible:always")

        for f in fields:
            fmt_name = f.get("format")
            path = f.get("path", "")
            leaf = path[2:].split(".")[0] if path.startswith("#.") else None
            if leaf and input_types.get(leaf, "").startswith("address") \
                    and fmt_name == "raw" and f.get("visible") != "never":
                flag("HIGH", sig, f"address '{leaf}' shown as raw hex, not addressName")
            if fmt_name == "tokenAmount":
                p = f.get("params", {})
                if not p.get("token") and not p.get("tokenPath"):
                    flag("CRITICAL", sig, f"tokenAmount '{leaf}' has no token/tokenPath")
            if f.get("label") and len(f["label"]) > LABEL_MAX:
                flag("MEDIUM", sig, f"label '{f['label']}' exceeds {LABEL_MAX} chars")

        for key in ("intent", "interpolatedIntent"):
            if fmt.get(key) and len(fmt[key]) > INTENT_MAX:
                flag("MEDIUM", sig, f"{key} exceeds {INTENT_MAX} chars")

        moves_value = fn.get("stateMutability") == "payable" or \
            any(f.get("format") in ("amount", "tokenAmount") for f in fields)
        if moves_value and len(visible) >= 2 and not fmt.get("interpolatedIntent"):
            flag("LOW", sig, "value-moving function without interpolatedIntent")

    score = max(0, 100 - sum(PENALTY[f["severity"]] for f in findings))
    grade = next(g for cut, g in GRADES if score >= cut)
    return {
        "score": score, "grade": grade,
        "signable_functions": len(signable),
        "covered_functions": sum(1 for s in signable if s in formats),
        "findings": sorted(findings, key=lambda f: list(PENALTY).index(f["severity"])),
    }


def report(name: str, r: dict) -> None:
    print(f"{name}: grade {r['grade']} ({r['score']}/100), "
          f"coverage {r['covered_functions']}/{r['signable_functions']}")
    for f in r["findings"]:
        print(f"  {f['severity']:8} [{f['function']}] {f['issue']}")
    if not r["findings"]:
        print("  no issues")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("descriptor")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    r = audit(json.loads(Path(args.descriptor).read_text()))
    print(json.dumps(r, indent=2) if args.json else "", end="")
    if not args.json:
        report(Path(args.descriptor).stem, r)
    return 1 if args.strict and r["grade"] not in ("A", "B") else 0


if __name__ == "__main__":
    raise SystemExit(main())
