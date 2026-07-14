#!/usr/bin/env python3
"""Score a descriptor on whether its on-device screen is trustworthy, beyond
what `erc7730 lint` checks for well-formedness.

Checks (severity -> penalty): a payable function that never shows @.value or a
tokenAmount with unknown units (CRITICAL); a signable function with no intent, a
function with inputs but nothing displayable, an address shown as raw hex, or a
signable function missing entirely (HIGH); device-limit truncation (MEDIUM); a
value-moving function without an interpolated summary (LOW). Reports a letter
grade; --strict exits non-zero below grade B.

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


def audit(desc: dict) -> dict:
    abi = common.descriptor_abi(desc)
    formats = desc.get("display", {}).get("formats", {})
    signable = {common.signature(f): f for f in common.signable_functions(abi)}

    findings = []
    def flag(severity, sig, issue):
        findings.append({"severity": severity, "function": sig.split("(")[0], "issue": issue})

    for sig, fn in signable.items():
        fmt = formats.get(sig)
        if fmt is None:
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
