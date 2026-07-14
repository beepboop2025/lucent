#!/usr/bin/env python3
"""Lucent Descriptor Security Audit — score an ERC-7730 descriptor on the
things that make a clear-signing screen *trustworthy*, not just schema-valid.

`erc7730 lint` answers "is this well-formed?". This answers "would this screen
actually protect a user, or lull them?" — which is the whole product. It codifies
the manual hardening judgement into a repeatable grade, so the moat
(verification, not generation) is a tool, and the output is a sellable artifact:
a Descriptor Security Report with a letter grade.

Checks (severity → penalty):
  CRITICAL  payable function that never displays @.value   (user can't see funds leaving)
  CRITICAL  tokenAmount with no token / tokenPath           (amount rendered with unknown/foreign units)
  HIGH      signable function with no intent                (no plain-language summary)
  HIGH      function with inputs but nothing visible:always (nothing guaranteed on screen)
  HIGH      address input rendered as raw hex               (loses name resolution / phishing check)
  HIGH      signable function absent from the descriptor    (silently blind-signs)
  MEDIUM    intent > 30 chars / label > 20 chars            (truncated on device)
  LOW       multi-field function without interpolatedIntent (weaker summary)

Usage:
    python scripts/audit.py <descriptor.json> [--json] [--strict]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import preview  # descriptor_abi(), _canonical_type()

PENALTY = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 2}
GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]
INTENT_MAX, LABEL_MAX = 30, 20


def canon_sig(fn: dict) -> str:
    types = ",".join(preview._canonical_type(i) for i in fn["inputs"])
    return f'{fn["name"]}({types})'


def audit(desc: dict) -> dict:
    abi = preview.descriptor_abi(desc)
    formats = desc.get("display", {}).get("formats", {})
    funcs = {canon_sig(e): e for e in abi if e.get("type") == "function"}
    signable = {s: e for s, e in funcs.items()
                if e.get("stateMutability") not in ("view", "pure")}

    findings = []
    def flag(sev, sig, msg):
        findings.append({"severity": sev, "function": sig.split("(")[0], "issue": msg})

    for sig, fn in signable.items():
        fmt = formats.get(sig)
        if fmt is None:
            # A hook like onERC721Received is signable-typed but not user-initiated;
            # only flag if it takes value-moving-looking inputs. Keep it simple: flag all.
            flag("HIGH", sig, "signable function has no descriptor entry (blind-signs)")
            continue

        fields = fmt.get("fields", [])
        inputs = fn["inputs"]
        input_types = {i["name"]: i["type"] for i in inputs if i["name"]}

        if not fmt.get("intent") and not fmt.get("interpolatedIntent"):
            flag("HIGH", sig, "no intent — no plain-language summary")

        # payable must reveal the ETH being spent
        value_field = next((f for f in fields if f.get("path") == "@.value"), None)
        if fn.get("stateMutability") == "payable" and value_field is None:
            flag("CRITICAL", sig, "payable but never displays the ETH amount (@.value)")

        # true blindness: has inputs but nothing is displayable at all
        # (a field defaults to visible unless explicitly visible:never)
        visible_fields = [f for f in fields if f.get("visible") != "never"]
        if inputs and not visible_fields:
            flag("HIGH", sig, "no visible field — blind-signs despite a descriptor")

        # best practice: pin the ETH amount visible:always so reduced-display
        # wallets still show what is being spent
        if value_field is not None and value_field.get("visible") != "always":
            flag("LOW", sig, "payable amount not pinned visible:always")

        for f in fields:
            fmt_name = f.get("format")
            path = f.get("path", "")
            leaf = path[2:].split(".")[0] if path.startswith("#.") else None

            # address rendered as raw hex
            if leaf and input_types.get(leaf, "").startswith("address") \
                    and fmt_name not in ("addressName", None) and f.get("visible") != "never":
                if fmt_name == "raw":
                    flag("HIGH", sig, f"address '{leaf}' shown as raw hex, not addressName")

            # tokenAmount must know its token
            if fmt_name == "tokenAmount":
                p = f.get("params", {})
                if not p.get("token") and not p.get("tokenPath"):
                    flag("CRITICAL", sig, f"tokenAmount '{leaf}' has no token/tokenPath (foreign units)")

            if f.get("label") and len(f["label"]) > LABEL_MAX:
                flag("MEDIUM", sig, f"label '{f['label']}' > {LABEL_MAX} chars (truncates)")

        for key in ("intent", "interpolatedIntent"):
            if fmt.get(key) and len(fmt[key]) > INTENT_MAX:
                flag("MEDIUM", sig, f"{key} > {INTENT_MAX} chars (truncates)")

        # a one-line interpolated summary matters most where value moves
        moves_value = fn.get("stateMutability") == "payable" or \
            any(f.get("format") in ("amount", "tokenAmount") for f in fields)
        if moves_value and len(visible_fields) >= 2 and not fmt.get("interpolatedIntent"):
            flag("LOW", sig, "value-moving function without interpolatedIntent")

    penalty = sum(PENALTY[f["severity"]] for f in findings)
    score = max(0, 100 - penalty)
    grade = next(g for cut, g in GRADES if score >= cut)
    covered = sum(1 for s in signable if s in formats)
    return {
        "score": score, "grade": grade,
        "signable_functions": len(signable),
        "covered_functions": covered,
        "findings": sorted(findings, key=lambda f: list(PENALTY).index(f["severity"])),
    }


def report(name: str, r: dict) -> None:
    bar = "█" * (r["score"] // 5) + "░" * (20 - r["score"] // 5)
    print(f"\n╔══ Descriptor Security Report ═══════════════════════════════╗")
    print(f"  {name}")
    print(f"  Grade {r['grade']}   score {r['score']}/100   [{bar}]")
    print(f"  coverage {r['covered_functions']}/{r['signable_functions']} signable functions")
    print(f"╚═════════════════════════════════════════════════════════════╝")
    if not r["findings"]:
        print("  ✔ no issues — trustworthy screen")
        return
    counts = {}
    for f in r["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("  " + "  ".join(f"{k}:{v}" for k, v in counts.items()))
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}
    for f in r["findings"]:
        print(f"  {icon[f['severity']]} [{f['function']}] {f['issue']}")


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 2
    r = audit(json.loads(Path(args[0]).read_text()))
    if "--json" in sys.argv:
        print(json.dumps(r, indent=2))
    else:
        report(Path(args[0]).stem, r)
    if "--strict" in sys.argv and r["grade"] not in ("A", "B"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
