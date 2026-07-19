#!/usr/bin/env python3
"""Produce a publishable review of one or more ERC-7730 descriptors.

Composes the checks this repo already ships (erc7730 lint, screen audit,
comprehension risk, danger surface, and semantic verification when test
vectors plus an ETHERSCAN_API_KEY are available) into one markdown report a
reviewer can post on a registry pull request. The overall verdict is the same
gate the MCP server exposes to signing agents (mcp_server._overall_verdict),
so a human review and an agent pre-flight can never disagree.

    review.py <descriptor.json> [more.json ...] [--tests path] [--out report.md]
              [--json] [--no-lint] [--no-semverify]

--tests applies only when reviewing a single descriptor; otherwise vectors are
autodiscovered at <dir>/tests/<name>.tests.json, the registry convention.
Semantic verification is attempted when a vectors file exists and
ETHERSCAN_API_KEY is set; anything that prevents it is reported as a skip with
the reason, never silently passed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import audit  # noqa: E402
import common  # noqa: E402
import comprehend  # noqa: E402
import danger  # noqa: E402
import mcp_server  # noqa: E402
import semverify  # noqa: E402


def _deployments(desc: dict) -> list[str]:
    out = []
    for d in desc.get("context", {}).get("contract", {}).get("deployments", []):
        chain = d.get("chainId", "?")
        out.append(f"eip155:{chain} {d.get('address', '?')}")
    return out


def _lint(path: Path) -> dict:
    """Run erc7730 lint as a subprocess. ABI cross-validation needs an
    ETHERSCAN_API_KEY; without one we lint with --skip-abi-validation and say so.
    Runs in the descriptor's own directory on the bare filename: the report is
    meant to be posted publicly, so no local absolute path may appear in it,
    and the registry lint expects registry-style names in place."""
    binary = Path(sys.executable).with_name("erc7730")
    if not binary.exists():
        found = shutil.which("erc7730")
        if not found:
            return {"status": "unavailable",
                    "detail": "erc7730 binary not found next to the interpreter or on PATH"}
        binary = Path(found)
    skip_abi = not os.environ.get("ETHERSCAN_API_KEY")
    cmd = [str(binary), "lint"] + (["--skip-abi-validation"] if skip_abi else []) + [path.name]
    env = {**os.environ, "COLUMNS": "4000"}  # erc7730 wraps output at terminal width
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                          cwd=path.resolve().parent, env=env)
    return {
        "status": "pass" if proc.returncode == 0 else "fail",
        "abi_validation": "skipped (no ETHERSCAN_API_KEY)" if skip_abi else "full",
        "detail": "" if proc.returncode == 0 else (proc.stdout + proc.stderr).strip()[-2000:],
    }


def _semverify(path: Path, tests: Path | None) -> dict:
    tests_path = tests or path.parent / "tests" / (path.stem + ".tests.json")
    if not tests_path.exists():
        return {"status": "skipped",
                "reason": f"no test vectors at tests/{tests_path.name}"}
    if not os.environ.get("ETHERSCAN_API_KEY"):
        return {"status": "skipped",
                "reason": "ETHERSCAN_API_KEY not set; receipts cannot be fetched"}
    try:
        r = semverify.evaluate(path, tests=tests_path)
    except Exception as exc:  # noqa: BLE001 - a broken vector file or network failure is a skip, not a pass
        reason = f"{type(exc).__name__}: {exc}".replace(str(path.resolve().parent), ".")
        return {"status": "skipped", "reason": reason}
    r["status"] = "ok"
    return r


def review_descriptor(path: Path, tests: Path | None = None,
                      run_lint: bool = True, run_semverify: bool = True) -> dict:
    """All checks for one descriptor, folded under the shared agent gate."""
    desc = json.loads(path.read_text())
    try:
        abi_ok, abi_err = bool(common.descriptor_abi(desc)), ""
    except Exception as exc:  # noqa: BLE001 - unresolvable ABI must surface in the report
        abi_ok = False
        abi_err = f"{type(exc).__name__}: {exc}".replace(
            str(common.ABI_CACHE), "abi_cache")
    if not abi_ok:
        return {"descriptor": path.stem, "path": str(path),
                "deployments": _deployments(desc),
                "error": f"could not resolve the contract ABI ({abi_err}); "
                         "review requires the verified ABI"}

    audit_r = audit.audit(desc)
    comp_r = comprehend.comprehend(desc)
    danger_r = danger.scan(desc)
    return {
        "descriptor": path.stem,
        "path": str(path),
        "deployments": _deployments(desc),
        "verdict": mcp_server._overall_verdict(audit_r, danger_r, comp_r),
        "lint": _lint(path) if run_lint else {"status": "skipped", "reason": "--no-lint"},
        "audit": audit_r,
        "comprehension": comp_r,
        "danger": danger_r,
        "semverify": (_semverify(path, tests) if run_semverify
                      else {"status": "skipped", "reason": "--no-semverify"}),
    }


def _md_one(r: dict) -> str:
    lines = [f"## {r['descriptor']}", ""]
    for d in r["deployments"]:
        lines.append(f"- deployment: `{d}`")
    if "error" in r:
        lines += ["", f"**Review not possible:** {r['error']}", ""]
        return "\n".join(lines)

    a, c, g = r["audit"], r["comprehension"], r["danger"]
    lines += [
        f"- signable functions: {a['signable_functions']}, "
        f"covered: {a['covered_functions']}",
        "",
        f"**Verdict: {r['verdict']['gate']}** - {r['verdict']['reason']}",
        "",
        f"### Lint: {r['lint']['status']}",
    ]
    if r["lint"].get("abi_validation"):
        lines.append(f"- ABI validation: {r['lint']['abi_validation']}")
    if r["lint"].get("detail"):
        lines += ["", "```", r["lint"]["detail"], "```"]
    if r["lint"].get("reason"):
        lines.append(f"- {r['lint']['reason']}")

    lines += ["", f"### Screen audit: grade {a['grade']} ({a['score']}/100)"]
    for f in a["findings"]:
        lines.append(f"- {f['severity']} `{f['function']}`: {f['issue']}")
    if not a["findings"]:
        lines.append("- no issues")

    lines += ["", f"### Comprehension: grade {c['comprehension_grade']} "
                  f"({c['comprehension_score']}/100), worst tier {c['worst_tier']}"]
    flagged = [f for f in c["functions"] if f.get("tier") in ("CRITICAL", "HIGH", "MEDIUM")]
    for f in flagged:
        lines += [f"- {f['tier']} `{f['function']}`",
                  f"  - screen: {f['sentence']}",
                  f"  - why: {f['reason']}"]
    if not flagged:
        lines.append("- no function above LOW comprehension risk")

    lines += ["", "### Danger surface"]
    if g.get("danger_findings"):
        for f in g["danger_findings"]:
            lines += [f"- {f['severity']} `{f['function']}`: {f['primitive']}",
                      f"  - {f['why']}"]
    else:
        lines.append(f"- no dangerous primitives among "
                     f"{g.get('signable_functions', '?')} signable functions")

    s = r["semverify"]
    lines += ["", "### Semantic verification"]
    if s["status"] == "ok":
        lines.append(f"- verified {s['verified']}/{s['total']} vectors, "
                     f"{s['divergences']} divergence(s)")
        for row in s.get("rows", []):
            if not row["ok"]:
                lines.append(f"- DIVERGENCE `{row['sig']}` ({row['source']}): "
                             + "; ".join(row["findings"]))
        for sk in s.get("skipped", []):
            lines.append(f"- skipped vector {sk.get('call', '?')}: {sk.get('reason', '')}")
    else:
        lines.append(f"- skipped: {s.get('reason', '')}")
    lines.append("")
    return "\n".join(lines)


def markdown_report(results: list[dict]) -> str:
    head = ["# ERC-7730 descriptor review", ""]
    if len(results) > 1:
        head += ["| descriptor | verdict | audit | comprehension | danger findings |",
                 "|---|---|---|---|---|"]
        for r in results:
            if "error" in r:
                head.append(f"| {r['descriptor']} | error | - | - | - |")
            else:
                head.append(
                    f"| {r['descriptor']} | {r['verdict']['gate']} "
                    f"| {r['audit']['grade']} "
                    f"| {r['comprehension']['comprehension_grade']} "
                    f"| {len(r['danger'].get('danger_findings', []))} |")
        head.append("")
    body = [_md_one(r) for r in results]
    tail = [
        "---",
        "",
        "Produced by Lucent (audit + comprehension + danger + semantic verification",
        "over ERC-7730 descriptors). Reproduce any section from the repo root:",
        "",
        "```",
        "make audit DESC=<descriptor.json>",
        "make comprehend DESC=<descriptor.json>",
        "make danger DESC=<descriptor.json>",
        "make semverify DESC=<descriptor.json>   # needs ETHERSCAN_API_KEY",
        "```",
        "",
    ]
    return "\n".join(head + body + tail)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("descriptors", nargs="+")
    ap.add_argument("--tests", help="explicit test-vectors file (single descriptor only)")
    ap.add_argument("--out", help="write the markdown report here instead of stdout")
    ap.add_argument("--json", action="store_true", help="emit raw JSON, not markdown")
    ap.add_argument("--no-lint", action="store_true")
    ap.add_argument("--no-semverify", action="store_true")
    args = ap.parse_args()

    if args.tests and len(args.descriptors) > 1:
        ap.error("--tests only applies to a single descriptor")

    results = [review_descriptor(Path(p),
                                 tests=Path(args.tests) if args.tests else None,
                                 run_lint=not args.no_lint,
                                 run_semverify=not args.no_semverify)
               for p in args.descriptors]

    out = (json.dumps(results, indent=2) if args.json else markdown_report(results))
    if args.out:
        Path(args.out).write_text(out)
        print(f"wrote {args.out}")
    else:
        print(out)
    return 1 if any("error" in r or r["verdict"]["gate"] == "block" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
