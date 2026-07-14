#!/usr/bin/env python3
"""Emit the registry-PR form of a descriptor under dist/registry-pr/<entity>/.

The working descriptor keeps the ABI inline and an absolute $schema URL for
offline tooling. The registry form uses the repo-relative schema path and drops
the inline ABI (registry CI fetches and validates it from the explorer). The
audit gate refuses to package a descriptor below grade B.

    to_submission.py <entity> <descriptor.json> [--force]
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import audit
import common

REL_SCHEMA = "../../specs/erc7730-v2.schema.json"
MIN_GRADE = ("A", "B")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("entity")
    ap.add_argument("descriptor")
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    desc_path = Path(args.descriptor)
    desc = json.loads(desc_path.read_text())

    r = audit.audit(desc)
    print(f"audit: grade {r['grade']} ({r['score']}/100)")
    if r["grade"] not in MIN_GRADE and not args.force:
        print(f"  refused: grade below {MIN_GRADE[-1]} (--force to override)")
        for f in r["findings"]:
            if f["severity"] in ("CRITICAL", "HIGH"):
                print(f"    {f['severity']} [{f['function']}] {f['issue']}")
        return 1

    desc["$schema"] = REL_SCHEMA
    desc["context"]["contract"].pop("abi", None)

    out_dir = common.ROOT / "dist" / "registry-pr" / args.entity
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / desc_path.name
    out_file.write_text(json.dumps(desc, indent=2) + "\n")

    tests_src = desc_path.parent / "tests" / (desc_path.stem + ".tests.json")
    if tests_src.exists():
        (out_dir / "tests").mkdir(exist_ok=True)
        shutil.copy(tests_src, out_dir / "tests" / tests_src.name)

    print(f"packaged {common.rel(out_file)}"
          + (f" (+ {tests_src.name})" if tests_src.exists() else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
