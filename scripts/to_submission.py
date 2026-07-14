#!/usr/bin/env python3
"""Emit the registry-PR form of a descriptor.

Our working descriptor keeps the ABI inline and an absolute $schema URL so the
offline tooling (resolve/preview) works without a network. The registry PR form
follows the repo's convention instead:

  * $schema is the repo-relative path ../../specs/erc7730-v2.schema.json
  * the ABI is NOT inlined — the registry CI fetches it from the explorer and
    validates the descriptor against it (proving the contract is verified)

This produces a drop-in file + its tests under dist/registry-pr/<entity>/, ready
to copy into a fork of ethereum/clear-signing-erc7730-registry.

Usage: python scripts/to_submission.py <entity> <descriptor.json>
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REL_SCHEMA = "../../specs/erc7730-v2.schema.json"


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    entity, desc_path = sys.argv[1], Path(sys.argv[2])
    desc = json.loads(desc_path.read_text())

    desc["$schema"] = REL_SCHEMA
    # Registry convention: reference the ABI via deployments, don't inline it.
    desc["context"]["contract"].pop("abi", None)

    out_dir = ROOT / "dist" / "registry-pr" / entity
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / desc_path.name
    out_file.write_text(json.dumps(desc, indent=2) + "\n")

    # Carry the tests across unchanged (already in registry form).
    tests_src = desc_path.parent / "tests" / (desc_path.stem + ".tests.json")
    if tests_src.exists():
        (out_dir / "tests").mkdir(exist_ok=True)
        shutil.copy(tests_src, out_dir / "tests" / tests_src.name)

    print(f"submission form -> {out_file.relative_to(ROOT)}")
    print(f"  $schema      : {REL_SCHEMA}")
    print(f"  inline ABI   : removed ({len(desc['context']['contract'].get('deployments', []))} deployment(s) referenced)")
    if tests_src.exists():
        print(f"  tests        : copied ({tests_src.name})")
    print("\nDrop dist/registry-pr/<entity>/ into a fork's registry/<entity>/ and open a PR.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
