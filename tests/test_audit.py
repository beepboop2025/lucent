"""Screen-audit layer (scripts/audit.py): the checks that decide whether a
descriptor's on-device screen can be trusted, including the non-canonical
format-key failure (entries that exist but never render) found in the wild on
registry PRs."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import audit  # noqa: E402


def _fn(name, inputs, mutability="nonpayable"):
    return {"type": "function", "name": name, "stateMutability": mutability,
            "inputs": inputs}


def _in(name, typ):
    return {"name": name, "type": typ}


def _desc(abi, formats):
    return {"context": {"contract": {"abi": abi}},
            "display": {"formats": formats}}


TRANSFER = _fn("transfer", [_in("to", "address"), _in("amount", "uint256")])
GOOD_ENTRY = {"intent": "Send tokens",
              "interpolatedIntent": "Send {Amount} to {To}",
              "fields": [{"path": "#.to", "label": "To", "format": "addressName"},
                         {"path": "#.amount", "label": "Amount", "format": "amount"}]}


# -- canonicalization ---------------------------------------------------------

def test_canonical_key_strips_parameter_names():
    assert audit._canonical_key("transfer(address to, uint256 amount)") \
        == "transfer(address,uint256)"


def test_canonical_key_leaves_canonical_untouched():
    assert audit._canonical_key("transfer(address,uint256)") \
        == "transfer(address,uint256)"


def test_canonical_key_handles_tuples_and_arrays():
    assert audit._canonical_key("swap((address a,uint256 b) params, bytes[] path)") \
        == "swap((address,uint256),bytes[])"
    assert audit._canonical_key("renewAll()") == "renewAll()"


# -- the findings -------------------------------------------------------------

def test_noncanonical_key_is_flagged_not_reported_missing():
    r = audit.audit(_desc([TRANSFER],
                          {"transfer(address to, uint256 amount)": GOOD_ENTRY}))
    issues = [f["issue"] for f in r["findings"]]
    assert any("non-canonically" in i for i in issues)
    assert not any(i.startswith("signable function has no descriptor entry")
                   for i in issues)


def test_canonical_key_still_audits_clean():
    r = audit.audit(_desc([TRANSFER], {"transfer(address,uint256)": GOOD_ENTRY}))
    assert r["grade"] == "A"
    assert r["findings"] == []


def test_orphan_entry_is_low_severity():
    r = audit.audit(_desc([TRANSFER],
                          {"transfer(address,uint256)": GOOD_ENTRY,
                           "bogus(uint8)": {"intent": "??", "fields": []}}))
    orphans = [f for f in r["findings"] if "orphan" in f["issue"]]
    assert len(orphans) == 1 and orphans[0]["severity"] == "LOW"


def test_shipped_ens_descriptors_still_grade_a():
    for name in ("calldata-ETHRegistrarController", "calldata-NameWrapper",
                 "calldata-BulkRenewal"):
        desc = json.loads((ROOT / "registry" / "ens" / f"{name}.json").read_text())
        assert audit.audit(desc)["grade"] == "A", name
