"""Comprehension-risk layer (scripts/comprehend.py): does each signable
function get the right consequence sentence, the right tier, and a REASON?
Runs against synthetic ABIs plus the real shipped ENS descriptors."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import comprehend  # noqa: E402


def _fn(name, inputs, mutability="nonpayable"):
    return {"type": "function", "name": name, "stateMutability": mutability,
            "inputs": inputs}


def _in(name, typ):
    return {"name": name, "type": typ}


def _classify(fn, fmt=None):
    return comprehend.classify(fn, fmt)


# ── the high-consequence patterns the paper says users miss ─────────────────────

def test_set_approval_for_all_is_critical_operator_grant():
    c = _classify(_fn("setApprovalForAll",
                      [_in("operator", "address"), _in("approved", "bool")]))
    assert c["tier"] == "CRITICAL"
    assert "ANY of your tokens" in c["sentence"]
    assert "revoke" in c["reason"]


def test_erc20_approve_is_high_with_allowance_reason():
    c = _classify(_fn("approve", [_in("spender", "address"), _in("amount", "uint256")]))
    assert c["tier"] == "HIGH"
    assert "spend up to" in c["sentence"]
    assert "allowance" in c["reason"] or "UNLIMITED" in c["reason"]


def test_erc721_approve_is_disambiguated_from_allowance():
    """approve(address,uint256) means different things for NFTs vs tokens; the
    tokenId name must switch the sentence to single-NFT language."""
    c = _classify(_fn("approve", [_in("to", "address"), _in("tokenId", "uint256")]))
    assert c["tier"] == "HIGH"
    assert "NFT" in c["sentence"] and "id" in c["sentence"]
    assert "spend up to" not in c["sentence"]  # not ERC-20 allowance phrasing


def test_transfer_ownership_is_critical_admin():
    c = _classify(_fn("transferOwnership", [_in("newOwner", "address")]))
    assert c["tier"] == "CRITICAL"
    assert "control" in c["reason"]


def test_upgrade_is_critical_admin_even_over_transfer_match():
    c = _classify(_fn("upgrade", [_in("newImpl", "address")]))
    assert c["tier"] == "CRITICAL"


def test_permit_is_high_offchain_reason():
    c = _classify(_fn("permit",
                      [_in("owner", "address"), _in("spender", "address"),
                       _in("value", "uint256")]))
    assert c["tier"] == "HIGH"
    assert "off-chain" in c["reason"].lower()


def test_safe_transfer_from_is_caught_as_transfer():
    """A name that CONTAINS 'transfer' but does not start with it must still
    be classified as value/asset movement, not fall through to the default."""
    c = _classify(_fn("safeTransferFrom",
                      [_in("from", "address"), _in("to", "address"),
                       _in("tokenId", "uint256")]))
    assert c["tier"] in ("MEDIUM", "HIGH")
    assert "send" in c["sentence"].lower()


# ── recipient readability (address poisoning surface) ───────────────────────────

def test_raw_hex_recipient_escalates_transfer_to_high():
    fn = _fn("transfer", [_in("to", "address"), _in("amount", "uint256")])
    raw_fmt = {"fields": [{"path": "#.to", "format": "raw", "visible": "always"}]}
    named_fmt = {"fields": [{"path": "#.to", "format": "addressName", "visible": "always"}]}
    assert _classify(fn, raw_fmt)["tier"] == "HIGH"
    assert "RAW HEX" in _classify(fn, raw_fmt)["reason"]
    assert _classify(fn, named_fmt)["tier"] == "MEDIUM"


# ── the conservative default: never wave an unexplained screen through ──────────

def test_unknown_function_without_intent_is_flagged_not_cleared():
    c = _classify(_fn("frobnicate", [_in("x", "uint256")]), fmt=None)
    assert c["tier"] == "HIGH"
    assert "unexplained" in c["reason"] or "unclassified" in c["reason"]


def test_unknown_function_with_untrusted_intent_still_requires_review():
    c = _classify(_fn("frobnicate", [_in("x", "uint256")]),
                  fmt={"intent": "Do the thing"})
    assert c["tier"] == "HIGH"
    assert c["sentence"] == "You call frobnicate; Lucent has not classified its consequence."
    assert "Do the thing" not in c["sentence"]


# ── aggregate + real descriptors ────────────────────────────────────────────────

def test_grade_orders_functions_worst_first():
    abi = [
        _fn("setApprovalForAll", [_in("op", "address"), _in("ok", "bool")]),
        _fn("balanceOf", [_in("o", "address")], "view"),  # excluded (view)
        _fn("doThing", [_in("x", "uint256")]),
    ]
    r = comprehend.comprehend({"context": {"contract": {"abi": abi}}, "display": {}})
    assert r["functions"][0]["tier"] == "CRITICAL"
    assert r["worst_tier"] == "CRITICAL"
    # the view function must not appear among signable functions
    assert all(f["function"] != "balanceOf" for f in r["functions"])


@pytest.mark.parametrize("path", sorted((ROOT / "registry" / "ens").glob("*.json")))
def test_real_ens_descriptors_every_function_has_sentence_and_reason(path):
    desc = json.loads(path.read_text())
    r = comprehend.comprehend(desc)
    assert r["functions"], f"{path.name}: no signable functions classified"
    for f in r["functions"]:
        assert f["sentence"].strip(), f"{f['function']}: empty sentence"
        assert f["reason"].strip(), f"{f['function']}: empty reason"
        assert f["tier"] in comprehend.TIER_ORDER


def test_namewrapper_flags_operator_grant_as_critical():
    """The known dangerous surface in the shipped bundle: setApprovalForAll on
    NameWrapper must land CRITICAL with the operator-grant explanation."""
    desc = json.loads((ROOT / "registry" / "ens" / "calldata-NameWrapper.json").read_text())
    r = comprehend.comprehend(desc)
    sfa = next(f for f in r["functions"] if f["function"] == "setApprovalForAll")
    assert sfa["tier"] == "CRITICAL"
    assert "ANY of your tokens" in sfa["sentence"]
