"""Danger-surface scan (scripts/danger.py): the structural 'loaded gun'
primitives must be caught, and the benign look-alikes (receiver hooks,
recipient transfers, name/proof blobs) must NOT false-positive — a danger
scan that cries wolf on safeTransferFrom is worse than none."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import danger  # noqa: E402


def _fn(name, inputs, mut="nonpayable"):
    return {"type": "function", "name": name, "stateMutability": mut, "inputs": inputs}


def _in(n, t):
    return {"name": n, "type": t}


def _prims(fn):
    return {f["primitive"] for f in danger.assess(fn)}


# ── real primitives are caught ──────────────────────────────────────────────────

def test_execute_target_data_is_arbitrary_call():
    assert "arbitrary-external-call" in _prims(
        _fn("execute", [_in("target", "address"), _in("data", "bytes")]))


def test_call_family_name_alone_is_enough():
    # a call-family name is dangerous even without the exact (target,data) shape
    assert "arbitrary-external-call" in _prims(_fn("multicall", [_in("data", "bytes[]")]))
    assert "arbitrary-external-call" in _prims(_fn("forward", [_in("x", "bytes")]))


def test_delegatecall_flagged_distinctly():
    p = _prims(_fn("delegateExecute", [_in("impl", "address"), _in("data", "bytes")]))
    assert "arbitrary-external-call" in p and "delegatecall" in p


def test_selfdestruct_is_critical():
    assert "self-destruct" in _prims(_fn("kill", []))
    assert "self-destruct" in _prims(_fn("selfDestruct", [_in("to", "address")]))


def test_upgrade_and_call_is_critical():
    assert "upgrade-and-execute" in _prims(
        _fn("upgradeToAndCall", [_in("impl", "address"), _in("data", "bytes")], "payable"))


def test_set_approval_for_all_is_unbounded_delegation():
    assert "unbounded-delegation" in _prims(
        _fn("setApprovalForAll", [_in("op", "address"), _in("ok", "bool")]))


def test_authority_transfer_flagged():
    assert "authority-transfer" in _prims(_fn("transferOwnership", [_in("o", "address")]))
    assert "authority-transfer" in _prims(_fn("grantRole", [_in("r", "bytes32"), _in("a", "address")]))


def test_value_sweep_flagged():
    assert "value-sweep-to-arbitrary-address" in _prims(
        _fn("withdrawTo", [_in("to", "address"), _in("amt", "uint256")]))


# ── benign look-alikes must NOT fire (the false-positive guard) ─────────────────

def test_receiver_hooks_are_clean():
    assert _prims(_fn("safeTransferFrom",
                      [_in("from", "address"), _in("to", "address"),
                       _in("id", "uint256"), _in("data", "bytes")])) == set()
    assert _prims(_fn("onERC721Received",
                      [_in("operator", "address"), _in("from", "address"),
                       _in("tokenId", "uint256"), _in("data", "bytes")])) == set()


def test_plain_transfer_is_clean():
    assert _prims(_fn("transfer", [_in("to", "address"), _in("amount", "uint256")])) == set()


def test_name_or_proof_bytes_is_clean():
    # bytes as a DNS name / merkle proof, not calldata, must not flag
    assert _prims(_fn("wrap", [_in("name", "bytes"), _in("owner", "address")])) == set()
    assert _prims(_fn("claim", [_in("proof", "bytes"), _in("amount", "uint256")])) == set()


def test_renew_does_not_match_run_substring():
    # word-boundary matching: 'renew' must not be read as a call-family name
    assert "arbitrary-external-call" not in _prims(_fn("renew", [_in("name", "string")]))


# ── aggregate + real descriptors ────────────────────────────────────────────────

def test_scan_counts_and_worst_severity():
    abi = [_fn("execute", [_in("target", "address"), _in("data", "bytes")]),
           _fn("transfer", [_in("to", "address"), _in("v", "uint256")])]
    r = danger.scan({"context": {"contract": {"abi": abi}}, "display": {}})
    assert r["critical"] == 1
    assert r["worst_severity"] == "CRITICAL"


@pytest.mark.parametrize("path", sorted((ROOT / "registry" / "ens").glob("*.json")))
def test_real_ens_descriptors_have_no_arbitrary_call_false_positives(path):
    """None of the shipped ENS functions is an arbitrary-call primitive; the
    scan must not invent one (it may still flag authority/delegation, which are
    real)."""
    r = danger.scan(json.loads(path.read_text()))
    arb = [f for f in r["danger_findings"] if f["primitive"] == "arbitrary-external-call"]
    assert not arb, f"{path.name}: false arbitrary-call flags on {[f['function'] for f in arb]}"
