"""Lucent MCP server: the JSON-RPC surface and the safety-gate logic. Drives
dispatch() directly (no subprocess) plus the three tools against the real ENS
descriptors and synthetic ABIs."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import mcp_server as mcp  # noqa: E402


def _call(name, arguments):
    resp = mcp.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": name, "arguments": arguments}})
    return json.loads(resp["result"]["content"][0]["text"]), resp["result"].get("isError", False)


def _desc(name):
    return json.loads((ROOT / "registry" / "ens" / f"{name}.json").read_text())


# ── protocol surface ────────────────────────────────────────────────────────────

def test_initialize_announces_server():
    r = mcp.dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert r["result"]["serverInfo"]["name"] == "lucent"
    assert "block on CRITICAL" in r["result"]["instructions"]


def test_tools_list_has_the_three_tools():
    r = mcp.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    names = {t["name"] for t in r["result"]["tools"]}
    assert names == {"check_descriptor", "explain_signature", "scan_contract"}


def test_notifications_have_no_response():
    assert mcp.dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_unknown_tool_is_an_error():
    r = mcp.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "nope", "arguments": {}}})
    assert "error" in r


# ── check_descriptor: the gate ──────────────────────────────────────────────────

def test_check_descriptor_reviews_operator_grant():
    """NameWrapper has setApprovalForAll (CRITICAL comprehension) but no CRITICAL
    danger primitive -> review, not block."""
    out, err = _call("check_descriptor", {"descriptor": _desc("calldata-NameWrapper")})
    assert not err
    assert out["verdict"]["gate"] == "review"
    assert out["comprehension"]["worst_tier"] == "CRITICAL"


def test_check_descriptor_blocks_arbitrary_call():
    """A descriptor over a contract with execute(target,data) must BLOCK, no
    matter how clean the screen."""
    desc = {"context": {"contract": {"abi": [
        {"type": "function", "name": "execute", "stateMutability": "payable",
         "inputs": [{"name": "target", "type": "address"}, {"name": "data", "type": "bytes"}]}
    ]}}, "display": {"formats": {}}}
    out, _ = _call("check_descriptor", {"descriptor": desc})
    assert out["verdict"]["gate"] == "block"
    assert out["danger"]["critical"] >= 1


def test_check_descriptor_passes_a_clean_descriptor():
    out, _ = _call("check_descriptor", {"descriptor": _desc("calldata-BulkRenewal")})
    assert out["verdict"]["gate"] in ("safe_to_present", "review")
    assert out["danger"]["critical"] == 0


# ── explain_signature ───────────────────────────────────────────────────────────

def test_explain_signature_returns_sentence_and_tier():
    out, _ = _call("explain_signature",
                   {"descriptor": _desc("calldata-NameWrapper"), "function": "setApprovalForAll"})
    assert out["found"]
    assert out["tier"] == "CRITICAL"
    assert "ANY of your tokens" in out["sentence"]
    assert out["reason"]


def test_explain_signature_unknown_function_lists_available():
    out, _ = _call("explain_signature",
                   {"descriptor": _desc("calldata-NameWrapper"), "function": "doesNotExist"})
    assert out["found"] is False
    assert "setApprovalForAll" in out["available"]


# ── scan_contract (ABI fetch mocked; no network in CI) ──────────────────────────

def test_scan_contract_flags_dangerous_abi(monkeypatch):
    abi = [{"type": "function", "name": "delegateExec", "stateMutability": "nonpayable",
            "inputs": [{"name": "impl", "type": "address"}, {"name": "data", "type": "bytes"}]}]
    monkeypatch.setattr(mcp.common, "sourcify_abi", lambda c, a: abi)
    out, _ = _call("scan_contract", {"chain_id": 1, "address": "0xabc"})
    assert out["matched"] is True
    prims = {f["primitive"] for f in out["danger_findings"]}
    assert "delegatecall" in prims


def test_scan_contract_honest_when_no_abi(monkeypatch):
    monkeypatch.setattr(mcp.common, "sourcify_abi", lambda c, a: None)
    out, _ = _call("scan_contract", {"chain_id": 1, "address": "0xabc"})
    assert out["matched"] is False and "no verified ABI" in out["reason"]


def test_scan_contract_reports_fetch_failure(monkeypatch):
    def boom(c, a):
        raise RuntimeError("sourcify down")
    monkeypatch.setattr(mcp.common, "sourcify_abi", boom)
    out, _ = _call("scan_contract", {"chain_id": 1, "address": "0xabc"})
    assert out["matched"] is False and "sourcify down" in out["reason"]


# ── missing-argument handling ────────────────────────────────────────────────────

def test_missing_argument_is_reported_not_crashed():
    out, err = _call("check_descriptor", {})  # no descriptor
    assert err and "missing required argument" in out["error"]
