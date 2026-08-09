"""Review composer (scripts/review.py): one command in, a publishable verdict
out. The gate must match the MCP server's agent gate exactly, and anything the
checks cannot run must surface as an explicit skip or error, never a pass."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import review  # noqa: E402


def _write(tmp_path, name, desc):
    p = tmp_path / name
    p.write_text(json.dumps(desc))
    return p


def _desc(abi, formats):
    return {
        "context": {"contract": {
            "abi": abi,
            "deployments": [{"chainId": 1, "address": "0x" + "11" * 20}],
        }},
        "metadata": {},
        "display": {"formats": formats},
    }


BENIGN = _desc(
    [{"type": "function", "name": "transfer", "stateMutability": "nonpayable",
      "inputs": [{"name": "to", "type": "address"},
                 {"name": "amount", "type": "uint256"}]}],
    {"transfer(address,uint256)": {
        "intent": "Send tokens",
        "fields": [{"path": "#.to", "label": "To", "format": "addressName"},
                   {"path": "#.amount", "label": "Amount", "format": "amount"}]}},
)

ARBITRARY_CALL = _desc(
    [{"type": "function", "name": "execute", "stateMutability": "payable",
      "inputs": [{"name": "target", "type": "address"},
                 {"name": "data", "type": "bytes"}]}],
    {},
)

OPERATOR_GRANT = _desc(
    [{"type": "function", "name": "setApprovalForAll",
      "stateMutability": "nonpayable",
      "inputs": [{"name": "operator", "type": "address"},
                 {"name": "approved", "type": "bool"}]}],
    {"setApprovalForAll(address,bool)": {
        "intent": "Set operator",
        "fields": [{"path": "#.operator", "label": "Operator",
                    "format": "addressName"},
                   {"path": "#.approved", "label": "Approved",
                    "format": "raw"}]}},
)


def _review(tmp_path, desc, name="d.json"):
    return review.review_descriptor(_write(tmp_path, name, desc),
                                    run_lint=False, run_semverify=False)


def test_benign_descriptor_is_safe_to_present(tmp_path):
    r = _review(tmp_path, BENIGN)
    assert r["verdict"]["gate"] == "safe_to_present"
    assert r["audit"]["grade"] == "A"


def test_arbitrary_call_blocks_regardless_of_screen(tmp_path):
    r = _review(tmp_path, ARBITRARY_CALL)
    assert r["verdict"]["gate"] == "block"
    assert r["danger"]["critical"] >= 1


def test_operator_grant_gates_review(tmp_path):
    r = _review(tmp_path, OPERATOR_GRANT)
    assert r["verdict"]["gate"] == "review"
    assert r["comprehension"]["worst_tier"] == "CRITICAL"


def test_unresolvable_abi_is_an_error_not_a_pass(tmp_path):
    broken = {"context": {"contract": {"deployments": [
        {"chainId": 999, "address": "0x" + "22" * 20}]}},
        "display": {"formats": {}}}
    r = _review(tmp_path, broken)
    assert "error" in r
    assert "ABI" in r["error"]


def test_skips_are_explicit_in_markdown(tmp_path):
    r = _review(tmp_path, BENIGN)
    md = review.markdown_report([r])
    assert "skipped: --no-lint" not in md  # lint section prints its status field
    assert r["lint"]["status"] == "skipped"
    assert r["semverify"]["status"] == "skipped"
    assert "Semantic verification" in md
    assert "--no-semverify" in md


def test_markdown_summary_table_for_multiple(tmp_path):
    rs = [_review(tmp_path, BENIGN, "a.json"),
          _review(tmp_path, ARBITRARY_CALL, "b.json")]
    md = review.markdown_report(rs)
    assert "| descriptor | verdict |" in md
    assert "| a | safe_to_present " in md
    assert "| b | block " in md
    assert "Reproduce" in md or "make audit" in md


def test_danger_findings_render_in_markdown(tmp_path):
    r = _review(tmp_path, ARBITRARY_CALL)
    md = review.markdown_report([r])
    assert "Verdict: block" in md
    assert "arbitrary-external-call" in md
    assert "no dangerous primitives" not in md.split("## ")[1]


def test_report_never_leaks_local_paths(tmp_path):
    """Reports are posted publicly; a local absolute path in one leaks
    environment and identity details. Every code path that embeds a path or
    an error message must reduce it to a basename or relative form."""
    broken = {"context": {"contract": {"deployments": [
        {"chainId": 999, "address": "0x" + "22" * 20}]}},
        "display": {"formats": {}}}
    rs = [_review(tmp_path, BENIGN, "a.json"),
          _review(tmp_path, broken, "b.json"),
          review.review_descriptor(_write(tmp_path, "c.json", BENIGN),
                                   run_lint=False, run_semverify=True)]
    md = review.markdown_report(rs)
    assert str(tmp_path) not in md
    assert "/private/" not in md and "/Users/" not in md and "/home/" not in md


def test_gate_matches_mcp_server(tmp_path):
    import mcp_server
    for desc in (BENIGN, ARBITRARY_CALL, OPERATOR_GRANT):
        via_review = _review(tmp_path, desc)["verdict"]["gate"]
        via_mcp = mcp_server.check_descriptor({"descriptor": desc})["verdict"]["gate"]
        assert via_review == via_mcp
