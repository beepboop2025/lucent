"""Fork-replay (scripts/forkreplay.py + semverify --simulate). Can't spin a real
anvil fork in CI, so we test the parts that MUST be correct regardless of the
toolchain: the availability gate, the exact command construction (verified
against Foundry's documented CLI), receipt normalization, and — the point of
the whole feature — that a fork-produced receipt flows through the EXISTING
semverify.verify_one and catches a hidden recipient / label swap identically to
a mined one."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import forkreplay  # noqa: E402
import semverify  # noqa: E402


# ── availability gate ───────────────────────────────────────────────────────────

def test_available_requires_toolchain_and_rpc(monkeypatch):
    monkeypatch.setattr(forkreplay.shutil, "which", lambda x: "/usr/bin/" + x)
    monkeypatch.setenv("ETH_RPC_URL", "https://rpc.example")
    assert forkreplay.available() is True
    monkeypatch.delenv("ETH_RPC_URL", raising=False)
    monkeypatch.delenv("LUCENT_RPC_URL", raising=False)
    assert forkreplay.available() is False  # no RPC -> unavailable
    monkeypatch.setattr(forkreplay.shutil, "which", lambda x: None)
    monkeypatch.setenv("ETH_RPC_URL", "https://rpc.example")
    assert forkreplay.available() is False  # no anvil/cast -> unavailable


def test_simulate_refuses_when_unavailable(monkeypatch):
    monkeypatch.setattr(forkreplay, "available", lambda *_: False)
    try:
        forkreplay.simulate("0xC0", "0x51", "transfer(address,uint256)", ["0xAb", "1"])
        assert False, "should have raised"
    except forkreplay.ForkReplayUnavailable as e:
        assert "foundryup" in str(e)


# ── command construction: verified against the documented Foundry CLI ───────────

def test_anvil_argv_forks_and_pins_block():
    argv = forkreplay.anvil_argv("https://rpc.example", 8600, 21_000_000)
    assert argv[:2] == ["anvil", "--fork-url"]
    assert "--fork-block-number" in argv and "21000000" in argv
    assert "8600" in argv


def test_anvil_argv_omits_block_when_none():
    assert "--fork-block-number" not in forkreplay.anvil_argv("https://r", 8600, None)


def test_send_argv_impersonates_and_passes_value():
    argv = forkreplay.send_argv("0xC0ntract", "0x51gner",
                                "transfer(address,uint256)", ["0xrecip", "5"], 10**18,
                                "http://127.0.0.1:8600")
    assert argv[:3] == ["cast", "send", "0xC0ntract"]
    assert "--unlocked" in argv and "--json" in argv
    assert "--from" in argv and "0x51gner" in argv
    assert "--value" in argv and "1000000000000000000" in argv
    assert "transfer(address,uint256)" in argv and "0xrecip" in argv


def test_impersonate_argv_uses_anvil_cheatcode():
    argv = forkreplay.impersonate_argv("0x51gner", "http://127.0.0.1:8600")
    assert "anvil_impersonateAccount" in argv and "0x51gner" in argv


# ── receipt normalization ───────────────────────────────────────────────────────

def test_normalize_receipt_lowercases_and_fills_defaults():
    raw = {"logs": [{"topics": ["0xABC", "0xDEF"], "address": "0xCa"}], "status": "0x1"}
    norm = forkreplay.normalize_receipt(raw)
    log = norm["logs"][0]
    assert log["topics"] == ["0xabc", "0xdef"]
    assert log["data"] == "0x"           # missing data defaulted, not crashed
    assert log["address"] == "0xca"


def test_normalize_receipt_handles_no_logs():
    assert forkreplay.normalize_receipt({})["logs"] == []


# ── the payoff: a fork receipt catches a label swap via the SAME verifier ───────

TRANSFER = semverify.TRANSFER


def _erc20_transfer_log(frm: str, to: str, amount: int) -> dict:
    pad = lambda a: "0x" + "0" * 24 + a[2:].lower()
    return {"topics": [TRANSFER, pad(frm), pad(to)],
            "data": hex(amount), "address": "0xToken"}


def test_fork_receipt_flows_through_verify_one_and_catches_hidden_recipient():
    # Descriptor claims a transfer to {to} and shows it as addressName, but the
    # fork receipt shows the asset actually went to a DIFFERENT address.
    real_recipient = "0x000000000000000000000000000000000000dead"
    shown = "0x0000000000000000000000000000000000001234"
    desc = {
        "context": {"contract": {"abi": [
            {"type": "function", "name": "transfer", "stateMutability": "nonpayable",
             "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}]}
        ]}},
        "display": {"formats": {"transfer(address,uint256)": {"fields": [
            {"label": "To", "format": "addressName", "path": "#.to", "visible": "always"}
        ]}}},
    }
    # calldata: transfer(shown, 5) — the screen will show `shown` as recipient
    import common
    from eth_abi import encode as abi_encode
    calldata = common.selector("transfer(address,uint256)") + \
        abi_encode(["address", "uint256"], [shown, 5]).hex()
    tx = {"input": calldata, "value": "0x0", "to": "0xtoken"}
    receipt = forkreplay.normalize_receipt(
        {"logs": [_erc20_transfer_log("0x00000000000000000000000000000000000000ff",
                                      real_recipient, 5)]})
    sig, moves, findings = semverify.verify_one(desc, "0xToken", tx, receipt)
    # the asset went to real_recipient, which the screen does not show -> flagged
    assert any(sev == "HIGH" and "not shown" in msg for sev, msg in findings) or \
        any("recipient" in msg for _, msg in findings)


def test_evaluate_simulate_skips_gracefully_when_forkreplay_unavailable(tmp_path, monkeypatch):
    """A --simulate run on a box without anvil must SKIP the call vector with a
    reason, never crash and never silently pass."""
    monkeypatch.setattr(forkreplay, "available", lambda *_: False)
    desc = {"context": {"contract": {"abi": [], "deployments": [{"address": "0xC0", "chainId": 1}]}},
            "display": {"formats": {}}}
    (tmp_path / "d.json").write_text(__import__("json").dumps(desc))
    (tmp_path / "t.json").write_text(__import__("json").dumps(
        {"tests": [{"call": {"signer": "0x51", "function": "foo()"}}]}))
    r = semverify.evaluate(str(tmp_path / "d.json"), str(tmp_path / "t.json"), simulate=True)
    assert r["total"] == 0
    assert r["skipped"] and "foo()" in r["skipped"][0]["call"]
