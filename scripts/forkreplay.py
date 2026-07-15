#!/usr/bin/env python3
"""Fork-replay an UNMINED call and hand the result to the existing verifier.

`semverify.py` proves a descriptor's screen is faithful — but only against a
MINED transaction, because it reads the real receipt. That leaves a gap the
README calls out: a brand-new descriptor for a call that has never been mined
(a fresh contract, a rarely-used function) has no receipt to check against.

This closes it. Given a call spec {contract, signer, function, args, value},
fork-replay:
  1. forks mainnet at HEAD (or a pinned block) into a local `anvil`,
  2. impersonates the signer and executes the call on the fork,
  3. reads back the standard eth receipt (real logs — Transfer, ApprovalForAll,
     ERC-1155 TransferSingle — because the call ran against real on-chain state),
  4. hands the (tx, receipt) pair to `semverify.verify_one` UNCHANGED.

The design point: the fork produces the SAME shapes semverify already consumes
from a mined receipt, so every movement/label check is the identical, tested
code path — fork-replay adds no new verification logic, only a new SOURCE of the
receipt. A label-swap or a hidden recipient is caught on an unmined call exactly
as it is on a mined one.

Honest degradation, as everywhere in the pipeline: without `anvil` + `cast` on
PATH and an RPC URL (ETH_RPC_URL or --rpc-url), `available()` is False and the
caller reports "fork-replay unavailable" rather than pretending. Enable with
`foundryup` and an archive/full RPC endpoint.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from contextlib import contextmanager


class ForkReplayUnavailable(RuntimeError):
    """Raised when the toolchain or RPC needed for a fork is not configured."""


def rpc_url(explicit: str | None = None) -> str | None:
    return explicit or os.environ.get("ETH_RPC_URL") or os.environ.get("LUCENT_RPC_URL")


def available(explicit_rpc: str | None = None) -> bool:
    """True iff anvil + cast are installed and an RPC endpoint is configured."""
    return bool(shutil.which("anvil") and shutil.which("cast") and rpc_url(explicit_rpc))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ── command construction (unit-tested without executing) ────────────────────────

def anvil_argv(fork_rpc: str, port: int, block: int | None) -> list[str]:
    argv = ["anvil", "--fork-url", fork_rpc, "--port", str(port),
            "--host", "127.0.0.1", "--silent"]
    if block is not None:
        argv += ["--fork-block-number", str(block)]
    return argv


def impersonate_argv(signer: str, local: str) -> list[str]:
    return ["cast", "rpc", "anvil_impersonateAccount", signer, "--rpc-url", local]


def send_argv(contract: str, signer: str, sig: str, args: list[str],
              value: int, local: str) -> list[str]:
    argv = ["cast", "send", contract, "--from", signer, "--unlocked",
            "--rpc-url", local, "--json"]
    if value:
        argv += ["--value", str(value)]
    if sig:
        argv += [sig, *[str(a) for a in args]]
    return argv


def calldata_argv(sig: str, args: list[str]) -> list[str]:
    return ["cast", "calldata", sig, *[str(a) for a in args]]


# ── receipt normalization ───────────────────────────────────────────────────────

def normalize_receipt(raw: dict) -> dict:
    """Coerce a `cast send --json` receipt into the shape semverify.movements
    expects: {"logs": [{"topics": [...], "data": "0x..."}]}. cast emits the
    standard eth receipt, so this is mostly a passthrough that guarantees the
    keys exist and topics/data are hex strings."""
    logs = []
    for log in raw.get("logs", []) or []:
        logs.append({
            "topics": [t.lower() for t in log.get("topics", [])],
            "data": log.get("data", "0x") or "0x",
            "address": (log.get("address") or "").lower(),
        })
    return {"logs": logs, "status": raw.get("status")}


# ── the fork lifecycle ──────────────────────────────────────────────────────────

@contextmanager
def _anvil(fork_rpc: str, block: int | None):
    port = _free_port()
    local = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(anvil_argv(fork_rpc, port, block),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_ready(local, proc)
        yield local
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _wait_ready(local: str, proc: subprocess.Popen, timeout: float = 30.0) -> None:
    """Block until the fork answers eth_blockNumber, or fail loudly."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise ForkReplayUnavailable("anvil exited before the fork was ready")
        r = subprocess.run(["cast", "block-number", "--rpc-url", local],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return
        time.sleep(0.4)
    raise ForkReplayUnavailable("anvil fork did not become ready in time")


def _run(argv: list[str]) -> str:
    r = subprocess.run(argv, capture_output=True, text=True)
    if r.returncode != 0:
        raise ForkReplayUnavailable(f"{argv[0]} failed: {r.stderr.strip()[:200]}")
    return r.stdout.strip()


def simulate(contract: str, signer: str, sig: str, args: list[str],
             value: int = 0, explicit_rpc: str | None = None,
             block: int | None = None) -> tuple[dict, dict]:
    """Run the call on a fork and return (tx_dict, receipt_dict) shaped exactly
    as semverify.verify_one consumes them. Raises ForkReplayUnavailable if the
    toolchain/RPC is missing or the fork call fails."""
    fork_rpc = rpc_url(explicit_rpc)
    if not available(explicit_rpc):
        raise ForkReplayUnavailable(
            "fork-replay needs `anvil` + `cast` on PATH and an RPC URL "
            "(ETH_RPC_URL or --rpc-url). Install via foundryup.")
    calldata = _run(calldata_argv(sig, args)) if sig else "0x"
    with _anvil(fork_rpc, block) as local:
        _run(impersonate_argv(signer, local))
        raw = json.loads(_run(send_argv(contract, signer, sig, args, value, local)))
    tx = {"input": calldata, "value": hex(value), "to": contract.lower()}
    return tx, normalize_receipt(raw)
