"""Exercise the real line-delimited stdio boundary, not only dispatch()."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "scripts" / "mcp_server.py"


def _run(raw: bytes) -> list[dict]:
    completed = subprocess.run(
        [sys.executable, str(SERVER)],
        input=raw,
        cwd=ROOT,
        capture_output=True,
        timeout=5,
        check=True,
    )
    assert completed.stderr == b""
    return [json.loads(line) for line in completed.stdout.splitlines()]


def _line(payload) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode() + b"\n"


def test_malformed_json_gets_parse_error_and_server_continues():
    output = _run(
        b"{not json}\n"
        + _line({"jsonrpc": "2.0", "id": "after", "method": "tools/list"})
    )
    assert output[0]["error"]["code"] == -32700
    assert output[1]["id"] == "after"


def test_deeply_nested_json_gets_parse_error_and_server_continues():
    deeply_nested = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","extra":'
        + b"[" * 20_000
        + b"0"
        + b"]" * 20_000
        + b"}\n"
    )
    output = _run(
        deeply_nested
        + _line({"jsonrpc": "2.0", "id": "after-depth", "method": "tools/list"})
    )
    assert output[0]["error"]["code"] == -32700
    assert output[1]["id"] == "after-depth"


def test_pathological_json_integer_gets_parse_error_and_server_continues():
    huge_integer = (
        b'{"jsonrpc":"2.0","id":'
        + b"9" * 10_000
        + b',"method":"tools/list"}\n'
    )
    output = _run(
        huge_integer
        + _line({"jsonrpc": "2.0", "id": "after-integer", "method": "tools/list"})
    )
    assert output[0]["error"]["code"] == -32700
    assert output[1]["id"] == "after-integer"


def test_array_and_wrong_protocol_version_are_invalid_requests():
    output = _run(
        _line([])
        + _line({"jsonrpc": "1.0", "id": 2, "method": "tools/list"})
    )
    assert [item["error"]["code"] for item in output] == [-32600, -32600]


def test_notification_produces_no_response():
    output = _run(_line({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "check_descriptor", "arguments": {}},
    }))
    assert output == []


def test_unknown_method_preserves_string_request_id():
    output = _run(_line({"jsonrpc": "2.0", "id": "req-7", "method": "nope"}))
    assert output == [{
        "jsonrpc": "2.0",
        "id": "req-7",
        "error": {"code": -32601, "message": "unknown method 'nope'"},
    }]


def test_oversized_line_is_rejected_and_server_recovers():
    oversized = b'"' + b"x" * (1024 * 1024 + 10) + b'"\n'
    output = _run(
        oversized
        + _line({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    )
    assert output[0]["error"]["code"] == -32600
    assert "size limit" in output[0]["error"]["message"]
    assert output[1]["id"] == 3
