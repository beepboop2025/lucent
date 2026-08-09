"""Shared source and cache boundaries reject path and resource abuse."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import common  # noqa: E402


def test_deployment_address_cannot_escape_abi_cache():
    descriptor = {
        "context": {"contract": {"deployments": [
            {"chainId": 1, "address": "../../private-key"}
        ]}}
    }
    with pytest.raises(ValueError, match="40 hexadecimal"):
        common.descriptor_abi(descriptor)


def test_chain_id_is_bounded_and_bool_is_not_an_integer():
    for value in (
        True,
        0,
        -1,
        common.MAX_CHAIN_ID + 1,
        "not-a-chain",
        "1",
        "+1",
        " 1 ",
        1.0,
        1.9,
    ):
        with pytest.raises(ValueError, match="chain id"):
            common.normalize_chain_id(value)


def test_abi_entry_and_encoded_size_limits():
    with pytest.raises(ValueError, match="entries"):
        common.validate_abi([{}] * (common.MAX_ABI_ENTRIES + 1))
    with pytest.raises(ValueError, match="encoded size"):
        common.validate_abi([{"type": "function", "name": "x" * common.MAX_REMOTE_BYTES}])


@pytest.mark.parametrize(
    "function",
    [
        {"type": "function", "name": [], "inputs": []},
        {"type": "function", "name": "f", "inputs": "bad"},
        {"type": "function", "name": "f", "inputs": [{"name": "x", "type": 123}]},
        {"type": "function", "name": "f", "inputs": [{"name": "x", "type": "uint257"}]},
        {"type": "function", "name": "f", "inputs": [{"name": "x", "type": "uint"}]},
        {
            "type": "function",
            "name": "f",
            "inputs": [],
            "stateMutability": "nonpayable",
            "payable": True,
        },
    ],
)
def test_malformed_function_abi_is_rejected_before_analysis(function):
    with pytest.raises(ValueError, match="ABI|inputs|input"):
        common.validate_abi([function])


class _Headers:
    def __init__(self, media_type="application/json", length=None):
        self.media_type = media_type
        self.length = length

    def get_content_type(self):
        return self.media_type

    def get(self, key):
        return self.length if key == "Content-Length" else None


class _Response:
    def __init__(self, body, *, media_type="application/json", length=None):
        self.body = body
        self.headers = _Headers(media_type, length)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, limit):
        return self.body[:limit]


def test_remote_json_rejects_wrong_content_type(monkeypatch):
    monkeypatch.setattr(
        common.JSON_OPENER,
        "open",
        lambda *_args, **_kwargs: _Response(b"{}", media_type="text/html"),
    )
    with pytest.raises(ValueError, match="not JSON"):
        common._get_json("https://fixed.example/data")


def test_remote_json_rejects_declared_and_streamed_oversize(monkeypatch):
    monkeypatch.setattr(
        common.JSON_OPENER,
        "open",
        lambda *_args, **_kwargs: _Response(
            b"{}", length=str(common.MAX_REMOTE_BYTES + 1)
        ),
    )
    with pytest.raises(ValueError, match="size limit"):
        common._get_json("https://fixed.example/data")

    monkeypatch.setattr(
        common.JSON_OPENER,
        "open",
        lambda *_args, **_kwargs: _Response(b"x" * (common.MAX_REMOTE_BYTES + 1)),
    )
    with pytest.raises(ValueError, match="size limit"):
        common._get_json("https://fixed.example/data")


def test_remote_json_accepts_bounded_json(monkeypatch):
    body = json.dumps({"abi": []}).encode()
    monkeypatch.setattr(
        common.JSON_OPENER,
        "open",
        lambda *_args, **_kwargs: _Response(body, length=str(len(body))),
    )
    assert common._get_json("https://fixed.example/data") == {"abi": []}
