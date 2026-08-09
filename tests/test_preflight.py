"""Call-scoped preflight policy and transaction binding."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from eth_abi import encode as abi_encode

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lucent import preflight  # noqa: E402

ADDRESS = "0x" + "11" * 20
RECIPIENT = "0x" + "22" * 20
SPENDER = "0x" + "33" * 20
SENDER = "0x" + "aa" * 20


def _function(name, inputs, *, mutability="nonpayable"):
    return {
        "type": "function",
        "name": name,
        "stateMutability": mutability,
        "inputs": [{"name": item_name, "type": item_type} for item_name, item_type in inputs],
    }


TRANSFER = _function("transfer", [("to", "address"), ("amount", "uint256")])
APPROVE = _function("approve", [("spender", "address"), ("amount", "uint256")])
EXECUTE = _function("execute", [("target", "address"), ("data", "bytes")])
DEPOSIT = _function("deposit", [], mutability="payable")

TRANSFER_FORMAT = {
    "intent": "Send tokens",
    "interpolatedIntent": "Send {amount} to {to}",
    "fields": [
        {"path": "#.to", "label": "To", "format": "addressName"},
        {"path": "#.amount", "label": "Amount", "format": "amount"},
    ],
}

APPROVE_FORMAT = {
    "intent": "Approve token spending",
    "interpolatedIntent": "Approve {spender} to spend {amount}",
    "fields": [
        {"path": "#.spender", "label": "Spender", "format": "addressName"},
        {"path": "#.amount", "label": "Amount", "format": "amount"},
    ],
}


def _descriptor(abi, formats):
    return {
        "context": {
            "contract": {
                "abi": abi,
                "deployments": [{"chainId": 1, "address": ADDRESS}],
            }
        },
        "display": {"formats": formats},
    }


def _calldata(function, values=()):
    signature = preflight.common.signature(function)
    types = [preflight.common.canonical_type(item) for item in function["inputs"]]
    encoded = abi_encode(types, list(values)) if types else b""
    return preflight.common.selector(signature) + encoded.hex()


def _request(function, values, descriptor, *, value="0x0"):
    return {
        "transaction": {
            "chain_id": 1,
            "from": SENDER,
            "to": ADDRESS,
            "data": _calldata(function, values),
            "value": value,
        },
        "descriptor": descriptor,
    }


def test_clean_selected_call_is_safe_to_present():
    descriptor = _descriptor(
        [TRANSFER], {"transfer(address,uint256)": TRANSFER_FORMAT}
    )
    result = preflight.preflight_transaction(
        _request(TRANSFER, [RECIPIENT, 42], descriptor)
    )
    assert result["verdict"]["gate"] == "safe_to_present"
    assert result["call"]["function"] == "transfer(address,uint256)"
    assert result["call"]["decoded_arguments"][0]["value"].lower() == RECIPIENT
    assert result["assurance"]["runtime_simulated"] is False


def test_unrelated_dangerous_function_does_not_taint_selected_call():
    descriptor = _descriptor(
        [TRANSFER, EXECUTE],
        {"transfer(address,uint256)": TRANSFER_FORMAT},
    )
    result = preflight.preflight_transaction(
        _request(TRANSFER, [RECIPIENT, 42], descriptor)
    )
    assert result["verdict"]["gate"] == "safe_to_present"
    assert result["checks"]["danger"]["findings"] == []


def test_selected_arbitrary_call_blocks():
    descriptor = _descriptor(
        [EXECUTE],
        {"execute(address,bytes)": {
            "intent": "Execute call",
            "fields": [
                {"path": "#.target", "label": "Target", "format": "addressName"},
                {"path": "#.data", "label": "Data", "format": "raw"},
            ],
        }},
    )
    result = preflight.preflight_transaction(
        _request(EXECUTE, [RECIPIENT, b"\x12\x34"], descriptor)
    )
    assert result["verdict"]["gate"] == "block"
    assert result["verdict"]["code"] == "DANGER_CRITICAL"


def test_payable_function_hiding_value_blocks_regression():
    descriptor = _descriptor(
        [DEPOSIT], {"deposit()": {"intent": "Deposit", "fields": []}}
    )
    result = preflight.preflight_transaction(
        _request(DEPOSIT, [], descriptor, value="0x1")
    )
    assert result["checks"]["audit"]["grade"] == "C"
    assert any(
        finding["severity"] == "CRITICAL"
        for finding in result["checks"]["audit"]["findings"]
    )
    assert result["verdict"]["gate"] == "block"
    assert result["verdict"]["code"] == "PRESENTATION_CRITICAL"


def test_descriptor_wide_gate_blocks_critical_audit_regression():
    descriptor = _descriptor(
        [DEPOSIT], {"deposit()": {"intent": "Deposit", "fields": []}}
    )
    result = preflight.check_descriptor({"descriptor": descriptor})
    assert result["audit"]["grade"] == "C"
    assert result["verdict"]["gate"] == "block"


def test_missing_selected_format_blocks_without_guessing():
    descriptor = _descriptor([TRANSFER], {})
    result = preflight.preflight_transaction(
        _request(TRANSFER, [RECIPIENT, 42], descriptor)
    )
    assert result["verdict"] == {
        "gate": "block",
        "code": "MISSING_CLEAR_SIGNING_FORMAT",
        "reason": "the selected function has no exact clear-signing format",
    }


def test_hidden_recipient_is_never_safe_to_present():
    descriptor = _descriptor(
        [TRANSFER],
        {"transfer(address,uint256)": {
            "intent": "Send tokens",
            "fields": [
                {"path": "#.not_the_recipient", "label": "To", "format": "addressName"},
                {"path": "#.not_the_amount", "label": "Amount", "format": "amount"},
            ],
        }},
    )
    result = preflight.preflight_transaction(
        _request(TRANSFER, [RECIPIENT, 42], descriptor)
    )
    assert result["verdict"]["gate"] in ("review", "block")
    assert result["verdict"]["gate"] != "safe_to_present"


@pytest.mark.parametrize(
    "fields",
    [
        [{"path": "#.to", "label": "To", "format": "addressName"}],
        [
            {"path": "#.to", "label": "To", "format": "addressName"},
            {"path": "#.amount", "label": "Amount", "format": "amount", "visible": "never"},
        ],
        [{"path": "#.bogus", "label": "Amount", "format": "amount"}],
    ],
)
def test_every_signed_argument_must_resolve_and_be_visible(fields):
    descriptor = _descriptor(
        [TRANSFER],
        {"transfer(address,uint256)": {"intent": "Send tokens", "fields": fields}},
    )
    result = preflight.preflight_transaction(
        _request(TRANSFER, [RECIPIENT, 42], descriptor)
    )
    assert result["verdict"]["gate"] == "block"
    assert result["verdict"]["code"] == "PRESENTATION_UNBOUND"
    assert result["checks"]["presentation_binding"]["complete"] is False


def test_every_nested_tuple_leaf_must_be_visible():
    set_config = {
        "type": "function",
        "name": "setConfig",
        "stateMutability": "nonpayable",
        "inputs": [{
            "name": "params",
            "type": "tuple",
            "components": [
                {"name": "recipient", "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
        }],
    }
    descriptor = _descriptor(
        [set_config],
        {"setConfig((address,uint256))": {
            "intent": "Set config",
            "fields": [
                {"path": "#.params.recipient", "label": "To", "format": "addressName"}
            ],
        }},
    )
    result = preflight.preflight_transaction(
        _request(set_config, [(RECIPIENT, 10**30)], descriptor)
    )
    assert result["verdict"]["gate"] == "block"
    assert any(
        finding.get("argument") == "params.amount"
        for finding in result["checks"]["presentation_binding"]["findings"]
    )


def test_parent_tuple_field_does_not_hide_nested_values():
    set_config = {
        "type": "function",
        "name": "setConfig",
        "stateMutability": "nonpayable",
        "inputs": [{
            "name": "params",
            "type": "tuple",
            "components": [
                {"name": "recipient", "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
        }],
    }
    descriptor = _descriptor(
        [set_config],
        {"setConfig((address,uint256))": {
            "intent": "Set config",
            "fields": [{"path": "#.params", "label": "Config", "format": "raw"}],
        }},
    )
    result = preflight.preflight_transaction(
        _request(set_config, [(RECIPIENT, 10**30)], descriptor)
    )
    assert result["verdict"]["gate"] == "block"
    missing = {
        finding.get("argument")
        for finding in result["checks"]["presentation_binding"]["findings"]
        if finding["code"] == "ARGUMENT_NOT_VISIBLE"
    }
    assert missing == {"params.recipient", "params.amount"}


def test_duplicate_abi_input_names_are_unbindable():
    duplicate = _function("configure", [("x", "uint256"), ("x", "uint256")])
    descriptor = _descriptor(
        [duplicate],
        {"configure(uint256,uint256)": {
            "intent": "Configure",
            "fields": [{"path": "#.x", "label": "X", "format": "raw"}],
        }},
    )
    with pytest.raises(preflight.PreflightInputError) as caught:
        preflight.preflight_transaction(_request(duplicate, [1, 2], descriptor))
    assert caught.value.code == "UNBINDABLE_ABI"


def test_array_rendering_does_not_claim_every_element_is_visible():
    batch = _function("batch", [("amounts", "uint256[]")])
    descriptor = _descriptor(
        [batch],
        {"batch(uint256[])": {
            "intent": "Batch amounts",
            "fields": [{"path": "#.amounts.[]", "label": "Amounts", "format": "amount"}],
        }},
    )
    result = preflight.preflight_transaction(
        _request(batch, [[1, preflight.UINT256_MAX]], descriptor)
    )
    assert result["verdict"]["gate"] == "block"
    assert any(
        finding["code"] == "COLLECTION_NOT_EXPANDED"
        for finding in result["checks"]["presentation_binding"]["findings"]
    )


def test_display_formats_must_match_their_abi_value_types():
    descriptor = _descriptor(
        [TRANSFER],
        {"transfer(address,uint256)": {
            "intent": "Send tokens",
            "fields": [
                {"path": "#.to", "label": "Amount", "format": "amount"},
                {"path": "#.amount", "label": "To", "format": "addressName"},
            ],
        }},
    )
    result = preflight.preflight_transaction(
        _request(TRANSFER, [RECIPIENT, 42], descriptor)
    )
    assert result["verdict"]["gate"] == "block"
    assert {
        finding["code"]
        for finding in result["checks"]["presentation_binding"]["findings"]
    } == {"FIELD_FORMAT_MISMATCH", "ARGUMENT_NOT_VISIBLE"}


def test_transfer_labels_and_intent_must_match_server_classified_roles():
    bad_formats = [
        {
            "intent": "Send tokens",
            "fields": [
                {"path": "#.to", "label": "Amount", "format": "addressName"},
                {"path": "#.amount", "label": "Recipient", "format": "amount"},
            ],
        },
        {
            "intent": "Receive reward",
            "interpolatedIntent": "Receive bonus",
            "fields": TRANSFER_FORMAT["fields"],
        },
        {
            "intent": "Send 0 tokens",
            "interpolatedIntent": "Send 0 to {to}",
            "fields": TRANSFER_FORMAT["fields"],
        },
    ]
    for fmt in bad_formats:
        descriptor = _descriptor([TRANSFER], {"transfer(address,uint256)": fmt})
        result = preflight.preflight_transaction(
            _request(TRANSFER, [RECIPIENT, 42], descriptor)
        )
        assert result["verdict"]["gate"] == "block"
        assert result["checks"]["presentation_binding"]["complete"] is False


def test_address_name_parameters_are_not_silently_trusted():
    descriptor = _descriptor(
        [TRANSFER],
        {"transfer(address,uint256)": {
            **TRANSFER_FORMAT,
            "fields": [
                {
                    "path": "#.to",
                    "label": "To",
                    "format": "addressName",
                    "params": {"senderAddress": RECIPIENT},
                },
                TRANSFER_FORMAT["fields"][1],
            ],
        }},
    )
    result = preflight.preflight_transaction(
        _request(TRANSFER, [RECIPIENT, 42], descriptor)
    )
    assert result["verdict"]["gate"] == "block"
    assert any(
        finding["code"] == "FORMAT_ASSURANCE_UNSUPPORTED"
        for finding in result["checks"]["presentation_binding"]["findings"]
    )


def test_unknown_display_format_is_invalid_descriptor_input():
    descriptor = _descriptor(
        [TRANSFER],
        {"transfer(address,uint256)": {
            "intent": "Send tokens",
            "fields": [
                {"path": "#.to", "label": "To", "format": "notARealFormat"},
                {"path": "#.amount", "label": "Amount", "format": "notARealFormat"},
            ],
        }},
    )
    with pytest.raises(preflight.PreflightInputError) as caught:
        preflight.preflight_transaction(_request(TRANSFER, [RECIPIENT, 42], descriptor))
    assert caught.value.code == "INVALID_DESCRIPTOR"


@pytest.mark.parametrize("missing", ["label", "format"])
def test_visible_fields_require_renderable_shape(missing):
    to_field = {"path": "#.to", "label": "To", "format": "addressName"}
    to_field.pop(missing)
    descriptor = _descriptor(
        [TRANSFER],
        {"transfer(address,uint256)": {
            "intent": "Send tokens",
            "fields": [
                to_field,
                {"path": "#.amount", "label": "Amount", "format": "amount"},
            ],
        }},
    )
    with pytest.raises(preflight.PreflightInputError) as caught:
        preflight.preflight_transaction(_request(TRANSFER, [RECIPIENT, 42], descriptor))
    assert caught.value.code == "INVALID_DESCRIPTOR"


def test_field_count_and_duplicate_paths_are_bounded():
    too_many = [
        {"path": f"#.field{i}", "label": f"Field {i}", "format": "raw"}
        for i in range(preflight.MAX_FIELDS_PER_FORMAT + 1)
    ]
    for fields in (
        too_many,
        [
            {"path": "#.to", "label": "To", "format": "addressName"},
            {"path": "#.to", "label": "Recipient", "format": "addressName"},
        ],
    ):
        descriptor = _descriptor(
            [TRANSFER],
            {"transfer(address,uint256)": {"intent": "Send", "fields": fields}},
        )
        with pytest.raises(preflight.PreflightInputError) as caught:
            preflight.preflight_transaction(
                _request(TRANSFER, [RECIPIENT, 42], descriptor)
            )
        assert caught.value.code == "INVALID_DESCRIPTOR"


def test_nonzero_payable_value_must_be_an_always_visible_amount():
    hidden_value_format = {
        "intent": "Deposit",
        "fields": [
            {"path": "@.value", "label": "Value", "format": "amount", "visible": "never"}
        ],
    }
    descriptor = _descriptor([DEPOSIT], {"deposit()": hidden_value_format})
    result = preflight.preflight_transaction(
        _request(DEPOSIT, [], descriptor, value="0x1234")
    )
    assert result["verdict"]["gate"] == "block"
    assert result["verdict"]["code"] == "PRESENTATION_UNBOUND"
    assert result["checks"]["presentation_binding"]["findings"][0]["code"] == (
        "VALUE_NOT_VISIBLE"
    )


@pytest.mark.parametrize(
    ("path", "label", "field_format"),
    [
        ("@.from", "Fee", "addressName"),
        ("@.to", "Amount", "addressName"),
        ("@.value", "Recipient", "amount"),
    ],
)
def test_container_field_labels_are_bound_to_transaction_roles(path, label, field_format):
    descriptor = _descriptor(
        [DEPOSIT],
        {"deposit()": {
            "intent": "Deposit",
            "fields": [{
                "path": path,
                "label": label,
                "format": field_format,
                "visible": "always",
            }],
        }},
    )
    result = preflight.preflight_transaction(
        _request(DEPOSIT, [], descriptor, value="0x1")
    )
    assert result["verdict"]["gate"] == "block"
    assert any(
        finding["code"] == "ROLE_LABEL_MISMATCH"
        for finding in result["checks"]["presentation_binding"]["findings"]
    )


@pytest.mark.parametrize(
    ("abi_type", "value", "code"),
    [
        ("bytes", b"x" * (preflight.MAX_BYTES_PREVIEW + 1), "OPAQUE_VALUE_TRUNCATED"),
        ("string", "x" * 257, "OPAQUE_VALUE_TOO_LONG"),
    ],
)
def test_opaque_values_that_cannot_be_fully_presented_block(abi_type, value, code):
    set_blob = _function("setBlob", [("blob", abi_type)])
    descriptor = _descriptor(
        [set_blob],
        {f"setBlob({abi_type})": {
            "intent": "Set blob",
            "fields": [{"path": "#.blob", "label": "Blob", "format": "raw"}],
        }},
    )
    result = preflight.preflight_transaction(
        _request(set_blob, [value], descriptor)
    )
    assert result["verdict"]["gate"] == "block"
    assert any(
        finding["code"] == code
        for finding in result["checks"]["presentation_binding"]["findings"]
    )


@pytest.mark.parametrize("amount", [(1 << 53) + 1, preflight.UINT256_MAX])
def test_decoded_integers_are_lossless_decimal_strings(amount):
    descriptor = _descriptor(
        [TRANSFER], {"transfer(address,uint256)": TRANSFER_FORMAT}
    )
    result = preflight.preflight_transaction(
        _request(TRANSFER, [RECIPIENT, amount], descriptor)
    )
    decoded_amount = result["call"]["decoded_arguments"][1]["value"]
    assert decoded_amount == str(amount)
    assert isinstance(decoded_amount, str)


def test_uint256_max_approval_is_explicit_review():
    descriptor = _descriptor(
        [APPROVE], {"approve(address,uint256)": APPROVE_FORMAT}
    )
    result = preflight.preflight_transaction(
        _request(APPROVE, [SPENDER, preflight.UINT256_MAX], descriptor)
    )
    assert result["verdict"]["gate"] == "review"
    assert result["verdict"]["code"] == "UNLIMITED_APPROVAL"
    assert result["checks"]["comprehension"]["unlimited_approval"] is True


def test_set_approval_for_all_false_is_described_as_revocation():
    revoke = _function(
        "setApprovalForAll", [("operator", "address"), ("approved", "bool")]
    )
    descriptor = _descriptor(
        [revoke],
        {"setApprovalForAll(address,bool)": {
            "intent": "Revoke operator",
            "fields": [
                {"path": "#.operator", "label": "Operator", "format": "addressName"},
                {"path": "#.approved", "label": "Approved", "format": "raw"},
            ],
        }},
    )
    result = preflight.preflight_transaction(
        _request(revoke, [SPENDER, False], descriptor)
    )
    assert result["verdict"]["gate"] == "safe_to_present"
    assert result["checks"]["comprehension"]["revocation"] is True
    assert result["checks"]["danger"]["findings"] == []
    assert "revoke" in result["presentation"]["sentence_template"].lower()


def test_zero_erc20_approval_is_described_as_revocation():
    revoke_format = {
        **APPROVE_FORMAT,
        "intent": "Revoke token spending",
        "interpolatedIntent": "Revoke {spender} allowance",
    }
    descriptor = _descriptor([APPROVE], {"approve(address,uint256)": revoke_format})
    result = preflight.preflight_transaction(
        _request(APPROVE, [SPENDER, 0], descriptor)
    )
    assert result["verdict"]["gate"] == "safe_to_present"
    assert result["checks"]["comprehension"]["revocation"] is True
    assert "revoke" in result["presentation"]["sentence_template"].lower()


def test_erc721_max_token_id_is_not_called_an_unlimited_allowance():
    nft_approve = _function("approve", [("to", "address"), ("tokenId", "uint256")])
    descriptor = _descriptor(
        [nft_approve],
        {"approve(address,uint256)": {
            "intent": "Approve NFT",
            "fields": [
                {"path": "#.to", "label": "To", "format": "addressName"},
                {"path": "#.tokenId", "label": "Token ID", "format": "raw"},
            ],
        }},
    )
    result = preflight.preflight_transaction(
        _request(nft_approve, [SPENDER, preflight.UINT256_MAX], descriptor)
    )
    assert result["verdict"]["gate"] == "review"
    assert result["verdict"]["code"] == "COMPREHENSION_REVIEW"
    assert result["checks"]["comprehension"].get("unlimited_approval") is not True


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda request: request["transaction"].update(to="0x" + "44" * 20),
         "DEPLOYMENT_MISMATCH"),
        (lambda request: request["transaction"].update(data="0xdeadbeef"),
         "UNKNOWN_SELECTOR"),
        (lambda request: request["transaction"].update(value="0x00"),
         "INVALID_VALUE"),
    ],
)
def test_invalid_or_unbound_calls_fail_closed(mutate, code):
    descriptor = _descriptor(
        [TRANSFER], {"transfer(address,uint256)": TRANSFER_FORMAT}
    )
    request = _request(TRANSFER, [RECIPIENT, 42], descriptor)
    mutate(request)
    with pytest.raises(preflight.PreflightInputError) as caught:
        preflight.preflight_transaction(request)
    assert caught.value.code == code


@pytest.mark.parametrize(
    ("location", "field", "code"),
    [
        ("request", "policy_version", "UNKNOWN_REQUEST_FIELD"),
        ("transaction", "nonce", "UNKNOWN_TRANSACTION_FIELD"),
        ("transaction", "gas", "UNKNOWN_TRANSACTION_FIELD"),
    ],
)
def test_unknown_fields_are_rejected_in_the_shared_core(location, field, code):
    descriptor = _descriptor(
        [TRANSFER], {"transfer(address,uint256)": TRANSFER_FORMAT}
    )
    request = _request(TRANSFER, [RECIPIENT, 42], descriptor)
    target = request if location == "request" else request["transaction"]
    target[field] = "unexpected"
    with pytest.raises(preflight.PreflightInputError) as caught:
        preflight.preflight_transaction(request)
    assert caught.value.code == code


@pytest.mark.parametrize("suffix", ["00", "deadbeef", "00" * 32, "ff" * 32])
def test_calldata_must_reject_trailing_bytes(suffix):
    descriptor = _descriptor(
        [TRANSFER], {"transfer(address,uint256)": TRANSFER_FORMAT}
    )
    request = _request(TRANSFER, [RECIPIENT, 42], descriptor)
    request["transaction"]["data"] += suffix
    with pytest.raises(preflight.PreflightInputError) as caught:
        preflight.preflight_transaction(request)
    assert caught.value.code == "CALLDATA_NOT_CANONICAL"


def test_calldata_must_decode_exactly_when_truncated():
    descriptor = _descriptor(
        [TRANSFER], {"transfer(address,uint256)": TRANSFER_FORMAT}
    )
    request = _request(TRANSFER, [RECIPIENT, 42], descriptor)
    request["transaction"]["data"] = request["transaction"]["data"][:-2]
    with pytest.raises(preflight.PreflightInputError) as caught:
        preflight.preflight_transaction(request)
    assert caught.value.code == "CALLDATA_DECODE_FAILED"


@pytest.mark.parametrize("value", ["0x1", "0xde0b6b3a7640000"])
def test_nonpayable_function_with_native_value_blocks(value):
    descriptor = _descriptor(
        [TRANSFER], {"transfer(address,uint256)": TRANSFER_FORMAT}
    )
    result = preflight.preflight_transaction(
        _request(TRANSFER, [RECIPIENT, 42], descriptor, value=value)
    )
    assert result["verdict"] == {
        "gate": "block",
        "code": "NONPAYABLE_WITH_VALUE",
        "reason": "the transaction sends native value to a function not declared payable",
    }


def test_selector_collision_is_rejected(monkeypatch):
    other = _function("other", [("value", "uint256")])
    descriptor = _descriptor([TRANSFER, other], {})
    monkeypatch.setattr(preflight.common, "selector", lambda _signature: "0x12345678")
    request = {
        "transaction": {
            "chain_id": 1,
            "from": SENDER,
            "to": ADDRESS,
            "data": "0x12345678" + "00" * 64,
            "value": "0x0",
        },
        "descriptor": descriptor,
    }
    with pytest.raises(preflight.PreflightInputError) as caught:
        preflight.preflight_transaction(request)
    assert caught.value.code == "SELECTOR_COLLISION"


def test_call_fingerprint_is_deterministic_and_binds_sender_and_value():
    descriptor = _descriptor(
        [TRANSFER], {"transfer(address,uint256)": TRANSFER_FORMAT}
    )
    request = _request(TRANSFER, [RECIPIENT, 42], descriptor)
    first = preflight.preflight_transaction(request)["call_fingerprint"]
    second = preflight.preflight_transaction(request)["call_fingerprint"]
    request["transaction"]["from"] = "0x" + "bb" * 20
    sender_changed = preflight.preflight_transaction(request)["call_fingerprint"]
    request["transaction"]["from"] = SENDER
    request["transaction"]["value"] = "0x1"
    changed = preflight.preflight_transaction(request)["call_fingerprint"]
    assert first == second
    assert first != sender_changed
    assert first != changed


def test_unsupported_display_path_cannot_clear_a_no_arg_call():
    ping = _function("ping", [])
    for path in ("@.bogus", "garbage", "$.evil"):
        descriptor = _descriptor(
            [ping],
            {"ping()": {
                "intent": "Ping",
                "fields": [{"path": path, "label": "Extra", "format": "raw"}],
            }},
        )
        result = preflight.preflight_transaction(_request(ping, [], descriptor))
        assert result["verdict"]["gate"] == "block"
        assert result["checks"]["presentation_binding"]["findings"][0]["code"] == (
            "UNSUPPORTED_FIELD_PATH"
        )


def test_descriptor_without_signable_functions_never_passes():
    descriptor = _descriptor([], {})
    result = preflight.check_descriptor({"descriptor": descriptor})
    assert result["verdict"]["gate"] == "block"
    assert result["verdict"]["code"] == "NO_SIGNABLE_FUNCTIONS"
