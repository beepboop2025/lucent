#!/usr/bin/env python3
"""Produce an ERC-8176 attestation over a descriptor's canonical hash.

Gated on evidence: the descriptor must pass the audit (grade B or better) and,
when an Etherscan key is present, semantic verification against its test
vectors. It then computes descriptorHash = keccak256(RFC-8785 JCS(descriptor))
and writes an EAS offchain attestation to registry/<project>/sigs/. Without a
schema UID or signing key it writes an unsigned evidence bundle instead.

--pq adds a post-quantum co-signature over the same hash: the hash is already
quantum-safe but the ECDSA signature is not, and attestations are long-lived.

    attest.py <descriptor.json> [--schema 0x...] [--require-sim] [--pq [--pq-scheme S]]
    attest.py <descriptor.json> --profile   (emit the auditor profile)

Env: ATTESTER_PRIVATE_KEY, ERC8176_SCHEMA_UID, ETHERSCAN_API_KEY, LUCENT_PQ_*
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import time
from importlib import import_module
from pathlib import Path

import rfc8785
from eth_account import Account
from eth_utils import keccak

import audit
import common
import semverify

# EAS v1.2 on Ethereum mainnet, the deployment ERC-8176 attestations ride on.
EAS_MAINNET = "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587"
ZERO32 = "0x" + "0" * 64
MIN_GRADE = ("A", "B")

PQ_SCHEMES = {
    "ml_dsa_44": "FIPS 204 (Dilithium2), ~2.4KB sig",
    "ml_dsa_65": "FIPS 204 (Dilithium3), ~3.3KB sig",
    "ml_dsa_87": "FIPS 204 (Dilithium5), ~4.6KB sig",
    "falcon_512": "FIPS 206 draft, ~0.65KB sig, float/side-channel risk",
    "sphincs_sha2_128s_simple": "SLH-DSA (FIPS 205), hash-based, ~7.9KB sig",
}
PQ_DEFAULT = "ml_dsa_65"


def descriptor_hash(desc: dict) -> str:
    return "0x" + keccak(rfc8785.dumps(desc)).hex()


def run_semverify(descriptor: Path) -> dict:
    if not os.environ.get("ETHERSCAN_API_KEY"):
        return {"ran": False, "passed": None}
    r = semverify.evaluate(descriptor)
    return {"ran": True, "passed": r["divergences"] == 0 and r["total"] > 0,
            "verified": r["verified"], "total": r["total"]}


def pq_keypair(scheme: str):
    """PQ keypair from env, else a gitignored keyfile, else generated and
    persisted with owner-only permissions. The secret never enters the tree."""
    sk_env, pk_env = os.environ.get("LUCENT_PQ_SECRET_KEY"), os.environ.get("LUCENT_PQ_PUBLIC_KEY")
    if sk_env and pk_env:
        return bytes.fromhex(pk_env.removeprefix("0x")), bytes.fromhex(sk_env.removeprefix("0x")), "env"
    keyfile = common.ROOT / ".attester-keys" / f"{scheme}.json"
    if keyfile.exists():
        k = json.loads(keyfile.read_text())
        return bytes.fromhex(k["publicKey"]), bytes.fromhex(k["secretKey"]), "keyfile"
    pk, sk = import_module(f"pqcrypto.sign.{scheme}").generate_keypair()
    keyfile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(keyfile.parent, 0o700)
    except OSError:
        pass
    payload = json.dumps({"scheme": scheme, "publicKey": pk.hex(), "secretKey": sk.hex(),
                          "_warning": "Generated key. A real attester generates this offline; "
                                      "this dir is gitignored."}, indent=2) + "\n"
    fd = os.open(str(keyfile), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(payload)
    return pk, sk, "generated"


def pq_attest(scheme: str, dhash: str) -> dict:
    mod = import_module(f"pqcrypto.sign.{scheme}")
    pk, sk, source = pq_keypair(scheme)
    sig = mod.sign(sk, bytes.fromhex(dhash.removeprefix("0x")))
    return {"scheme": scheme, "standard": PQ_SCHEMES.get(scheme, "post-quantum"),
            "signs": "descriptorHash", "keySource": source,
            "publicKey": "0x" + pk.hex(), "signature": "0x" + sig.hex(),
            "verify": f"pqcrypto.sign.{scheme}.verify(publicKey, descriptorHash, signature)"}


def eas_typed_data(schema_uid: str, chain_id: int, data_hex: str) -> dict:
    return {
        "domain": {"name": "EAS Attestation", "version": "1.2.0",
                   "chainId": chain_id, "verifyingContract": EAS_MAINNET},
        "primaryType": "Attest",
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Attest": [
                {"name": "version", "type": "uint16"},
                {"name": "schema", "type": "bytes32"},
                {"name": "recipient", "type": "address"},
                {"name": "time", "type": "uint64"},
                {"name": "expirationTime", "type": "uint64"},
                {"name": "revocable", "type": "bool"},
                {"name": "refUID", "type": "bytes32"},
                {"name": "data", "type": "bytes"},
                {"name": "salt", "type": "bytes32"},
            ],
        },
        "message": {
            "version": 2, "schema": schema_uid, "recipient": common.ZERO_ADDRESS,
            "time": int(time.time()), "expirationTime": 0, "revocable": True,
            "refUID": ZERO32, "data": data_hex, "salt": "0x" + secrets.token_bytes(32).hex(),
        },
    }


def write_profile(attester: str, name: str, ens: str = "", org: str = "") -> Path:
    """Auditor registration file per the registry spec: {id, name, ens?, organization?}."""
    profile = {"id": f"eip155:1:{attester}", "name": name}
    if ens:
        profile["ens"] = ens
    if org:
        profile["organization"] = org
    out = common.ROOT / "dist" / "auditors" / f"eip155-1-{attester.lower()}" / "profile.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(profile, indent=2) + "\n")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("descriptor")
    ap.add_argument("--schema", default=os.environ.get("ERC8176_SCHEMA_UID"))
    ap.add_argument("--require-sim", action="store_true")
    ap.add_argument("--pq", action="store_true")
    ap.add_argument("--pq-scheme", default=PQ_DEFAULT, choices=list(PQ_SCHEMES))
    ap.add_argument("--profile", action="store_true")
    ap.add_argument("--name", default="Lucent")
    ap.add_argument("--ens", default="")
    ap.add_argument("--org", default="")
    args = ap.parse_args()

    desc_path = Path(args.descriptor).resolve()
    desc = json.loads(desc_path.read_text())
    key = os.environ.get("ATTESTER_PRIVATE_KEY")
    acct = Account.from_key(key) if key else None

    if args.profile:
        if not acct:
            print("ATTESTER_PRIVATE_KEY required to derive the profile address")
            return 1
        print(f"profile {common.rel(write_profile(acct.address, args.name, args.ens, args.org))}")
        return 0

    name = desc_path.stem
    print(f"attest {name}")

    r = audit.audit(desc)
    print(f"  audit      grade {r['grade']} ({r['score']}/100)")
    if r["grade"] not in MIN_GRADE:
        print(f"  refused: grade below {MIN_GRADE[-1]}")
        return 1

    sim = run_semverify(desc_path)
    if sim["ran"]:
        print(f"  semverify  {sim['verified']}/{sim['total']} "
              + ("verified" if sim["passed"] else "DIVERGENCE"))
        if not sim["passed"]:
            print("  refused: a diverging descriptor must not be attested")
            return 1
    else:
        print("  semverify  skipped (no ETHERSCAN_API_KEY)")
        if args.require_sim:
            return 1

    dhash = descriptor_hash(desc)
    print(f"  hash       {dhash}")

    bundle = {
        "descriptor": desc_path.name, "descriptorHash": dhash,
        "canonicalization": "RFC-8785 (JCS)", "standard": "ERC-8176 via EAS offchain",
        "evidence": {"audit": {"grade": r["grade"], "score": r["score"]}, "semverify": sim},
    }
    if args.pq:
        bundle["pqAttestation"] = pq_attest(args.pq_scheme, dhash)
        b = len(bundle["pqAttestation"]["signature"]) // 2 - 1
        print(f"  pq         {args.pq_scheme} ({b}B sig, key: {bundle['pqAttestation']['keySource']})")

    sigs = desc_path.parent / "sigs"
    sigs.mkdir(exist_ok=True)
    if not (args.schema and acct):
        out = sigs / f"{name}.UNSIGNED.json"
        out.write_text(json.dumps(bundle, indent=2) + "\n")
        print(f"  unsigned evidence bundle {common.rel(out)}")
        print("  (set --schema and ATTESTER_PRIVATE_KEY to sign)")
        return 0

    typed = eas_typed_data(args.schema, desc["context"]["contract"]["deployments"][0]["chainId"], dhash)
    signed = acct.sign_typed_data(full_message=typed)
    bundle["attestation"] = {
        "attester": acct.address, "eas": {"contract": EAS_MAINNET},
        "typedData": typed, "signature": signed.signature.to_0x_hex(),
    }
    out = sigs / f"{name}.{acct.address.lower()}.json"
    out.write_text(json.dumps(bundle, indent=2) + "\n")
    print(f"  signed by {acct.address}")
    print(f"  attestation {common.rel(out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
