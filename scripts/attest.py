#!/usr/bin/env python3
"""ERC-8176 attestation — sign an evidence-backed statement that a descriptor
faithfully represents its contract.

This is the rung above verification: `audit.py` grades a descriptor and
`semverify.py` proves its screens against mined receipts, but neither produces
anything a *wallet* can consume. ERC-8176 defines that consumable: an EAS
attestation over the descriptor's canonical hash, signed by a registered
auditor. Wallets weight descriptors by whose attestations they carry — so the
attestation, not the descriptor, is where pricing power lives.

What this tool does, in order:
  1. Quality-gate: refuse to attest anything below audit grade B.
  2. Evidence: run semverify (needs ETHERSCAN_API_KEY); record the outcome.
     `--require-sim` makes a semverify pass mandatory — the differentiator vs
     attesters who sign on eyeball review.
  3. Canonicalize the descriptor per RFC 8785 (JCS) and keccak256 it. ERC-7730
     JSON is strings/ints/bools only, so sorted-keys + minimal separators IS
     the JCS form (floats, which JCS serializes specially, never occur).
  4. Sign an EAS *offchain* attestation (EIP-712, version-2 struct with salt)
     binding the hash under the ERC-8176 schema. Offchain = free, revocable
     by publishing, and exactly what the registry's sigs/ convention expects.
  5. Drop registry/<project>/sigs/<descriptor>.<attester>.json next to the
     descriptor, ready for the registry PR.

The ERC-8176 schema UID is NOT hardcoded: it lives on the EAS registry and is
published via clearsigning.org. Pass it with --schema or ERC8176_SCHEMA_UID.
Without it the tool still runs end-to-end and writes an UNSIGNED evidence
bundle (--dry-run implied), so the pipeline can be exercised before the
auditor profile PR is merged.

Env:  ATTESTER_PRIVATE_KEY  (never committed; throwaway ok for dry runs)
      ERC8176_SCHEMA_UID    (or --schema 0x…)
      ETHERSCAN_API_KEY     (for semverify evidence)
Usage:
    python scripts/attest.py <descriptor.json> [--schema 0x…] [--require-sim]
    python scripts/attest.py <descriptor.json> --pq [--pq-scheme ml_dsa_65]  # + quantum-safe co-signature
    python scripts/attest.py <descriptor.json> --profile   # emit auditor profile stub
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import rfc8785
from eth_account import Account
from eth_utils import keccak

import audit

ROOT = Path(__file__).resolve().parent.parent
# EAS v1.2 on Ethereum mainnet — the deployment ERC-8176 rides on.
EAS_MAINNET = "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587"
ZERO32 = "0x" + "0" * 64
MIN_GRADE = ("A", "B")


def rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def canonical_bytes(obj) -> bytes:
    """RFC 8785 (JCS) serialization — reference impl, verified byte-identical to
    Cyfrin's official `clearsig descriptor-hash` on the ENS descriptors."""
    return rfc8785.dumps(obj)


def descriptor_hash(desc: dict) -> str:
    return "0x" + keccak(canonical_bytes(desc)).hex()


def flag_value(name: str, default=None):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default


# ---- post-quantum co-signing (crypto-agility) ------------------------------
# ECDSA (the EAS signature) falls to Shor once a CRQC exists; keccak256 (the
# descriptorHash) does not (Grover only halves it). So we keep the hash and add
# a quantum-safe signature over the SAME commitment. Attestations are long-lived
# trust artifacts — "harvest now, forge later" — which is exactly the class
# worth PQ-signing before a CRQC arrives, not after.
PQ_SCHEMES = {
    "ml_dsa_44": "FIPS 204 (Dilithium2) — smallest ML-DSA, ~2.4KB sig",
    "ml_dsa_65": "FIPS 204 (Dilithium3) — balanced default, ~3.3KB sig",
    "ml_dsa_87": "FIPS 204 (Dilithium5) — highest ML-DSA margin, ~4.6KB sig",
    "falcon_512": "FIPS 206 draft — compact ~0.65KB sig, but float/side-channel risk (Donjon-flagged)",
    "sphincs_sha2_128s_simple": "SLH-DSA (FIPS 205) — hash-based, most conservative, large ~7.9KB sig",
}
PQ_DEFAULT = "ml_dsa_65"


def pq_keypair(scheme: str):
    """Attester PQ keypair: env, else a gitignored keyfile, else generate+persist.
    The secret key is NEVER written to the tracked tree."""
    sk_env, pk_env = os.environ.get("LUCENT_PQ_SECRET_KEY"), os.environ.get("LUCENT_PQ_PUBLIC_KEY")
    if sk_env and pk_env:
        return bytes.fromhex(pk_env.removeprefix("0x")), bytes.fromhex(sk_env.removeprefix("0x")), "env"
    keyfile = ROOT / ".attester-keys" / f"{scheme}.json"      # gitignored
    if keyfile.exists():
        k = json.loads(keyfile.read_text())
        return bytes.fromhex(k["publicKey"]), bytes.fromhex(k["secretKey"]), "keyfile"
    from importlib import import_module
    mod = import_module(f"pqcrypto.sign.{scheme}")
    pk, sk = mod.generate_keypair()
    # Secret signing key — write owner-only regardless of umask.
    keyfile.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(keyfile.parent, 0o700)
    except OSError:
        pass
    payload = json.dumps({
        "scheme": scheme, "publicKey": pk.hex(), "secretKey": sk.hex(),
        "_warning": "GENERATED demo key. A real attester generates this OFFLINE "
                    "and keeps secretKey out of any repo. This dir is gitignored.",
    }, indent=2) + "\n"
    fd = os.open(str(keyfile), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(payload)
    return pk, sk, "generated"


def pq_attest(scheme: str, dhash_hex: str) -> dict:
    """Quantum-safe signature over the descriptorHash (scheme-agnostic claim)."""
    from importlib import import_module
    mod = import_module(f"pqcrypto.sign.{scheme}")
    pk, sk, src = pq_keypair(scheme)
    sig = mod.sign(sk, bytes.fromhex(dhash_hex.removeprefix("0x")))
    return {
        "scheme": scheme, "standard": PQ_SCHEMES.get(scheme, "post-quantum"),
        "signs": "descriptorHash", "keySource": src,
        "publicKey": "0x" + pk.hex(), "signature": "0x" + sig.hex(),
        "verify": f"pqcrypto.sign.{scheme}.verify(publicKey, descriptorHash, signature)",
    }


def run_semverify(desc_path: Path) -> dict:
    """Semantic-verification evidence; the receipt-backed half of the claim."""
    if not os.environ.get("ETHERSCAN_API_KEY"):
        return {"ran": False, "passed": None, "note": "no ETHERSCAN_API_KEY"}
    proc = subprocess.run(
        [sys.executable, str(Path(__file__).parent / "semverify.py"), str(desc_path)],
        capture_output=True, text=True)
    return {"ran": True, "passed": proc.returncode == 0,
            "note": proc.stdout.strip().splitlines()[-1] if proc.stdout else ""}


def eas_typed_data(schema_uid: str, chain_id: int, data_hex: str) -> dict:
    """EAS offchain attestation (struct version 2 — salted) as EIP-712 payload."""
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
            "version": 2,
            "schema": schema_uid,
            "recipient": "0x" + "0" * 40,   # attestation is about a hash, not a party
            "time": int(time.time()),
            "expirationTime": 0,             # stands until revoked (drift → revoke, see watch.py)
            "revocable": True,
            "refUID": ZERO32,
            "data": data_hex,
            "salt": "0x" + secrets.token_bytes(32).hex(),
        },
    }


def write_profile(attester: str, ens: str = "", org: str = "") -> Path:
    """Auditor registration file, per the registry auditors spec:
    {id, name, ens?, organization?}. PR to auditors/eip155-1-<addr>/profile.json.
    (Extra descriptive fields like a review policy belong on the linked site/ENS,
    not this index — the importer expects exactly these keys.)"""
    d = ROOT / "dist" / "auditors" / f"eip155-1-{attester.lower()}"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "profile.json"
    profile = {"id": f"eip155:1:{attester}", "name": "Lucent"}
    if ens:
        profile["ens"] = ens
    if org:
        profile["organization"] = org
    p.write_text(json.dumps(profile, indent=2) + "\n")
    return p


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 2
    desc_path = Path(args[0]).resolve()
    desc = json.loads(desc_path.read_text())
    schema = os.environ.get("ERC8176_SCHEMA_UID")
    if "--schema" in sys.argv:
        schema = sys.argv[sys.argv.index("--schema") + 1]

    key = os.environ.get("ATTESTER_PRIVATE_KEY")
    acct = Account.from_key(key) if key else None

    if "--profile" in sys.argv:
        if not acct:
            print("ATTESTER_PRIVATE_KEY required to derive the profile address")
            return 1
        print(f"auditor profile stub -> {write_profile(acct.address).relative_to(ROOT)}")
        return 0

    name = desc_path.stem
    print(f"Attestation pipeline — {name}")
    print("─" * 66)

    # Gate 1: audit grade
    r = audit.audit(desc)
    ok = r["grade"] in MIN_GRADE
    print(f"  audit      grade {r['grade']} ({r['score']}/100)  "
          f"{'✓' if ok else '✗ below ' + MIN_GRADE[-1] + ' — refusing to attest'}")
    if not ok:
        return 1

    # Gate 2: semantic evidence
    sim = run_semverify(desc_path)
    if sim["ran"]:
        print(f"  semverify  {'✓ receipts match screens' if sim['passed'] else '✗ DIVERGENCE'}")
        if not sim["passed"]:
            print("  a diverging descriptor must never be attested.")
            return 1
    else:
        print(f"  semverify  skipped ({sim['note']})")
        if "--require-sim" in sys.argv:
            return 1

    # The claim: keccak256 of the JCS-canonical descriptor
    dhash = descriptor_hash(desc)
    print(f"  hash       {dhash}  (keccak256 · RFC-8785)")

    chain = desc["context"]["contract"]["deployments"][0]["chainId"]
    bundle = {
        "descriptor": desc_path.name,
        "descriptorHash": dhash,
        "canonicalization": "RFC-8785 (JCS)",
        "standard": "ERC-8176 via EAS offchain",
        "evidence": {
            "audit": {"grade": r["grade"], "score": r["score"],
                      "coverage": f"{r['covered_functions']}/{r['signable_functions']}"},
            "semverify": sim,
        },
    }

    # Optional crypto-agile post-quantum co-signature over the same hash.
    if "--pq" in sys.argv:
        scheme = flag_value("--pq-scheme", PQ_DEFAULT)
        pqa = pq_attest(scheme, dhash)
        bundle["pqAttestation"] = pqa
        print(f"  pq-sign    {scheme} ✓ quantum-safe "
              f"({len(pqa['signature']) // 2 - 1} B sig, key: {pqa['keySource']})")

    if not (schema and acct):
        missing = [w for w, v in
                   [("ERC8176_SCHEMA_UID/--schema", schema),
                    ("ATTESTER_PRIVATE_KEY", acct)] if not v]
        out = desc_path.parent / "sigs" / f"{name}.UNSIGNED.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(bundle, indent=2) + "\n")
        print(f"  UNSIGNED evidence bundle -> {rel(out)}")
        print(f"  (missing: {', '.join(missing)} — schema UID is published on clearsigning.org)")
        return 0

    typed = eas_typed_data(schema, chain, dhash)
    signed = acct.sign_typed_data(full_message=typed)
    bundle["attestation"] = {
        "attester": acct.address,
        "eas": {"contract": EAS_MAINNET, "chainId": chain},
        "typedData": typed,
        "signature": signed.signature.to_0x_hex(),
        "uid": "0x" + keccak(canonical_bytes(typed["message"])).hex(),
    }
    out = desc_path.parent / "sigs" / f"{name}.{acct.address.lower()}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2) + "\n")
    print(f"  ✅ signed by {acct.address}")
    print(f"  attestation -> {rel(out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
