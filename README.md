# Lucent

Tooling to author, verify, and attest [ERC-7730](https://eips.ethereum.org/EIPS/eip-7730)
Clear Signing descriptors for the public
[registry](https://github.com/ethereum/clear-signing-erc7730-registry) that
compatible wallets read from.

A descriptor is a JSON file that tells a wallet how to render a contract call in
plain language, so users see what they are signing instead of raw hex. Lucent
covers the full path: find contracts that lack a descriptor, write and harden
one, check it beyond schema validity, prove it against real transactions, and
produce an ERC-8176 attestation.

## Install

```bash
make setup     # creates .venv and installs requirements (Python 3.12+)
```

Most stages that read on-chain data need a free Etherscan API key:

```bash
export ETHERSCAN_API_KEY=...
```

## Pipeline

| Stage | Script | Purpose |
|-------|--------|---------|
| Discover | `discover.py` | Classify candidates: verified, signable, and uncovered |
| Fetch ABI | `fetch_abi.py` | Verified ABI from Sourcify (a registry requirement) |
| Resolve proxy | `resolve_proxy.py` | Cache an implementation ABI under a proxy address |
| Generate | `erc7730 generate` | Bootstrap a draft descriptor |
| Lint | `erc7730 lint` | Schema, selectors, device limits, ABI consistency |
| Audit | `audit.py` | Grade the descriptor on screen trustworthiness |
| Verify | `semverify.py` | Check the screen against real on-chain movements |
| Prove | `preview.py`, `fetch_tx.py` | Render the screen and build real test vectors |
| Package | `to_submission.py` | Registry-form output under `dist/`, gated on audit grade |
| Attest | `attest.py` | ERC-8176 attestation over the descriptor hash |
| Watch | `watch.py` | Monitor merged descriptors for drift |

A `common.py` module holds the shared Sourcify and Etherscan clients and ABI
utilities.

## Audit

`erc7730 lint` checks that a descriptor is well-formed. `audit.py` checks whether
the on-device screen would mislead a user, which lint does not:

- CRITICAL: a payable function that never shows `@.value`, or a `tokenAmount`
  with no known token.
- HIGH: a signable function with no intent or no visible field, or an address
  shown as raw hex.
- MEDIUM/LOW: labels or intents past the device character limits, missing
  interpolated summaries.

It reports a letter grade. `to_submission.py` refuses to package below grade B.
A raw generated draft of the ENS controller scores F; the hardened descriptors
score A.

## Semantic verification

Lint proves a descriptor is well-formed, not that its summary is honest. A
descriptor can pass every schema check and still render a benign screen for a
call that sends assets elsewhere.

For each test vector, `semverify.py` fetches the mined receipt (the record of
what actually moved), extracts the asset movements and approvals (ETH, ERC-20,
ERC-1155, ApprovalForAll), and checks the screen against them: every real
recipient and operator is shown, ETH spent is shown, and the field labelled as
the recipient matches the address that received the asset.

Worked example, a `safeTransferFrom` descriptor with the To and From labels
swapped:

| Check | Result |
|-------|--------|
| `erc7730 lint` | pass (schema-valid, both fields shown) |
| `audit.py` | grade A (structurally correct) |
| `semverify.py` | divergence (labels the sender as recipient) |

The receipt is exact for mined transactions. Hypothetical or unmined calls would
need a fork replay (Foundry `cast run`), which is not wired up. The recipient
check is heuristic on field labels; it catches recipient hiding and label
spoofing, not every possible mismatch.

## Post-quantum co-signing

A descriptor hash is `keccak256`, which is quantum-safe. The ECDSA signature over
it is not, and attestations are long-lived. `attest.py --pq` adds a post-quantum
signature over the same hash so the attestation stays verifiable if the
signature scheme is broken. The hash is unchanged; only the signature scheme is
added.

| Scheme | Standard | Signature size |
|--------|----------|----------------|
| `ml_dsa_65` (default) | FIPS 204 | ~3.3 KB |
| `ml_dsa_44` / `ml_dsa_87` | FIPS 204 | ~2.4 / ~4.6 KB |
| `falcon_512` | FIPS 206 draft | ~0.65 KB (float and side-channel risk) |
| `sphincs_sha2_128s_simple` | FIPS 205 | ~7.9 KB (hash-based) |

The signature binds the exact descriptor hash. Keys are read from `LUCENT_PQ_*`
env vars or a gitignored `.attester-keys/` directory, written owner-only. No
cryptographically-relevant quantum computer exists yet and there is no standard
for post-quantum attestations, so this is forward positioning, not a current
requirement.

## Current state

Three ENS descriptors, each grade A and lint clean against the on-chain ABI,
packaged under `dist/registry-pr/ens/`:

| Descriptor | Functions | Test vectors |
|------------|-----------|--------------|
| ETHRegistrarController (`0x2535…303b`) | 7 | 8 |
| NameWrapper (`0xD441…6401`) | 26 | 6 |
| BulkRenewal | 1 | 3 |

Test vectors are real historical transactions, built with
`fetch_tx.py <chain> <address> <descriptor>`.

A registry PR should be submitted by or on behalf of the contract's owner. The
remaining step for the ENS descriptors is that authorization, not code.

## Attester registration

`attest.py --profile` writes an auditor profile
(`auditors/eip155-1-<address>/profile.json`) for a registry PR. Signing an EAS
offchain attestation needs the ERC-8176 schema UID (published on clearsigning.org)
and an attester key. Without them, `attest.py` writes an unsigned evidence
bundle so the pipeline can run end to end first.
