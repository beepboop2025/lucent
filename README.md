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

## For signing agents: the MCP server

An AI agent about to sign a transaction faces exactly the question Lucent's
checks answer — is this call safe, and does the screen a human would see actually
describe what it does? `scripts/mcp_server.py` exposes that as an MCP server
(stdlib JSON-RPC over stdio) so an agent can pre-flight a signature:

- **`check_descriptor`** — one combined gate over an ERC-7730 descriptor: the
  audit grade (screen shows the right fields), the comprehension grade (a
  plain-language consequence sentence + risk tier per function), and the danger
  scan (structural primitives a clear screen can't make safe). Returns a
  `verdict.gate` of `safe_to_present` / `review` / `block` to branch on — a
  CRITICAL danger primitive blocks regardless of how benign the sentence reads.
- **`explain_signature`** — the actor→action→object sentence + risk tier +
  reason for one function, to render a human confirmation before a signature.
- **`scan_contract`** — danger-scan a deployed contract by address (fetches the
  verified ABI from Sourcify), so an agent can assess a contract before any
  transaction is built.

```bash
make mcp    # or: .venv/bin/python scripts/mcp_server.py
```

Register it as a stdio MCP server pointing at `scripts/mcp_server.py` from the
repo root (see `mcp.json`). Same transport shape as the sibling Groundcheck and
Seiche servers.

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
| Comprehend | `comprehend.py` | Grade the descriptor on human comprehension risk |
| Danger | `danger.py` | Flag structural danger primitives a clear screen can't make safe |
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

## Comprehension risk

Lint checks that a descriptor is well-formed; `audit.py` checks that the screen
_shows_ the right fields. Neither asks the question that
["What I Sign Is Not What I See"](https://arxiv.org/abs/2601.16751) shows is the
real failure: users mis-_understand_ a technically-correct screen. Its studies
found people fixate on the amount and recipient and miss scope, delegation, and
unlimited allowances — and that a bare field list, even a complete one, leaves
comprehension at chance on the dangerous cases. Its Signature Semantic Decoder
cut false approvals on unlimited-allowance and phishing transactions by 73% and
46% by rendering an actor→action→object sentence and a risk tier _with a reason_.

`comprehend.py` brings that to the descriptor. For each signable function it
emits:

- a **consequence sentence** — who acts on what, plus conditions, built from the
  ABI and the descriptor's own labels so it renders what the wallet will show:
  _"You let {Operator} transfer ANY of your tokens in this contract, at any time,
  until you revoke it."_
- a **risk tier with the clause that earned it** — the paper's users rejected
  bare labels and demanded the why. Patterns scored are the ones the study found
  people miss: operator grants (`setApprovalForAll`), ERC-20 allowances (flagged
  distinctly from ERC-721 token-id approvals, since `approve(address,uint256)`
  reads identically but means different things), permits (off-chain, invisible in
  history), admin/upgrade authority, and raw-hex recipients (the address-poisoning
  surface).

An unrecognised function with no on-screen intent is reported as an unexplained
screen (a caution), never silently cleared — an unexplained screen invites blind
approval, which is the failure the paper measures. Run it with `make comprehend
DESC=…`; NameWrapper's `setApprovalForAll` and the controller's
`transferOwnership` both surface as CRITICAL comprehension risks that lint and
audit pass.

## Danger surface

Audit asks whether the screen shows the right fields; comprehend asks whether the
human understands them. `danger.py` asks the third question: can this function,
_by construction_, do something a clear screen still can't make safe? A descriptor
can render a perfectly honest sentence for `execute(address target, bytes data)` —
"Call {target} with {data}" — and that call can still drain the wallet, because
the primitive itself is unbounded.

Runtime systems catch this by instrumenting transaction-trace properties
([arXiv:2408.14621](https://arxiv.org/abs/2408.14621): arbitrary
`CALL`/`DELEGATECALL`/`SELFDESTRUCT` in the trace). `danger.py` lifts the same
property set to **static ABI analysis**, so the danger is named before anyone
signs:

- **CRITICAL** — arbitrary external call (a call-family name, or a target-address
  + calldata-blob signature), `delegatecall` (foreign code in this contract's
  context), self-destruct, and upgrade-and-execute.
- **HIGH** — unbounded delegation (`setApprovalForAll`), authority transfer
  (ownership / admin / role).
- **MEDIUM** — value sweep to a caller-supplied address.

Precision is the whole game: a danger scan that cries wolf on `safeTransferFrom`
is worse than none. The detector distinguishes calldata from data-as-content by
_parameter name_ (`target`+`data`, not any address-plus-bytes), excludes `to`
(a recipient, not a callee), and whitelists the standard ERC receiver hooks — so
the shipped ENS bundle raises **zero** false arbitrary-call flags while a real
`execute(target,data)` drainer is still caught. `--strict` exits non-zero on any
CRITICAL.

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

The receipt is exact for mined transactions. The recipient check is heuristic on
field labels; it catches recipient hiding and label spoofing, not every possible
mismatch.

**Unmined calls — fork replay.** A brand-new descriptor for a call that has never
been mined (a fresh contract, a rarely-used function) has no receipt to check
against. `forkreplay.py` closes that gap: given a call spec
`{signer, function, args, value}` it forks mainnet at HEAD into a local `anvil`,
impersonates the signer, executes the call against real on-chain state, and reads
back the standard eth receipt. That `(tx, receipt)` pair is handed to
`semverify.verify_one` **unchanged** — so a label swap or hidden recipient on an
unmined call is caught by the identical, tested code path, not a second
implementation. Run it with `make semverify DESC=… SIMULATE=1` on a test file
whose vectors carry a `call` object instead of a `txHash`. It needs `anvil` +
`cast` (`foundryup`) and an RPC URL (`ETH_RPC_URL`); without them the call vector
is skipped with a reason, never silently passed.

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
