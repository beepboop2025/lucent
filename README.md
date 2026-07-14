# Lucent — Clear Signing, done right

Lucent turns the transactions users **blind-sign** today into plain-language
screens they can actually read, by authoring high-quality
[ERC-7730](https://eips.ethereum.org/EIPS/eip-7730) *Clear Signing* descriptors
and submitting them to the public
[registry](https://github.com/ethereum/clear-signing-erc7730-registry) that
every compatible wallet (Ledger and partners) reads from.

> Working name. The first artifact is a hardened descriptor for the **ENS
> ETHRegistrarController** — one of the most blind-signed contracts on
> Ethereum, with **zero** existing registry coverage.

## Why this exists

A wallet that can't decode a contract shows the user raw hex and a "blind
signing" warning. Users approve anyway, and that gap is the mechanic behind a
large share of phishing losses. ERC-7730 fixes it with a JSON descriptor that
tells wallets how to render each function in human terms.

Ledger even ships an LLM *generator* for these files. So the market is about to
flood with **shallow, auto-generated descriptors** — and a *wrong* descriptor
is worse than hex, because it shows the user a confident summary that is false.

**Lucent's product is not generation. It is verification.** The moat is the
hardening + test layer that a generator cannot produce:

- correct **intents** and interpolated summaries, within device screen limits;
- the **native ETH amount** shown on payable calls (generators routinely miss this);
- honest handling of opaque fields (`visible: never`, never silently dropped);
- refusal to fake a unit we can't verify (dynamic-token amounts shown as raw);
- **test vectors** proving the on-device screen for real transactions.

## The pipeline

| Stage | Tool | What it guarantees |
|-------|------|--------------------|
| 0. Discover | `scripts/discover.py` | Finds verified, signable, **uncovered** contracts — the leads |
| 1. Fetch | `scripts/fetch_abi.py` | Verified ABI from **Sourcify** (also the registry's verification requirement) |
| 2. Generate | `erc7730 generate` | A minimal, valid draft to build on |
| 3. **Harden** | manual, expert | Intents, amounts, formats, visibility, security review — *the value-add* |
| 4. Lint | `erc7730 lint` | Schema-valid, within device limits, ABI-consistent |
| 4b. **Audit** | `scripts/audit.py` | Security/quality **grade** — the moat as a tool (see below) |
| 4c. **Semantic verify** | `scripts/semverify.py` | Proves the screen matches what the tx **actually did on-chain** (see below) |
| 5. **Prove** | `scripts/preview.py` + `fetch_tx.py` | Renders the signer screen + emits **real** registry test vectors |
| 6. Package | `scripts/to_submission.py` | Registry-PR form under `dist/` — **gated: refuses to package below Grade B** |
| 7. Submit | PR to registry | Auto-imported into the Ledger Cryptoassets list once merged |
| 8. **Attest** | `scripts/attest.py` | Signed **ERC-8176** (EAS) attestation over the JCS-canonical hash — gated on audit grade + semverify pass |
| 9. **Watch** | `scripts/watch.py` | Cron drift monitor: proxy impl changes, new uncovered functions, stale entries → re-verify / re-attest / revoke |

Stages 8 and 9 are the business model: 8 is what wallets consume when they
weight descriptor trust (attestations, not descriptors, carry the pricing
power), and 9 is the recurring service — a verified descriptor silently rots
the moment its proxy upgrades, and nothing else in the clear-signing stack
re-checks.

Stages 3, 4b and 5 are where quality lives, and where a competitor running only
the LLM generator falls short.

## The audit — the moat, as a tool

`erc7730 lint` answers "is this well-formed?". `scripts/audit.py` answers "would
this screen actually protect a user, or lull them?" — the whole product. It
grades a descriptor on the failures a generator makes:

- **CRITICAL** — a `payable` function that never shows `@.value` (funds leave invisibly), or `tokenAmount` with unknown units.
- **HIGH** — no `intent`, a function that blind-signs despite a descriptor, an address shown as raw hex.
- **MEDIUM/LOW** — device-limit truncation, missing interpolated summaries.

The same raw LLM-generated ENS draft a competitor would submit scores **Grade F
(0/100)**; the Lucent hardened descriptors score **Grade A (100/100)**. The
grade is both an internal gate and a sellable artifact ("audited, Grade A").
`scripts/to_submission.py` runs it and **refuses to package anything below Grade
B** (override with `--force`).

## Semantic verification — the up-a-rung moat

The EF registry CI now gives away schema / selector / Sourcify / ABI checks, so
"ABI-clean descriptor" is becoming table stakes. Those prove a descriptor is
*well-formed*; they can't prove the human summary is *honest*. A descriptor can
pass every structural check and still render a benign screen for a call that
sends assets elsewhere.

`scripts/semverify.py` closes that gap. For each real vector it pulls the mined
**receipt** (the ground truth of what moved), extracts the actual asset
movements and approvals (ETH / ERC-20 / ERC-1155 / ApprovalForAll), and asserts
the screen is faithful — the real recipient/operator is shown, ETH spent is
shown, and the field *labelled* as the recipient equals the address that
actually received the asset.

A worked spoof — `safeTransferFrom` with the **To/From labels swapped**:

| Check | Result |
|-------|--------|
| `erc7730 lint` (= EF CI) | **PASS** — schema-valid, both fields shown |
| `audit.py` (structural) | **Grade A** — structurally perfect |
| `semverify.py` (semantic) | **DIVERGENCE** — "screen labels the sender as recipient; assets went elsewhere" |

Only simulation-backed semantic verification catches it. "Simulation-verified:
the screen matches the chain" is a claim no generator or linter can make, and —
critically — it is the only trust signal an autonomous **agent** can consume,
since an agent has no human to read a warning popup.

**Scope, honestly:** for mined transactions the receipt *is* the realized
execution, so this is exact. For *hypothetical/unmined* calls the same
assertions run against a fork replay (Foundry `cast run`) — not yet wired, since
we verify real vectors. The role check is heuristic on field labels; it catches
recipient hiding and recipient/label spoofing, not every possible semantic lie.

### Discovery output (seed run)

```
🎯 GAP          ENS ETHRegistrarController   7 signable fns, no registry coverage
🎯 GAP          Uniswap UniversalRouter      4 signable fns, no registry coverage
🎯 GAP          Seaport 1.6                  12 signable fns, no registry coverage
🧅 proxy-shell  Aave v3 Pool                 proxy — resolve implementation
✅ covered      Uniswap V3 SwapRouter02      already in registry
```

Point `discover.py` at the scraper infra's output (high-usage uncovered
contracts) to industrialise the top of the funnel.

Proxy leads (🧅) need one extra step — `scripts/resolve_proxy.py` finds the
implementation (EIP-1967 slot or Etherscan `Implementation`), caches its ABI
under the *proxy* address, and the rest of the pipeline proceeds normally.
Verified on Aave v3 Pool (`supply`/`borrow`/`repay`/`withdraw`) and EigenLayer
StrategyManager (`depositIntoStrategy`).

## Quick start

```bash
make setup                                   # venv + tooling (Python 3.12+)
make fetch CHAIN=1 ADDR=0x253553366Da8546fC250F225fe3d25d0C782303b
make all                                     # lint + resolve + preview
```

`make preview` prints the on-device screens and writes
`registry/ens/tests/calldata-ETHRegistrarController.tests.json`.

## Current state

Two ENS descriptors, both **full lint clean against the on-chain ABI**, both
packaged for PR under `dist/registry-pr/ens/`:

| Descriptor | Functions | Real test vectors |
|------------|-----------|-------------------|
| ETHRegistrarController (`0x2535…303b`) | 7 | 8 (`register`/`renew`/`commit`) |
| NameWrapper (`0xD441…6401`) | 26 | 6 (`wrap`/`unwrap`/`setApprovalForAll`/…) |

Both targets **confirmed active** (most recent tx today). One ENS relationship
covers both — plus BulkRenewal, a known one-function gap.

Real test vectors come from `scripts/fetch_tx.py <chain> <address> <descriptor>`
(derives the covered selectors from the descriptor itself, so it works for any
target).

### Before an actual registry PR
- Switch `$schema` to the registry-relative path
  `../../specs/erc7730-v2.schema.json` and drop the inline ABI (registry
  convention references it via `deployments`; kept inline here for offline work).
- A registry PR must be submitted by / on behalf of the entity (ENS) — the
  remaining step is a relationship/authorization one, not a technical one.

## Business model

Protocols pay for descriptors because blind-signing warnings cost them
conversions and support tickets. Lucent sells the *hardened, tested,
security-reviewed* descriptor and its maintenance — the parts an LLM generator
can't be trusted to produce. The discovery→harden→test→submit loop is
repeatable across the long tail of uncovered contracts.
