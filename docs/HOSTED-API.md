# Lucent hosted preflight API

## Product boundary

Lucent answers one bounded question:

> Given this unsigned EVM call and this ERC-7730 descriptor, is the selected
> call clear enough to present to a signer, and what deserves explicit review?

It does **not** answer whether the transaction is profitable, whether the
counterparty is honest, or whether runtime execution is safe. Keeping that
boundary explicit prevents a static ABI heuristic from becoming a false
security guarantee.

## Request path

```text
wallet / signing agent
        |
        | POST /v1/preflight
        v
body + structural limits
        |
auth + idempotency ---- reject key/quota/replay conflicts
        |
local call validation - reject before external work
        |
x402 verify ----------- validate fixed Base-USDC terms, do not settle yet
        |
finalized source ------ direct runtime code + exact Sourcify match
        |
deployment binding ---- reject mismatch
        |
unique selector ------- reject missing/collision
        |
strict calldata decode - reject malformed payload
        |
one-function slice
   |        |        |
 audit  comprehend  danger
   +--------+--------+
            |
severity-driven policy
            |
response constructed -- enforce cache/header bounds
            |
x402 settle ----------- emit PAYMENT-RESPONSE receipt
            |
idempotency commit ---- exact business-result replay
            |
call + assessment fingerprinted present / review / block response
```

Open local mode performs no RPC calls. When verified-source mode is required,
Lucent uses only code-owned Ethereum/Base RPC endpoints and Sourcify; request
data cannot choose an outbound URL. The process never writes files, launches
subprocesses, simulates execution, or holds attestation keys.

## `POST /v1/preflight`

```json
{
  "transaction": {
    "chain_id": 1,
    "from": "0x1111111111111111111111111111111111111111",
    "to": "0x253553366Da8546fC250F225fe3d25d0C782303b",
    "data": "0x12345678...",
    "value": "0x0"
  },
  "descriptor": {
    "context": {
      "contract": {
        "abi": [],
        "deployments": []
      }
    },
    "display": {"formats": {}}
  }
}
```

V1 request requirements:

- `chain_id` is a positive bounded integer.
- `from` is exactly one 20-byte sender address and binds `msg.sender`.
- `to` is exactly one 20-byte EVM address.
- `data` is even-length hexadecimal, includes a four-byte selector, and is at
  most 128 KiB.
- `value` is a non-negative integer or canonical hexadecimal quantity bounded
  to `uint256`.
- An inline ABI is required, and an exact descriptor deployment must match
  `chain_id + to`.
- The selector must resolve to exactly one ABI signature and the remaining
  calldata must decode strictly.
- Requests are capped at 832 KiB; descriptors, ABI entries, nesting, and
  individual strings have their own lower limits.

The call fingerprint binds the supported unsigned-call fields and the complete
descriptor. A separate assessment fingerprint binds the complete decision,
policy, and verified-source evidence, so a new finalized block or code hash is
never confused with an earlier assessment. Neither digest claims to identify a
full unsigned transaction: nonce, gas, fee fields, access lists, and blob fields
are outside this API and are rejected rather than silently ignored.

## Deterministic V1 presentation profile

ERC-7730 supports richer display behavior than Lucent can prove without a full
wallet renderer and trusted reference resolver. V1 therefore clears only this
portable subset:

- at most 16 uniquely-pathed, uniquely-labelled visible fields per function;
- scalar ABI arguments, each with one exact, universally visible `#.path`;
- `addressName` for addresses with no formatter parameters;
- `amount` or `duration` for compatible integers, and `raw` for other
  non-address scalars;
- `@.from` and `@.to` as `addressName`, and `@.value` as `amount`;
- exact role labels and policy-owned intent templates for classified transfer
  and approval actions;
- strings no longer than 256 characters and bytes that fit the 64-byte preview.

V1 blocks tuples, arrays, conditional/hidden fields, parent-only container
rendering, raw addresses, formatter parameters, and reference-dependent
`calldata`, `tokenAmount`, `nftName`, `date`, `unit`, and `enum` formats. This is
a Lucent hosted-service profile, not a claim that those constructs are invalid
ERC-7730. Supporting them requires a renderer that can prove every value shown
on the target device and a resolver that binds every reference.

## Policy

The gate is driven by the selected function's finding severities. Aggregate
letter grades remain explanatory because they are biased by contract size.

| Gate | Conditions |
|---|---|
| `block` | Missing format; nonpayable value; unbound/unsupported presentation; audit CRITICAL; danger CRITICAL |
| `review` | Comprehension CRITICAL/HIGH; audit HIGH/MEDIUM; danger HIGH/MEDIUM |
| `safe_to_present` | None of the conditions above |

Actual calldata can elevate a result. For example,
`approve(spender, 2**256 - 1)` returns `review` with the stable code
`UNLIMITED_APPROVAL`; the same ABI alone cannot establish that fact.

Every response includes:

- the normalized chain, sender, destination, selector, signature, value, and bounded
  decoded arguments;
- a SHA-256 call fingerprint binding the supported call fields and descriptor;
- a SHA-256 assessment fingerprint binding the decision, policy, and provenance;
- the individual audit, comprehension, and danger evidence;
- assurance flags describing what was and was not verified;
- limitations stating which provenance layer ran and that no runtime simulation
  ran.

The consequence sentence is generated from the selected ABI and decoded call;
descriptor-authored prose is excluded. For classified actions, Lucent also
requires the descriptor headline/template to match a small policy-owned grammar
so a phrase such as “Send 0 tokens” cannot clear a call sending 42. Applications
must render `presentation.sentence_template` and decoded values as untrusted UI
data, never concatenate calldata or descriptor text into model instructions.

`descriptor_semantics_verified=false` remains explicit because display rules
and prose are caller supplied. In verified-source mode, the ABI and code obtain
separate provenance fields; bytecode provenance does not make arbitrary UI copy
truthful.

## Verified-source mode

Set `LUCENT_VERIFIED_SOURCE_MODE=required` to replace the inline ABI used for
decoding/policy with a server-resolved ABI. The inline ABI is still required for
fast local validation, but it is never the authoritative function surface in
the final result.

The resolver:

- permits only Ethereum mainnet (`1`) and Base mainnet (`8453`);
- checks the allowlisted RPC's own chain id;
- pins a finalized block number and hash, then reconfirms the block after all
  reads;
- hashes target runtime bytecode and detects bounded EIP-1967 evidence;
- rejects every proxy-backed result in hosted V1 because a populated storage
  slot alone does not prove runtime delegation or current upgrade state;
- rejects direct-looking runtime that contains executable `DELEGATECALL` or
  legacy `CALLCODE` dispatch outside compiler metadata;
- fetches Sourcify v2 for the resolved runtime identity;
- releases the ABI only when Sourcify's recorded on-chain runtime bytecode is
  byte-for-byte identical to the finalized RPC bytecode.

Successful direct-deployment responses include the finalized block, target code
hash, Sourcify match, and ABI hash under
`assurance.verified_source`. The full ABI is deliberately not duplicated in the
response. A single-flight cache coalesces identical concurrent lookups, retains
at most 64 successes under a 16 MiB aggregate byte budget, and applies only a
two-second bounded backoff to failures. The default public RPC endpoints are
appropriate for a small beta, not high-volume production—replace them with
reviewed code-owned provider endpoints in the deployment build before scaling.

All proxy-backed contracts—including EIP-1967 deployments—fail closed with
`PROXY_SEMANTICS_UNVERIFIED`. Proxy support is deferred until Lucent can prove
dispatch behavior and compare execution-time upgrade state.

## Authentication, quota, and idempotency

`LUCENT_ACCESS_MODE` accepts:

- `disabled` (default; health only, readiness/preflight return 503);
- `open` (explicit loopback-only local development);
- `api_key`;
- `x402`;
- `api_key_or_x402`.

API-key clients send `X-API-Key` and `Idempotency-Key`. Configure tenants as a
bounded JSON array containing hashes—not plaintext secrets:

```bash
python - <<'PY'
from getpass import getpass
from lucent.access import hash_api_key
print(hash_api_key(getpass("New Lucent API key: ")))
PY

export LUCENT_ACCESS_MODE=api_key
export LUCENT_VERIFIED_SOURCE_MODE=required
export LUCENT_TENANTS_JSON='[
  {
    "tenant_id": "wallet-co",
    "api_key_hash": "sha256:REPLACE_WITH_64_HEX_DIGEST",
    "capacity": 60,
    "refill_tokens_per_second": 1.0
  }
]'
```

Authentication errors are indistinguishable to prevent tenant enumeration.
Accepted requests return `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and
`X-RateLimit-Reset`. Idempotency keys are tenant-scoped and never retained in
plaintext. Every authenticated HTTP attempt consumes quota, including result
replays. Equivalent completed API-key requests replay for five minutes; paid
results and authorization claims remain paired for fifteen minutes. Reusing a
key for a different canonical request returns 409.

Quota and idempotency state are process-local and byte-bounded. Unexpired paid
results and authorization claims are never evicted to admit newer work; Lucent
returns a capacity error before payment work instead. Run the shipped
single-worker container with explicit access configuration for a beta. Before
multiple replicas/workers, replace all state stores with one atomic shared backend;
otherwise quotas fragment and concurrent requests may reach settlement from
different processes.

## Base-USDC x402 v2

Paid modes use the official x402 v2 models and headers:
`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, and `PAYMENT-RESPONSE`. Terms are
server-owned and fixed to Base mainnet (`eip155:8453`) and native USDC
`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` using exact EIP-3009 settlement.
Clients cannot choose the network, asset, payee, price, resource URL, or
facilitator.

```bash
export LUCENT_ACCESS_MODE=x402             # or api_key_or_x402
export LUCENT_VERIFIED_SOURCE_MODE=required
export LUCENT_X402_ENABLED=true
export LUCENT_X402_PAY_TO=0xYOUR_20_BYTE_BASE_ADDRESS
export LUCENT_X402_AMOUNT=10000             # atomic USDC: 0.01 USDC
export LUCENT_X402_RESOURCE_URL=https://api.example/v1/preflight
export LUCENT_X402_FACILITATOR_URL=https://YOUR_ALLOWLISTED_FACILITATOR/x402
export LUCENT_X402_ALLOWED_FACILITATOR_HOSTS=payments.example
# Optional for facilitators using a static bearer credential:
export LUCENT_X402_FACILITATOR_BEARER_TOKEN='...'
```

The price is a positive integer in six-decimal USDC atomic units and has a
100-USDC startup safety ceiling. Facilitator URLs must be canonical HTTPS, use
port 443, follow no redirects, and match a built-in or explicitly configured
server-side hostname allowlist. Responses and timeouts are bounded; upstream
error bodies and credentials are never exposed.

Flow and charging semantics:

1. A request without payment receives 402 plus `PAYMENT-REQUIRED`.
2. The retry must include `PAYMENT-SIGNATURE` and `Idempotency-Key`; its
   official required `payment-identifier` extension must contain the same id.
3. Lucent validates the call locally, then asks the facilitator to verify the
   payment proof. The signed authorization must already be active and expire
   within the server-owned 300-second window.
4. Lucent resolves provenance and constructs the complete bounded result.
5. Only then does it settle; success returns `PAYMENT-RESPONSE`.
6. An equivalent retry presenting the exact original payment proof replays the
   result and receipt without another verify or settlement call. The proof hash
   is retained only inside the idempotency cache and is never returned as an
   HTTP header.
7. A second wrapper around the same signed EIP-3009 authorization is rejected,
   even if it uses a new payment identifier and idempotency key.

Malformed calls, mismatched payment identifiers, failed source resolution, and
internal analysis failures are never settled. Once settlement is submitted, an
unavailable or malformed facilitator response is terminal for that
authorization: Lucent retains a tombstone and requires reconciliation instead
of advertising an unsafe retry. EIP-3009's authorization nonce remains the
chain-level final defense against settlement replay; separate request and
authorization ledgers enforce the local payment lifecycle.

### Stable decision and input codes

HTTP 200 verdict codes are `PRESENTATION_CLEAR`,
`MISSING_CLEAR_SIGNING_FORMAT`, `PRESENTATION_CRITICAL`, `PRESENTATION_UNBOUND`,
`NONPAYABLE_WITH_VALUE`, `DANGER_CRITICAL`, `DANGER_REVIEW`,
`COMPREHENSION_REVIEW`, `UNLIMITED_APPROVAL`, and `PRESENTATION_REVIEW`.

Problem responses use stable input/access/payment codes including `MALFORMED_JSON`,
`REQUEST_TOO_LARGE`, `REQUEST_VALIDATION_FAILED`, `INVALID_TRANSACTION`,
`UNKNOWN_REQUEST_FIELD`, `UNKNOWN_TRANSACTION_FIELD`, `INVALID_CALLDATA`,
`CALLDATA_TOO_LARGE`, `INVALID_VALUE`, `INVALID_DESCRIPTOR`,
`INLINE_ABI_REQUIRED`, `DEPLOYMENT_MISMATCH`, `UNKNOWN_SELECTOR`,
`SELECTOR_COLLISION`, `CALLDATA_DECODE_FAILED`, `CALLDATA_NOT_CANONICAL`,
`UNBINDABLE_ABI`, `AUTHENTICATION_FAILED`, `QUOTA_EXCEEDED`,
`IDEMPOTENCY_CONFLICT`, `PAYMENT_REQUIRED`, `PAYMENT_NOT_VERIFIED`,
`PAYMENT_NOT_SETTLED`, `PAYMENT_AUTHORIZATION_ALREADY_USED`,
`PAYMENT_AUTHORIZATION_WINDOW_MISMATCH`,
`SOURCE_NOT_VERIFIED`, `PROXY_SEMANTICS_UNVERIFIED`,
`UNSUPPORTED_DISPATCH`, `SERVICE_NOT_CONFIGURED`, and `UPSTREAM_UNAVAILABLE`.
Clients should branch on `code`, never on human text.

## HTTP behavior

- A `block` verdict is a completed analysis and returns HTTP 200.
- Invalid JSON returns 400.
- Missing/invalid API keys return 401; x402 challenges and rejected proofs
  return 402.
- Idempotency conflicts return 409; quota exhaustion returns 429.
- Oversized input returns 413.
- Invalid descriptor/transaction structure, deployment mismatch, unknown or
  colliding selectors, and decode failures return 422 with stable codes.
- Internal failures return a redacted 500 response without exception text,
  local paths, URLs, or credentials.
- Facilitator failures return 502; temporary verified-source/access dependency
  failures return 503 with `Retry-After`.
- Responses use `Cache-Control: no-store`, security headers, and an
  `X-Request-ID`. Request bodies and calldata are never logged.

## Deployment

Build the non-root, read-only-compatible container:

```bash
docker build -f Dockerfile.api -t lucent-api:0.2.1 .
docker run --rm --read-only -p 8780:8780 \
  -e LUCENT_ACCESS_MODE=api_key \
  -e LUCENT_TENANTS_JSON='[...]' \
  lucent-api:0.2.1
```

The shipped image intentionally exposes only `/v1/preflight`, health/readiness,
and API documentation—authoring, simulation, and attestation routes are not
hosted. With no explicit access configuration, `/ready` and `/v1/preflight`
return `503 SERVICE_NOT_CONFIGURED`. `/ready` otherwise reports the active
access/source modes and explicitly names the process-local state backend. Never
place attester keys in this container.

## Deferred assurance layers

These require separate trust and resource boundaries:

1. Isolated trace/state-diff simulation workers with allowlisted RPC providers,
   egress policy, CPU/memory/process limits, and hard deadlines.
2. A key-isolated attestation service that signs only policy-complete evidence.
3. A shared atomic quota/idempotency backend for multi-worker or multi-region
   deployment.
4. Additional reviewed proxy families and production private RPC capacity.

At scale, revisit request coalescing and a cache keyed by chain, address,
finalized block, code hash, implementation/facets, ABI hash, and policy version.
