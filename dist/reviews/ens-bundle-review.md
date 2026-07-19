# ERC-7730 descriptor review

| descriptor | verdict | audit | comprehension | danger findings |
|---|---|---|---|---|
| calldata-ETHRegistrarController | review | A | F | 3 |
| calldata-NameWrapper | review | A | F | 4 |
| calldata-BulkRenewal | safe_to_present | A | A | 0 |

## calldata-ETHRegistrarController

- deployment: `eip155:1 0x253553366Da8546fC250F225fe3d25d0C782303b`
- signable functions: 7, covered: 7

**Verdict: review** - a function carries CRITICAL comprehension risk (e.g. operator grant, admin/upgrade authority) — present with a prominent warning

### Lint: pass
- ABI validation: skipped (no ETHERSCAN_API_KEY)

### Screen audit: grade A (100/100)
- no issues

### Comprehension: grade F (49/100), worst tier CRITICAL
- CRITICAL `transferOwnership`
  - screen: You change the control or code of the contract (transferOwnership), affecting everyone who uses it.
  - why: changes WHO controls the contract or WHAT code runs — a consequence far beyond moving your own funds
- MEDIUM `register`
  - screen: You send {Amount paid} to {Owner} now.
  - why: moves value out of your wallet now — verify the recipient is who you expect
- MEDIUM `renew`
  - screen: You send {Amount paid} to a recipient now.
  - why: moves value out of your wallet now — verify the recipient is who you expect
- MEDIUM `withdraw`
  - screen: You send {amount} to a recipient now.
  - why: moves value out of your wallet now — verify the recipient is who you expect

### Danger surface
- HIGH `renounceOwnership`: authority-transfer
  - changes who controls the contract (ownership/admin/role) — affects every user, not just the signer's funds.
- HIGH `transferOwnership`: authority-transfer
  - changes who controls the contract (ownership/admin/role) — affects every user, not just the signer's funds.
- MEDIUM `recoverFunds`: value-sweep-to-arbitrary-address
  - moves held value to a caller-supplied address — verify the destination is not attacker-controlled.

### Semantic verification
- skipped: ETHERSCAN_API_KEY not set; receipts cannot be fetched

## calldata-NameWrapper

- deployment: `eip155:1 0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401`
- signable functions: 26, covered: 26

**Verdict: review** - a function carries CRITICAL comprehension risk (e.g. operator grant, admin/upgrade authority) — present with a prominent warning

### Lint: pass
- ABI validation: skipped (no ETHERSCAN_API_KEY)

### Screen audit: grade A (100/100)
- no issues

### Comprehension: grade F (0/100), worst tier CRITICAL
- CRITICAL `setApprovalForAll`
  - screen: You let {Operator} transfer ANY of your tokens in this contract, at any time, until you revoke it.
  - why: grants operator control over your ENTIRE collection/balance, not a single asset — the approval persists until you revoke it
- CRITICAL `setUpgradeContract`
  - screen: You change the control or code of the contract (setUpgradeContract), affecting everyone who uses it.
  - why: changes WHO controls the contract or WHAT code runs — a consequence far beyond moving your own funds
- CRITICAL `transferOwnership`
  - screen: You change the control or code of the contract (transferOwnership), affecting everyone who uses it.
  - why: changes WHO controls the contract or WHAT code runs — a consequence far beyond moving your own funds
- CRITICAL `upgrade`
  - screen: You change the control or code of the contract (upgrade), affecting everyone who uses it.
  - why: changes WHO controls the contract or WHAT code runs — a consequence far beyond moving your own funds
- HIGH `approve`
  - screen: You let {Approved to} take the NFT with id {Name (token id)} from your wallet, until you revoke it.
  - why: grants control of ONE specific NFT (by token id) to the approved address — they can transfer that NFT out of your wallet until you revoke it
- MEDIUM `safeBatchTransferFrom`
  - screen: You send {Amounts} to {To} now.
  - why: moves value out of your wallet now — verify the recipient is who you expect
- MEDIUM `safeTransferFrom`
  - screen: You send {Amount} to {To} now.
  - why: moves value out of your wallet now — verify the recipient is who you expect

### Danger surface
- HIGH `renounceOwnership`: authority-transfer
  - changes who controls the contract (ownership/admin/role) — affects every user, not just the signer's funds.
- HIGH `setApprovalForAll`: unbounded-delegation
  - grants an operator control over ALL of the signer's assets in this contract until revoked.
- HIGH `transferOwnership`: authority-transfer
  - changes who controls the contract (ownership/admin/role) — affects every user, not just the signer's funds.
- MEDIUM `recoverFunds`: value-sweep-to-arbitrary-address
  - moves held value to a caller-supplied address — verify the destination is not attacker-controlled.

### Semantic verification
- skipped: ETHERSCAN_API_KEY not set; receipts cannot be fetched

## calldata-BulkRenewal

- deployment: `eip155:1 0xfF252725f6122A92551A5FA9a6b6bf10eb0Be035`
- signable functions: 1, covered: 1

**Verdict: safe_to_present** - no critical danger primitive; the screen audits and reads clearly

### Lint: pass
- ABI validation: skipped (no ETHERSCAN_API_KEY)

### Screen audit: grade A (100/100)
- no issues

### Comprehension: grade A (95/100), worst tier MEDIUM
- MEDIUM `renewAll`
  - screen: You send {Amount paid} to a recipient now.
  - why: moves value out of your wallet now — verify the recipient is who you expect

### Danger surface
- no dangerous primitives among 1 signable functions

### Semantic verification
- skipped: ETHERSCAN_API_KEY not set; receipts cannot be fetched

---

Produced by Lucent (audit + comprehension + danger + semantic verification
over ERC-7730 descriptors). Reproduce any section from the repo root:

```
make audit DESC=<descriptor.json>
make comprehend DESC=<descriptor.json>
make danger DESC=<descriptor.json>
make semverify DESC=<descriptor.json>   # needs ETHERSCAN_API_KEY
```
