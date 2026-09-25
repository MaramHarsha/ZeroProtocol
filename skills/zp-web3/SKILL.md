---
name: zp-web3
description: ZeroProtocol hunter for smart-contract and web3 bounty targets. Use when a contract address, protocol, bridge or dApp is in scope, when reviewing Solidity for reentrancy, access control, oracle manipulation or arithmetic flaws, when building a fork-based proof of concept with Foundry, or when assessing an Immunefi-style program. Proofs run on a local fork, never on mainnet - an on-chain exploit is theft, not a demonstration.
---

# zp-web3 - prove it on a fork

**Phase:** 5 | **Gate:** reading verified source and simulating on a **local fork** touches no
target and needs no gate. Any interaction with a live deployment, testnet or mainnet, is active:
`zp-scope check` exit 0, and the program's explicit permission.

**The rule that defines web3 bounty work:** the PoC runs against a local fork of chain state. An
exploit executed on mainnet moves real funds - that is theft regardless of intent, it is
irreversible, and no bounty program treats it as a demonstration. Immunefi and every serious
program require fork-based PoCs for exactly this reason.

Testnets are also not a free-for-all: use them only if the program names them.

---

## Procedure

**1. Get the verified source and pin the state.**

```bash
export ETHERSCAN_API_KEY=…
cast etherscan-source -d src/ 0xCONTRACT --chain mainnet    # verified source, if published
cast code 0xCONTRACT | head -c 120                           # bytecode if unverified
cast storage 0xCONTRACT 0                                    # a storage slot
BLOCK=$(cast block-number)
echo "pinned at block $BLOCK"
```

Unverified bytecode means decompilation, a much longer job, and usually a lower expected value
unless the program specifically wants it.

**2. Map the contract before reading it line by line.**

```bash
forge inspect src/Target.sol:Target methods
grep -nE 'function .*(external|public)' src/*.sol
grep -nE '\b(onlyOwner|onlyRole|requiresAuth|modifier )' src/*.sol
grep -nE 'delegatecall|call\{value|selfdestruct|assembly|create2' src/*.sol
grep -nE 'initialize\(|_disableInitializers|upgradeTo|_authorizeUpgrade' src/*.sol
```

Answer four questions first: who can call what, where does value move, what is upgradeable, and
what external data is trusted.

**3. Work the class list against those answers.**

| Class | What to look for | Severity when real |
|---|---|---|
| **Reentrancy** | state written *after* an external call; missing `nonReentrant`; ERC-777/ERC-721 hooks; read-only reentrancy against a price view | Critical |
| **Access control** | `external` function with no modifier; `initialize()` callable twice; ownership transfer with no two-step; a role granted in a constructor that is not the proxy | Critical |
| **Oracle manipulation** | spot price from `getReserves()`/`slot0`; no TWAP; a single-source oracle; no staleness or deviation check | Critical |
| **Arithmetic / precision** | division before multiplication; rounding that favours the caller; `unchecked` blocks; decimal mismatch between tokens; share-price inflation on an empty vault (the "first depositor" bug) | High to Critical |
| **delegatecall / proxy** | uninitialised implementation; storage-layout collision on upgrade; `delegatecall` to user-supplied target | Critical |
| **Signature handling** | missing nonce (replay); no `chainId` in the digest (cross-chain replay); `ecrecover` without the `v` range check; malleability; no `EIP-712` domain separator | High to Critical |
| **Slippage / MEV** | `amountOutMin: 0`; no deadline; swap on behalf of a user with attacker-set parameters | High |
| **Flash-loan composability** | any invariant that assumes balances cannot change within a transaction | Critical |
| **Token assumptions** | fee-on-transfer, rebasing, non-standard decimals, ERC-20 returning false instead of reverting, double-entrypoint tokens | High |
| **Bridges** | message replay, unvalidated source chain/sender, missing finality wait, mint without matching burn | Critical |
| **Gas / DoS** | unbounded loop over a user-growable array; a `push` payment that a reverting receiver can block | Medium to High |

Run the static tools, then read the code - they find the shape, not the economics:

```bash
slither . --exclude-informational
forge test -vvv
```

**4. Build the PoC on a fork. This is the deliverable.**

```bash
forge init poc && cd poc
cat > test/Poc.t.sol <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";

interface ITarget { function deposit(uint256) external; function withdraw(uint256) external; }

contract Poc is Test {
    ITarget target = ITarget(0xCONTRACT);

    function setUp() public {
        // pin the block so the PoC is reproducible forever
        vm.createSelectFork(vm.envString("RPC_URL"), 20_000_000);
    }

    function test_exploit() public {
        uint256 before = address(this).balance;
        // … the minimum sequence that violates the invariant …
        assertGt(address(this).balance, before, "value extracted");
        emit log_named_uint("profit (wei)", address(this).balance - before);
    }
}
SOL
RPC_URL=https://eth-mainnet.g.alchemy.com/v2/KEY forge test -vvv --match-test test_exploit
```

A good PoC: pins the block, states the invariant it breaks, prints the quantified loss, and is the
**minimum** sequence that does it. Quantified loss is what sets the payout on Immunefi-style
programs, so compute it - funds at risk, not just "it is possible".

**5. Severity, in the terms these programs use.**

```
Critical   direct theft or permanent freezing of principal; unauthorised minting; governance takeover
High       theft of unclaimed yield/fees; temporary freezing; griefing with real cost
Medium     contract fails under specific conditions; recoverable value loss
Low        informational, gas, best-practice
```

State explicitly: funds at risk, preconditions (attacker capital, a particular market state, a
specific block), and whether it is atomic or needs several transactions.

---

## Confirm or kill

| Evidence | Verdict |
|---|---|
| fork test extracts value or breaks the invariant, with a pinned block | **confirmed.** Severity by loss |
| the flaw needs privileged access the owner already has | usually killed - "owner can rug" is by design in most programs. Read the program's stance |
| reachable only with an unrealistic market state | Medium at best. State the precondition honestly |
| reentrancy path exists but `nonReentrant` is present on every entry | killed |
| unbounded loop that only the caller can grow | killed - self-griefing |
| precision loss of a few wei | killed unless it compounds into real value |
| oracle uses a TWAP over a meaningful window | killed unless you can move the TWAP within it |
| the contract is not the one in scope | back to `zp-scope` - protocols deploy many contracts, only some are in scope |
| it is already reported or disclosed | killed. Search the program's past reports, audits and the code's own comments |
| no PoC, only reasoning | **not submittable** to most web3 programs. Build the fork test |

**Check the existing audits first.** Most protocols publish them, and the finding you just made
is often already listed as acknowledged or accepted-risk. Reading the audit is the cheapest
duplicate-check in this skill.

---

## High-value patterns

- **Read-only reentrancy** against a price or share view used by another protocol - a persistently productive class.
- **First-depositor / empty-vault share inflation** in ERC-4626-style vaults.
- **Cross-chain signature replay** - no `chainId` in the digest.
- **Uninitialised proxy implementation** - anyone calls `initialize()` and owns it.
- **Bridge message validation** - unchecked source sender or chain id.
- **Single-source spot oracle** on a thin pool, with a flash loan available.
- **Fee-on-transfer or rebasing tokens** in a protocol that assumes balance deltas equal amounts.
- **Governance timelock bypass** or a quorum computed from a manipulable snapshot.

---

## Pitfalls

- **Executing on mainnet.** Theft. Irreversible. Never.
- **Executing on a testnet the program did not name.**
- **Submitting without a PoC.** Most web3 programs reject reasoning-only reports.
- **Not pinning the fork block** - the PoC stops reproducing and the report dies in triage.
- **Reporting owner privileges as a vulnerability** without reading the program's centralisation stance.
- **Not reading the published audits** and filing a known, accepted issue.
- **Ignoring which contracts are in scope.** Protocols have dozens of deployments.
- **Overstating loss.** Compute it from the fork; triagers will.
- **Front-running someone else's live exploit** "to prove it" - that is participating in the attack.
- **Testing on a fork of a chain the program does not cover** (an L2 deployment, a different fork of the protocol).

---

## Hand off to

Confirmed -> `zp-triage`, `zp-report` with the fork test attached and the loss quantified.
The dApp front end, its API and its RPC handling -> the normal web pipeline (`zp-api`, `zp-xss`,
`zp-authz`) - front-end bugs on a web3 target are often in scope and far less contested.
Keys or mnemonics found in the front end -> `zp-js-secrets`, and report immediately.
