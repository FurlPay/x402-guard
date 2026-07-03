# @furlpay/x402-guard

Facilitator-layer hardening for the [x402](https://www.x402.org) agentic payment protocol. Drop it into any x402 facilitator or merchant to close the two most damaging implementation flaws from the security literature — with a test suite that reproduces the attacks and proves they're blocked.

[![npm](https://img.shields.io/npm/v/%40furlpay%2Fx402-guard)](https://www.npmjs.com/package/@furlpay/x402-guard)

Zero dependencies. TypeScript. Works on Base, Solana, or any x402 deployment.

## Why

x402 decouples off-chain verification from on-chain settlement to get throughput. That gap is where the money leaks. *Free-Riding the Agentic Web: A Systematic Security Analysis of x402 Payments* ([Ling et al., arXiv:2605.30998](https://arxiv.org/abs/2605.30998)) tested official SDKs and a production deployment and found **resource-leakage ratios up to 100%**. Two of its flaws are facilitator-layer and fixable in library code:

| Flaw | Invariant | What goes wrong | This library |
| --- | --- | --- | --- |
| **F1** Cross-resource substitution | I3 Context Binding | A signature minted for resource A unlocks an equal-priced resource B, because verify() checks value + payee but not the resource ("Pattern 3: blind trust in facilitator"). Found near-universal: 38% of hosts expose same-price sibling clusters. | `requestBindingHash` / `verifyRequestBinding` — commit `H(method \| uri \| body)` and reject mismatches (paper §5.1) |
| **F2** Duplicate-settlement race | I4 Authorization Uniqueness | Concurrent requests with one nonce all clear verification before any settles on-chain; each gets the full service, one pays. Rolling a timed-out nonce back to unused reopens it for replay. | `MemoryNonceStore` + `guardedSettle` — atomic Null→PENDING→SETTLED, never freed on an *unknown* outcome (paper §5.2, §5.4) |

## Install

```sh
npm install @furlpay/x402-guard
```

## Use

Wrap your settler with `guardedSettle`. It runs the F1 binding gate first (no wasted compute on a bad request), then the F2 atomic nonce claim, then your settler — releasing the nonce only when the chain *proves* nothing landed.

```ts
import { guardedSettle, MemoryNonceStore } from "@furlpay/x402-guard";

const store = new MemoryNonceStore(); // swap for a Redis-backed store at scale

const result = await guardedSettle(facilitatorReq, {
  nonce: auth.nonce,
  store,
  // F1: bind the payment to the exact request being served
  binding: { presented: payload.extra?.binding, method: req.method, uri: req.url, body: rawBody },
  // your on-chain settler returns a discriminated outcome
  settler: async (r) => {
    try {
      const tx = await submitOnChain(r);         // confirmed
      return { status: "confirmed", transaction: tx };
    } catch (e) {
      return isProvablyNotLanded(e)
        ? { status: "failed_no_tx" }             // safe to release + retry
        : { status: "unknown" };                 // timeout → keep locked, NEVER replayable
    }
  },
});

if (result.success) deliver(result.transaction);
else refuse(result.reason); // fail closed
```

### The `unknown` outcome is the whole point

A naïve facilitator deletes the nonce when settlement "fails" — but a facilitator timeout is not proof the transaction failed; it may still confirm. Freeing the nonce lets an attacker replay it. `guardedSettle` distinguishes:

- `confirmed` → nonce is **SETTLED** (terminal, never replayable)
- `failed_no_tx` → chain proved nothing landed → nonce **released** for an honest retry
- `unknown` → nonce stays **PENDING** forever unless you reconcile it against the chain

## Redis at scale

`NonceStore` is a 4-method interface. The in-memory default is atomic within one process; for a multi-instance facilitator back `acquire` with `SET key PENDING NX` (or Postgres `INSERT … ON CONFLICT DO NOTHING`) — the atomic check-and-set maps directly.

```ts
class RedisNonceStore implements NonceStore {
  async acquire(nonce: string) {
    return (await redis.set(`x402:${nonce}`, "pending", "NX")) === "OK";
  }
  async markSettled(nonce: string) { await redis.set(`x402:${nonce}`, "settled"); }
  async release(nonce: string) { /* only if still pending */ await redis.del(`x402:${nonce}`); }
  async state(nonce: string) { return (await redis.get(`x402:${nonce}`)) as any; }
}
```

## Test suite

`npm test` reproduces the attacks and asserts they fail — including a 20-concurrent-request race (the paper's Base reproduction) where exactly one request settles and the settler runs exactly once.

## Scope

F1 and F2 are the facilitator/SDK-layer flaws a library can close. The paper's F3 (allowance overdraft), F4 (denial of settlement), and F5 (hidden-compute pricing impossibility) are deployment-layer and dynamic-pricing concerns — tracked in [furlpay-x402](https://github.com/furlpay/furlpay-x402/issues). This library does not verify signatures or submit transactions; it hardens the state machine around your settler.

## Security

Report vulnerabilities to hello@furlpay.com — please don't open public issues.

## License

MIT
