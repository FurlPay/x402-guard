# x402-guard

![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)
![Solana](https://img.shields.io/badge/Solana-9945FF?style=flat-square&logo=solana&logoColor=white)
![x402](https://img.shields.io/badge/x402-0052FF?style=flat-square)
![Zero dependencies](https://img.shields.io/badge/Zero%20dependencies-4C1?style=flat-square)

Vendor-neutral facilitator-layer hardening for the [x402](https://www.x402.org) agentic payment protocol. Drop it into any x402 facilitator or merchant to close all five implementation flaw classes from the security literature — with a test suite that reproduces each attack and proves it's blocked.

Zero dependencies. TypeScript. Works on Base, Solana, or any x402 deployment — independent of which facilitator or SDK you use. Maintained by [FurlPay](https://furlpay.com).

## Why

x402 decouples off-chain verification from on-chain settlement to get throughput. That gap is where the money leaks. *Free-Riding the Agentic Web: A Systematic Security Analysis of x402 Payments* ([Ling et al., arXiv:2605.30998](https://arxiv.org/abs/2605.30998)) tested official SDKs and a production deployment and found **resource-leakage ratios up to 100%**. This library implements the paper's defenses for all five flaw classes:

| Flaw | Invariant | What goes wrong | This library |
| --- | --- | --- | --- |
| **F1** Cross-resource substitution | I3 Context Binding | A signature minted for resource A unlocks an equal-priced resource B, because verify() checks value + payee but not the resource ("Pattern 3: blind trust in facilitator"). Found near-universal: 38% of hosts expose same-price sibling clusters. | `requestBindingHash` / `verifyRequestBinding` — commit `H(method \| uri \| body)` and reject mismatches (paper §5.1) |
| **F2** Duplicate-settlement race | I4 Authorization Uniqueness | Concurrent requests with one nonce all clear verification before any settles on-chain; each gets the full service, one pays. Rolling a timed-out nonce back to unused reopens it for replay. | `MemoryNonceStore` + `guardedSettle` — atomic Null→PENDING→SETTLED, never freed on an *unknown* outcome (paper §5.2, §5.4) |
| **F3** Allowance overdraft (upto scheme) | I5 Balance Sufficiency | N concurrent requests against one signed allowance each read the full remaining balance before any deducts — total spend N × Vmax against a balance of Vmax. | `MemoryAllowanceStore` + `guardedCharge` — pessimistic reserve-commit: escrow Vmax atomically *before* execution, bill actual, refund the rest (paper §5.3) |
| **F4** Denial of settlement | I2 Settlement Guarantee | An attacker floods the facilitator with slow settlements; the server has already delivered when honest settlements time out — service rendered, never paid. | `SettlementCapacityLimiter` in `guardedSettle` — reserve settlement capacity *before* serving; overflow gets 429, not free service (paper §5.4) |
| **F5** Hidden-compute pricing | G2 dynamic billing | Pay-per-token cost is unknowable at quote time; adversarial prompts maximize compute per fixed quote and free-ride the difference. | `AdaptivePricer` — EWMA-learned billing weight; quote `estimate × ratio × margin` as the Vmax you escrow, refund honest callers at commit (paper §5.5) |

## Install

```sh
npm install x402-guard
```

## Use

Wrap your settler with `guardedSettle`. It runs the F1 binding gate first (no wasted compute on a bad request), then the F2 atomic nonce claim, then your settler — releasing the nonce only when the chain *proves* nothing landed.

```ts
import { guardedSettle, MemoryNonceStore } from "x402-guard";

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

### F3: charge an `upto` allowance without overdraft

`guardedCharge` escrows `Vmax` atomically before your handler runs, bills what the handler reports, and refunds the difference. Concurrent requests can never spend more than the allowance holds.

```ts
import { MemoryAllowanceStore, guardedCharge } from "x402-guard";

const allowances = new MemoryAllowanceStore();
allowances.create(auth.allowanceId, auth.totalAuthorized); // on receipt of the signed upto authorization

const res = await guardedCharge({
  allowanceId: auth.allowanceId,
  vmax: quotedMax,
  store: allowances,
  execute: async () => {
    const output = await runInference(prompt);
    return { actual: meter(output), value: output }; // billed amount is clamped to vmax
  },
});

if (res.success) deliver(res.value); // res.charged ≤ vmax; remainder refunded
else refuse(res.reason);             // "allowance_exhausted" | "execution_failed"
```

### F4: fail closed under settlement pressure

Pass a `SettlementCapacityLimiter` to `guardedSettle` and capacity is reserved *before* the nonce is claimed or your settler runs. When the settlement path is saturated (or under attack), overflow requests get `settlement_capacity_exhausted` — map it to HTTP 429. The refused authorization is untouched, so an honest client simply retries.

```ts
import { SettlementCapacityLimiter } from "x402-guard";

const capacity = new SettlementCapacityLimiter(32); // concurrent settlements you can actually clear

const result = await guardedSettle(req, { nonce, store, capacity, settler });
if (!result.success && result.reason === "settlement_capacity_exhausted") {
  return res.status(429).set("Retry-After", "1").end(); // never serve for free
}
```

### F5: price compute you can't predict

For pay-per-token inference the true cost is unknown at quote time — no static price is safe. `AdaptivePricer` learns the observed actual/estimated ratio (EWMA, clamped) and quotes a `Vmax` with enough headroom to cover it. Compose it with the F3 escrow: free-riders stop leaking once the weight adapts, and honest callers get the overshoot refunded at commit.

```ts
import { AdaptivePricer } from "x402-guard";

const pricer = new AdaptivePricer({ unitPrice: 10n }); // atomic units per output token

const vmax = pricer.quoteMax(estimatedTokens);          // demand this in the 402 challenge
// ... guardedCharge({ vmax, execute }) as above, billing pricer.bill(actualTokens)
pricer.observe(estimatedTokens, actualTokens);          // feed every settlement back
```

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

`npm test` reproduces every attack and asserts it fails: the F2 20-concurrent-request race (the paper's Base reproduction — exactly one settles, the settler runs exactly once), the F3 overdraft (20 concurrent charges against one allowance — exactly ⌊balance/Vmax⌋ served, balance never negative), the F4 flood (overflow refused *before* delivery, authorizations left intact for retry), and F5 convergence (a 5× compute free-rider is fully covered after adaptation, with the learned ratio clamped at both ends).

## Scope

This library hardens the state machine around your settler — it does not verify signatures or submit transactions. Wiring these primitives into a live facilitator (Redis-backed stores, the `/verify`/`/settle` endpoints) is deployment work; the FurlPay integration is tracked in [furlpay-x402#3](https://github.com/furlpay/furlpay-x402/issues/3).

## Security

Report vulnerabilities to hello@furlpay.com — please don't open public issues.

## License

MIT
