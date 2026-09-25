# @furlpay/x402-guard

Vendor-neutral facilitator-layer hardening for the [x402](https://www.x402.org) agentic payment protocol. Drop it into any x402 facilitator or merchant to close all five implementation flaw classes from the security literature — with a test suite that reproduces each attack and asserts the defense refuses it.

[![npm](https://img.shields.io/npm/v/@furlpay/x402-guard)](https://www.npmjs.com/package/@furlpay/x402-guard)

Zero dependencies. TypeScript. Works on Base, Solana, or any x402 deployment — independent of which facilitator or SDK you use. Maintained by [FurlPay](https://furlpay.com).

## Status

**Published on npm: `0.2.0`.** The badge above tracks it.

`0.3.0` is prepared but **not released** — it adds the mandate / spend-control
surface (`/redis`, `/mandate`, `/policy`) documented below. Until it is published,
those entry points are available from the repository, not from npm. Anything in
this README describing them describes the next release.

No third-party security audit has been performed on this package. What exists is
the test suite described under [Test suite](#test-suite) and
[Adversarial evaluation](#adversarial-evaluation), including the honest account of
what the default suite cannot catch.

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
npm install @furlpay/x402-guard
```

The package is **scoped**. `npm install x402-guard` — which this README used to
say — resolves to nothing: the unscoped name is not published. Check the `@furlpay/`
prefix before installing anything that claims to be this package.

ESM only (`"type": "module"`); there is no CommonJS entry point, so `require()`
will fail with `ERR_PACKAGE_PATH_NOT_EXPORTED`. Node 18+.

TypeScript consumers should have `@types/node` installed — `Buffer` appears in
the public type surface. It is declared as an optional peer, so npm will tell you
rather than leaving you with an error inside our declarations.

### Entry points

| Import | Contains |
|---|---|
| `@furlpay/x402-guard` | `guardedSettle`, `guardedCharge`, the in-memory stores, `requestBindingHash` |
| `@furlpay/x402-guard/redis` | `RedisNonceStore`, `RedisAllowanceStore`, `RedisMandateSpendStore`, `RedisSettlementCapacityLimiter` |
| `@furlpay/x402-guard/mandate` | `WindowSpec`, `windowKeyFor()`, `evaluateSpendAuthorization()` |
| `@furlpay/x402-guard/policy` | `SettlementAuthorization`, `evaluateMandate()` |

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

### F3: charge an `upto` allowance without overdraft

`guardedCharge` escrows `Vmax` atomically before your handler runs, bills what the handler reports, and refunds the difference. Concurrent requests can never spend more than the allowance holds.

```ts
import { MemoryAllowanceStore, guardedCharge } from "@furlpay/x402-guard";

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
import { SettlementCapacityLimiter } from "@furlpay/x402-guard";

const capacity = new SettlementCapacityLimiter(32); // concurrent settlements you can actually clear

const result = await guardedSettle(req, { nonce, store, capacity, settler });
if (!result.success && result.reason === "settlement_capacity_exhausted") {
  return res.status(429).set("Retry-After", "1").end(); // never serve for free
}
```

### F5: price compute you can't predict

For pay-per-token inference the true cost is unknown at quote time — no static price is safe. `AdaptivePricer` learns the observed actual/estimated ratio (EWMA, clamped) and quotes a `Vmax` with enough headroom to cover it. Compose it with the F3 escrow: free-riders stop leaking once the weight adapts, and honest callers get the overshoot refunded at commit.

```ts
import { AdaptivePricer } from "@furlpay/x402-guard";

const pricer = new AdaptivePricer({ unitPrice: 10n }); // atomic units per output token

const vmax = pricer.quoteMax(estimatedTokens);          // demand this in the 402 challenge
// ... guardedCharge({ vmax, execute }) as above, billing pricer.bill(actualTokens)
pricer.observe(estimatedTokens, actualTokens);          // feed every settlement back
```

### F6: enforce a signed spend mandate at settlement

A mandate is a user-signed grant: this agent, up to this much per payment, up to this much per window, at these sellers, until this date. The facilitator sees every settlement, so it is the place where exceeding one can be made impossible rather than discouraged.

**`reserveSpend()` takes the nonce and the window budget in one Lua script, or neither.**

```ts
import { RedisMandateSpendStore } from "@furlpay/x402-guard/redis";

const spend = new RedisMandateSpendStore(redis);
await spend.openWindow("mnd_1", "2026-09", 50_000_000n);   // $50, atomic

const r = await spend.reserveSpend({
  mandateId: "mnd_1", window: "2026-09", nonce, paymentHash,
  resource: "/v1/summarize", amount: 25_000_000n,
});
if (!r.ok) return refuse(r.reason);   // nonce_taken | budget_exhausted | ...

// settle, then:
await spend.commit(r.reservationId);
```

Two independent calls would leak: `budget reserved -> nonce acquire fails -> budget held forever` throws nothing anywhere, and the user's cap is simply smaller next month. `resource` is part of the reservation identity, so two endpoints at the same seller and price cannot share a slot.

`releaseProvenUnsettled()` has **no timer**. It returns the budget and reopens the nonce only while that nonce is still `pending`, so a late SUCCESS can never hand a window slot back after settlement committed. A frozen budget slot is an availability problem; a wrongly-released one is a double-spend.

### Window semantics are part of the signed mandate

`"$50 per 30d"` is ambiguous, and the ambiguity is not cosmetic: a payer measuring a rolling 30 days and a facilitator measuring a calendar month both enforce $50 and disagree about every payment near a boundary. `WindowSpec` is a tagged union and `windowKeyFor()` is pure, so both sides derive the same bucket from the same mandate.

**The type selects a storage model, not a label.** A decrementing counter cannot express a rolling window — nothing re-credits it as spend ages out of the trailing period — so `rolling` uses a timestamped ledger summed per reservation (`reserveSpendRolling`), while `calendar` and `fixed_period` use a counter.

### The policy evaluator is pure

`evaluateMandate()` has no Redis, no clock and no side effects; window spend is passed in. That makes every denial path testable without a network, and lets the payer-side gate run the identical function so the two layers cannot drift.

All money is integer atomic units compared as `bigint`. Float USD on this boundary fails in both directions — `0.1 + 0.2 > 0.3` is `true`, which refuses a user $0.20 of a $0.30 cap they hold.

```ts
import { evaluateMandate } from "@furlpay/x402-guard/policy";

const verdict = evaluateMandate({ policy, authorization, windowSpentAtomic, approval, nowMs });
// { allowed, reason?, requiresApproval, policyVersion, evaluated }
```

Step-up approval evidence (the signature half) lives in [`@furlpay/agent-trust`](https://github.com/FurlPay/agent-trust), which holds the keys; this package takes `verified` as an input and stays pure.

## Redis at scale

Every atomicity guarantee the in-memory stores make rests on Node being single-threaded — `MemoryNonceStore.acquire` is safe only because no `await` sits between its read and its write. That is real, and it is worth nothing across two workers, two lambdas or two regions, which is how facilitators actually run. **The F2 race the paper reproduces is a race between machines.**

`@furlpay/x402-guard/redis` ships multi-process implementations of the same interfaces:

```ts
import {
  RedisNonceStore, RedisAllowanceStore, RedisSettlementCapacityLimiter,
  fromUpstashRest, // or fromIoRedis / fromNodeRedis
} from "@furlpay/x402-guard";

const redis = fromUpstashRest(process.env.UPSTASH_REDIS_REST_URL!, process.env.UPSTASH_REDIS_REST_TOKEN!);

await guardedSettle(req, {
  nonce,
  store: new RedisNonceStore(redis),
  capacity: new RedisSettlementCapacityLimiter(redis, 32),
  settler,
});
```

**Still zero dependencies.** The client is injected, not imported — anything that can send one Redis command and return its reply works. Adapters for Upstash REST, ioredis and node-redis are included; a fourth is three lines.

Each operation is one round trip whose atomicity is Redis's, not ours — either a natively atomic command (`SET … NX`) or a single Lua script. Three details are load-bearing:

- **`release` is a compare-and-delete, not a `DEL`.** A stray release arriving after a nonce reached `SETTLED` would reopen a spent authorization for replay — exactly the hole the paper documents. A `DEL` cannot tell the two states apart, so the check and the delete must be one script.
- **Capacity is a lease-scored sorted set, not a counter.** An `INCR`/`DECR` counter leaks a slot permanently when a worker dies holding one, and a facilitator that slowly starves itself into refusing everything has inflicted F4 on itself. Holders are entries scored by acquisition time; each reservation first evicts anything past its lease, so a crashed worker's slot is reclaimed automatically.
- **Amounts above 2^53 are refused, not rounded.** Redis Lua numbers are IEEE doubles, so in-script integer arithmetic is exact only below that. For 6-decimal USDC this permits ~9 billion; larger allowances need a bigint-safe backend, and failing loudly is the only honest option.

### What is actually verified

| Suite | Runs the Lua? | Real processes? |
| --- | --- | --- |
| `npm test` → `redis-stores.test.mjs` | ❌ JS twins behind a test double | ❌ one process |
| `npm run test:redis` | ✅ | ❌ one process |
| `npm run mp` | ✅ | ✅ N OS processes |

The default suite runs the stores against a double that interleaves callers between commands and serialises them within a script — Redis's two relevant properties. It catches store-logic and sequencing bugs and **cannot catch a bug in the Lua, because the Lua never runs.** The double keys its stand-ins off a *hash* of each script, so editing the Lua makes the lookup miss and the double throw, rather than quietly testing stale logic.

`npm run mp` is the run to cite. Each worker is a real OS process with its own heap and event loop, sharing nothing but Redis, all aligned to a common start timestamp so their attempts genuinely overlap:

```
8 OS processes x 25 attempts, sharing nothing but Redis

F2  exactly one acquire succeeds fleet-wide  (of 200 concurrent)
F3  reservations granted = allowance / vmax; total charged never exceeds the allowance
F4  slots admitted fleet-wide = the ceiling, while every winner still holds
```

Both Redis suites **skip** when no server is configured, so a green run on a laptop with no Redis is never mistaken for evidence.

## Test suite

`npm test` reproduces every attack and asserts it fails: the F2 20-concurrent-request race (the paper's Base reproduction — exactly one settles, the settler runs exactly once), the F3 overdraft (20 concurrent charges against one allowance — exactly ⌊balance/Vmax⌋ served, balance never negative), the F4 flood (overflow refused *before* delivery, authorizations left intact for retry), and F5 convergence (a 5× compute free-rider is fully covered after adaptation, with the learned ratio clamped at both ends).

The F6 mandate suites (unreleased, in `0.3.0`) cover the same ground for spend
control: ten agents racing one window with exactly four winners and the balance
landing on zero, a budget rejection that must not burn the nonce, a release that
refuses once the nonce has settled, and rolling-window spend ageing out so a
capped window accepts a full-cap payment 31 days later with nobody topping it up.

Counts, so they are not inflated: **117 tests, 112 passing, 0 failing, 5 skipped.**
The five skips are the Redis integration suite, which skips itself when no server
is configured — see the table above. `112/117` is not `117/117`, and a green local
run without Redis is not evidence about the Lua.

## Adversarial evaluation

The test suite above shows the defenses refusing bad traffic. That is necessary but not sufficient evidence: a component that refuses *everything* passes every defense test. `harness/` measures the thing that actually matters — how much service leaks with and without the guard, under the same attack.

```sh
npm run build && npm run harness     # results table
npm run harness:json                 # machine-readable
npm run sweep                        # F5 parameter frontier
```

Both facilitators settle against a shared `SimulatedChain` that consumes an authorization exactly once, mirroring EIP-3009 `authorizationState`. The merchant loop is x402's real shape — `verify()` off-chain, **deliver**, `settle()` on-chain — so every flaw lives in the gap the protocol actually has.

Resource-leakage ratio, seed 42:

| Flaw | Invariant | Unguarded | Guarded |
| --- | --- | --- | --- |
| **F1** Cross-resource substitution | I3 | **75.0%** — 4 siblings served, 1 paid | **0%** (3 refused at admission) |
| **F2** Duplicate-settlement race | I4 | **95.0%** — 20 served, chain consumed 1 | **0%** (19 refused) |
| **F3** Allowance overdraft | I5 | **50.0%** value — drew 1000 on a 500 allowance (**2.00×**) | **0%** (**1.00×**) |
| **F4** Denial of settlement | I2 | **75.0%** — 12 served, 3 settled | **0%** (9 refused) |
| **F5** Hidden-compute pricing | G2 | **68.8%** value — 8,609 of 12,507 units free-ridden | **33.9%** — 4,244 units |

F1–F4 close completely. **F5 does not, and is reported as a mitigation rather than a fix** — the paper itself notes there is no static defense when the true cost is unknowable at quote time. `npm run sweep` maps the frontier:

| Safety margin | Value leakage | Honest over-escrow |
| --- | --- | --- |
| 1.0 | 43.5% | 3.3× |
| 1.25 (default) | 33.9% | 4.1× |
| 2.0 | 11.9% | 6.6× |
| 4.0 | 1.6% | 13.2× |
| 6.0 | **0.0%** | **19.8×** |

Leakage *can* be driven to zero, but only by escrowing ~20× an honest caller's eventual bill. Honest callers are quoted against an average that includes the abusers, so they subsidise the unpredictability — refunded at commit, but locked until then. Choosing a margin is choosing where on that curve to sit; the default sits deliberately near the cheap end.

Two guards keep the numbers honest, and both fail the build if violated:

- **Control** — every unguarded baseline must still be exploitable. If a scenario drifts and the baseline stops leaking, the guarded 0% proves nothing, so the suite fails rather than reporting a comfortable result.
- **Liveness** — the guarded facilitator must still deliver *and* settle honest traffic in every scenario. Without this, `verify() { return false }` would score a perfect zero.

## Scope

This library hardens the state machine around your settler — it does not verify signatures or submit transactions. Wiring these primitives into a live facilitator (Redis-backed stores, the `/verify`/`/settle` endpoints) is deployment work; the FurlPay integration is tracked in [furlpay-x402#3](https://github.com/furlpay/furlpay-x402/issues/3).

## Security

Report vulnerabilities to hello@furlpay.com — please don't open public issues.

## License

MIT
