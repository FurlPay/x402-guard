import { test } from "node:test";
import assert from "node:assert/strict";
import {
  RedisNonceStore,
  RedisAllowanceStore,
  RedisSettlementCapacityLimiter,
  guardedSettle,
  guardedCharge,
  MAX_SAFE_AMOUNT,
} from "../dist/index.js";
import { FakeRedis } from "./fake-redis.mjs";

// ---------------------------------------------------------------------------
// The Redis stores, exercised against a double that interleaves callers between
// commands and serialises them within a script — Redis's two relevant
// properties. See test/fake-redis.mjs for what this does and does not prove;
// the Lua itself is only executed by `npm run test:redis`.
//
// The point of every test here is CROSS-PROCESS behaviour. The in-memory stores
// pass their equivalents for free because Node never preempts them mid-function;
// these stores have a real network round trip inside every operation, which is
// where a naive implementation loses its atomicity.
// ---------------------------------------------------------------------------

const client = () => new FakeRedis();

// ── F2: nonce linearization ────────────────────────────────────────────────

test("redis nonce: exactly one of 50 concurrent acquires wins", async () => {
  const store = new RedisNonceStore(client());
  const results = await Promise.all(Array.from({ length: 50 }, () => store.acquire("n1")));
  assert.equal(results.filter(Boolean).length, 1);
  assert.equal(await store.state("n1"), "pending");
});

test("redis nonce: release is compare-and-delete — a SETTLED nonce is never reopened", async () => {
  const store = new RedisNonceStore(client());
  assert.equal(await store.acquire("n2"), true);
  await store.markSettled("n2");

  // A late/duplicated release must not resurrect a spent authorization. A plain
  // DEL here would reopen it for replay, which is the exact hole in the paper.
  await store.release("n2");
  assert.equal(await store.state("n2"), "settled");
  assert.equal(await store.acquire("n2"), false, "a settled nonce must stay unacquirable");
});

test("redis nonce: release of a PENDING nonce frees it for an honest retry", async () => {
  const store = new RedisNonceStore(client());
  await store.acquire("n3");
  await store.release("n3");
  assert.equal(await store.state("n3"), undefined);
  assert.equal(await store.acquire("n3"), true);
});

test("redis nonce: guardedSettle end-to-end — 20 concurrent, settler runs once", async () => {
  const store = new RedisNonceStore(client());
  let runs = 0;
  const settler = async () => {
    runs++;
    await new Promise((r) => setTimeout(r, 5));
    return { status: "confirmed", transaction: "0xok" };
  };

  const results = await Promise.all(
    Array.from({ length: 20 }, () => guardedSettle({}, { nonce: "shared", store, settler }))
  );
  assert.equal(results.filter((r) => r.success).length, 1);
  assert.equal(runs, 1, "the settler must execute exactly once across all workers");
});

// ── F3: allowance reserve-commit ───────────────────────────────────────────

test("redis allowance: 10 concurrent reserves of 100 against 500 — exactly 5 win", async () => {
  const store = new RedisAllowanceStore(client());
  await store.create("a1", 500n);

  const ids = await Promise.all(Array.from({ length: 10 }, () => store.reserve("a1", 100n)));
  assert.equal(ids.filter(Boolean).length, 5, "the escrow is a hard ceiling under concurrency");
  assert.equal(await store.remaining("a1"), 0n, "balance must never go negative");
});

test("redis allowance: commit bills the actual amount and refunds the remainder", async () => {
  const store = new RedisAllowanceStore(client());
  await store.create("a2", 1000n);

  const id = await store.reserve("a2", 400n);
  assert.equal(await store.remaining("a2"), 600n, "escrow leaves the balance immediately");

  const charged = await store.commit(id, 150n);
  assert.equal(charged, 150n);
  assert.equal(await store.remaining("a2"), 850n, "250 of the escrow is refunded");
});

test("redis allowance: over-reporting is clamped to the escrow, and commit is idempotent", async () => {
  const store = new RedisAllowanceStore(client());
  await store.create("a3", 500n);
  const id = await store.reserve("a3", 100n);

  assert.equal(await store.commit(id, 10_000n), 100n, "never bill beyond what was escrowed");
  assert.equal(await store.commit(id, 100n), 0n, "a second commit is a no-op");
  assert.equal(await store.remaining("a3"), 400n);
});

test("redis allowance: release refunds the full escrow", async () => {
  const store = new RedisAllowanceStore(client());
  await store.create("a4", 300n);
  const id = await store.reserve("a4", 300n);
  assert.equal(await store.remaining("a4"), 0n);
  await store.release(id);
  assert.equal(await store.remaining("a4"), 300n);
});

test("redis allowance: guardedCharge works against the redis store", async () => {
  const store = new RedisAllowanceStore(client());
  await store.create("a5", 1000n);

  const res = await guardedCharge({
    allowanceId: "a5",
    vmax: 200n,
    store,
    execute: async () => ({ actual: 75n, value: "inference" }),
  });
  assert.equal(res.success, true);
  assert.equal(res.charged, 75n);
  assert.equal(await store.remaining("a5"), 925n);
});

test("redis allowance: an unknown allowance reserves nothing", async () => {
  const store = new RedisAllowanceStore(client());
  assert.equal(await store.reserve("nope", 1n), null);
});

test("redis allowance: amounts above the Lua exact-integer ceiling are refused, not rounded", async () => {
  const store = new RedisAllowanceStore(client());
  await assert.rejects(() => store.create("big", MAX_SAFE_AMOUNT + 1n), RangeError);
});

// ── F4: settlement capacity ────────────────────────────────────────────────

test("redis capacity: 12 concurrent reservations against max 3 — exactly 3 admitted", async () => {
  const limiter = new RedisSettlementCapacityLimiter(client(), 3);
  const slots = await Promise.all(Array.from({ length: 12 }, () => limiter.tryReserve()));
  assert.equal(slots.filter(Boolean).length, 3);
  assert.equal(await limiter.inFlight(), 3);
});

test("redis capacity: releasing a slot readmits exactly one more caller", async () => {
  const limiter = new RedisSettlementCapacityLimiter(client(), 2);
  const a = await limiter.tryReserve();
  const b = await limiter.tryReserve();
  assert.ok(a && b);
  assert.equal(await limiter.tryReserve(), null);

  await a();
  assert.ok(await limiter.tryReserve(), "the freed slot is reusable");
  assert.equal(await limiter.tryReserve(), null);
});

test("redis capacity: release is idempotent — a double release cannot inflate capacity", async () => {
  const limiter = new RedisSettlementCapacityLimiter(client(), 1);
  const a = await limiter.tryReserve();
  await a();
  await a();
  assert.equal(await limiter.inFlight(), 0);
  assert.ok(await limiter.tryReserve());
  assert.equal(await limiter.tryReserve(), null, "capacity is still 1, not 2");
});

test("redis capacity: a crashed holder's lease expires and its slot is reclaimed", async () => {
  // The failure mode an INCR/DECR counter cannot survive: a worker dies holding
  // a slot and never decrements, so the facilitator slowly starves itself into
  // refusing everything — denial of settlement, self-inflicted.
  const limiter = new RedisSettlementCapacityLimiter(client(), 1, { leaseMs: 40 });
  const held = await limiter.tryReserve();
  assert.ok(held);
  assert.equal(await limiter.tryReserve(), null);

  await new Promise((r) => setTimeout(r, 60)); // worker "crashed"; lease lapses
  assert.ok(await limiter.tryReserve(), "an expired lease must be reclaimable");
});

test("redis capacity: guardedSettle refuses overflow before the settler runs", async () => {
  const store = new RedisNonceStore(client());
  const capacity = new RedisSettlementCapacityLimiter(client(), 2);
  let runs = 0;
  const settler = async () => {
    runs++;
    await new Promise((r) => setTimeout(r, 20));
    return { status: "confirmed", transaction: "0x1" };
  };

  const results = await Promise.all(
    Array.from({ length: 6 }, (_, i) =>
      guardedSettle({}, { nonce: `cap-${i}`, store, capacity, settler })
    )
  );

  const refused = results.filter((r) => r.reason === "settlement_capacity_exhausted");
  assert.equal(refused.length, 4);
  assert.equal(runs, 2, "no settlement work is done for a refused request");
});
