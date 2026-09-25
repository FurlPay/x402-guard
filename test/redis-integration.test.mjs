import { test } from "node:test";
import assert from "node:assert/strict";
import {
  RedisNonceStore,
  RedisAllowanceStore,
  RedisSettlementCapacityLimiter,
} from "../dist/index.js";
import { redisFromEnv, runPrefix, HINT } from "../harness/redis-env.mjs";

// ---------------------------------------------------------------------------
// The only tests in this repo that execute the actual Lua.
//
// redis-stores.test.mjs runs against a double whose scripts are re-implemented
// in JavaScript. That catches store-logic and command-sequencing bugs, and it
// cannot catch a bug in the Lua, because the Lua never runs. These tests close
// that gap — and they SKIP when no server is configured, so a green suite on a
// laptop with no Redis is not evidence the scripts work.
//
// Anything published about atomicity should cite this file plus
// harness/multiprocess.mjs, not the fake-backed suite.
// ---------------------------------------------------------------------------

const client = redisFromEnv();
const skip = client ? false : `no Redis configured — ${HINT}`;

test("integration: SET NX admits exactly one of 50 concurrent acquires", { skip }, async () => {
  const store = new RedisNonceStore(client, { prefix: runPrefix("int-nonce"), ttlSeconds: 120 });
  const results = await Promise.all(Array.from({ length: 50 }, () => store.acquire("n")));
  assert.equal(results.filter(Boolean).length, 1);
});

test("integration: the release script is a real compare-and-delete", { skip }, async () => {
  const store = new RedisNonceStore(client, { prefix: runPrefix("int-rel"), ttlSeconds: 120 });
  await store.acquire("n");
  await store.markSettled("n");
  await store.release("n");
  assert.equal(await store.state("n"), "settled", "Lua must not delete a SETTLED nonce");

  await store.acquire("m");
  await store.release("m");
  assert.equal(await store.state("m"), undefined, "Lua must delete a PENDING nonce");
});

test("integration: the reserve script cannot overdraft under concurrency", { skip }, async () => {
  const store = new RedisAllowanceStore(client, { prefix: runPrefix("int-alw"), reservationTtlSeconds: 120 });
  await store.create("a", 500n);
  const ids = await Promise.all(Array.from({ length: 20 }, () => store.reserve("a", 100n)));
  assert.equal(ids.filter(Boolean).length, 5);
  assert.equal(await store.remaining("a"), 0n);
});

test("integration: commit clamps to the escrow, refunds, and is idempotent", { skip }, async () => {
  const store = new RedisAllowanceStore(client, { prefix: runPrefix("int-commit"), reservationTtlSeconds: 120 });
  await store.create("a", 1000n);
  const id = await store.reserve("a", 400n);

  assert.equal(await store.commit(id, 10_000n), 400n, "clamped to the escrow");
  assert.equal(await store.commit(id, 400n), 0n, "second commit is a no-op");
  assert.equal(await store.remaining("a"), 600n);
});

test("integration: capacity script honours the ceiling and reclaims expired leases", { skip }, async () => {
  const key = `${runPrefix("int-cap")}capacity`;
  const limiter = new RedisSettlementCapacityLimiter(client, 3, { key, leaseMs: 1500 });
  const slots = await Promise.all(Array.from({ length: 12 }, () => limiter.tryReserve()));
  assert.equal(slots.filter(Boolean).length, 3);

  await new Promise((r) => setTimeout(r, 1800)); // leases lapse
  assert.ok(await limiter.tryReserve(), "an expired lease is reclaimable");
});
