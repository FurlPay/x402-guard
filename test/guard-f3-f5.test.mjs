import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MemoryNonceStore,
  guardedSettle,
  MemoryAllowanceStore,
  guardedCharge,
  SettlementCapacityLimiter,
  AdaptivePricer,
} from "../dist/index.js";

// ── F3: allowance overdraft (paper §4.3 / §5.3) ─────────────────────────────

test("F3: concurrent upto charges cannot overdraft the allowance", async () => {
  const store = new MemoryAllowanceStore();
  store.create("alw-1", 100n);

  // The paper's overdraft: 20 concurrent requests, each up to 10, against a
  // balance of 100. Read-then-deduct lets all 20 through (spend 200);
  // pessimistic reserve-commit admits exactly 10.
  const results = await Promise.all(
    Array.from({ length: 20 }, () =>
      guardedCharge({
        allowanceId: "alw-1",
        vmax: 10n,
        store,
        execute: async () => {
          await new Promise((r) => setTimeout(r, 5)); // the verify→settle gap
          return { actual: 10n, value: "served" };
        },
      })
    )
  );

  const served = results.filter((r) => r.success);
  const refused = results.filter((r) => !r.success);
  assert.equal(served.length, 10, "only ⌊balance / Vmax⌋ requests may be served");
  assert.equal(refused.length, 10);
  assert.ok(refused.every((r) => r.reason === "allowance_exhausted"));
  assert.equal(store.remaining("alw-1"), 0n, "balance is exactly exhausted, never negative");
});

test("F3: actual usage below Vmax is refunded at commit", async () => {
  const store = new MemoryAllowanceStore();
  store.create("alw-2", 50n);

  const res = await guardedCharge({
    allowanceId: "alw-2",
    vmax: 30n,
    store,
    execute: () => ({ actual: 12n, value: null }),
  });

  assert.equal(res.success, true);
  assert.equal(res.charged, 12n);
  assert.equal(store.remaining("alw-2"), 38n, "escrowed 30, billed 12, refunded 18");
});

test("F3: the escrow is a hard billing ceiling — over-report is clamped to Vmax", async () => {
  const store = new MemoryAllowanceStore();
  store.create("alw-3", 50n);

  const res = await guardedCharge({
    allowanceId: "alw-3",
    vmax: 30n,
    store,
    // a buggy/hostile meter reports more than was authorized
    execute: () => ({ actual: 999n, value: null }),
  });

  assert.equal(res.success, true);
  assert.equal(res.charged, 30n, "billing never exceeds the reserved Vmax");
  assert.equal(store.remaining("alw-3"), 20n);
});

test("F3: failed execution refunds the full escrow; commit is idempotent", async () => {
  const store = new MemoryAllowanceStore();
  store.create("alw-4", 40n);

  const res = await guardedCharge({
    allowanceId: "alw-4",
    vmax: 25n,
    store,
    execute: () => {
      throw new Error("upstream blew up before delivering anything");
    },
  });

  assert.equal(res.success, false);
  assert.equal(res.reason, "execution_failed");
  assert.equal(store.remaining("alw-4"), 40n, "nothing delivered → nothing billed");

  // Double-settling a reservation must not mint refunds.
  const rid = store.reserve("alw-4", 10n);
  assert.equal(store.commit(rid, 4n), 4n);
  assert.equal(store.commit(rid, 4n), 0n, "second commit is a no-op");
  assert.equal(store.remaining("alw-4"), 36n);
});

// ── F4: denial of settlement (paper §4.4 / §5.4) ────────────────────────────

test("F4: settlement capacity is reserved BEFORE serving — overflow is refused, not served free", async () => {
  const nonces = new MemoryNonceStore();
  const capacity = new SettlementCapacityLimiter(5);

  // 20 distinct authorizations arrive while settlement is slow (the DoS
  // window). Hold every admitted settlement open until we've observed who got
  // in, proving admission happens before delivery.
  let admitted = 0;
  let releaseSettlers;
  const gate = new Promise((r) => (releaseSettlers = r));

  const inFlight = Array.from({ length: 20 }, (_, i) =>
    guardedSettle({}, {
      nonce: `n-${i}`,
      store: nonces,
      capacity,
      settler: async () => {
        admitted++;
        await gate;
        return { status: "confirmed", transaction: `0x${i}` };
      },
    })
  );

  await new Promise((r) => setTimeout(r, 20)); // let all 20 hit the gate
  assert.equal(admitted, 5, "only maxConcurrent settlers may be executing");
  assert.equal(capacity.available, 0);

  releaseSettlers();
  const results = await Promise.all(inFlight);

  const ok = results.filter((r) => r.success);
  const refused = results.filter((r) => !r.success);
  assert.equal(ok.length, 5);
  assert.equal(refused.length, 15);
  assert.ok(refused.every((r) => r.reason === "settlement_capacity_exhausted"), "overflow maps to HTTP 429");
  assert.equal(capacity.available, 5, "all slots released after settlement");
});

test("F4: a capacity-refused authorization is NOT consumed — honest retry succeeds", async () => {
  const nonces = new MemoryNonceStore();
  const capacity = new SettlementCapacityLimiter(1);

  // Occupy the only slot.
  let releaseFirst;
  const firstDone = guardedSettle({}, {
    nonce: "n-occupier",
    store: nonces,
    capacity,
    settler: async () => {
      await new Promise((r) => (releaseFirst = r));
      return { status: "confirmed", transaction: "0xa" };
    },
  });
  await new Promise((r) => setTimeout(r, 10));

  // The honest request is refused at the door — before its nonce is claimed.
  const refused = await guardedSettle({}, {
    nonce: "n-honest",
    store: nonces,
    capacity,
    settler: async () => ({ status: "confirmed", transaction: "0xb" }),
  });
  assert.equal(refused.success, false);
  assert.equal(refused.reason, "settlement_capacity_exhausted");
  assert.equal(await nonces.state("n-honest"), undefined, "nonce untouched by the 429");

  releaseFirst();
  await firstDone;

  // Same authorization retries cleanly once capacity frees up.
  const retry = await guardedSettle({}, {
    nonce: "n-honest",
    store: nonces,
    capacity,
    settler: async () => ({ status: "confirmed", transaction: "0xb" }),
  });
  assert.equal(retry.success, true);
  assert.equal(retry.transaction, "0xb");
});

// ── F5: hidden-compute pricing (paper §5.5, G2) ─────────────────────────────

test("F5: adaptive weight converges so the escrow covers a compute free-rider", () => {
  const pricer = new AdaptivePricer({ unitPrice: 100n });

  // Adversary estimates 100 tokens per request but consistently burns 500 —
  // the fixed-quote leak. Feed the pricer what it actually observes.
  const estimated = 100;
  const actual = 500;

  // Cold start: the first quote under-covers (inherent — cost is unknowable).
  assert.ok(pricer.quoteMax(estimated) < pricer.bill(actual));

  for (let i = 0; i < 25; i++) pricer.observe(estimated, actual);

  // After adaptation the quoted Vmax covers the realized bill: leakage → 0.
  assert.ok(
    pricer.quoteMax(estimated) >= pricer.bill(actual),
    `quote ${pricer.quoteMax(estimated)} must cover bill ${pricer.bill(actual)} (ratio ${pricer.ratio.toFixed(2)})`
  );
});

test("F5: honest traffic is quoted near its estimate and refunded via the F3 escrow", async () => {
  const pricer = new AdaptivePricer({ unitPrice: 10n });
  for (let i = 0; i < 10; i++) pricer.observe(100, 90); // well-behaved history

  // minRatio floors at 1: never quote below the caller's own estimate.
  assert.equal(pricer.ratio, 1);
  const vmax = pricer.quoteMax(100); // 100 × 1 × 1.25 → 125 units → 1250
  assert.equal(vmax, 1250n);

  // Compose with F3: escrow the quote, bill actual usage, refund the margin.
  const store = new MemoryAllowanceStore();
  store.create("alw-f5", 10000n);
  const res = await guardedCharge({
    allowanceId: "alw-f5",
    vmax,
    store,
    execute: () => ({ actual: pricer.bill(90), value: null }),
  });
  assert.equal(res.success, true);
  assert.equal(res.charged, 900n, "honest caller pays actual usage, not the quote");
  assert.equal(store.remaining("alw-f5"), 9100n, "the safety margin came back as refund");
});

test("F5: the learned ratio is clamped — one abuse wave cannot inflate quotes unboundedly", () => {
  const pricer = new AdaptivePricer({ unitPrice: 1n, maxRatio: 10, alpha: 1 });

  pricer.observe(1, 1_000_000); // absurd single observation
  assert.equal(pricer.ratio, 10, "ratio ceiling holds");

  pricer.observe(100, 0); // then a zero-cost request
  assert.equal(pricer.ratio, 1, "ratio floor holds — never quote below estimate");
});
