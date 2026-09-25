import test from "node:test";
import assert from "node:assert/strict";
import { FakeRedis } from "./fake-redis.mjs";
import { RedisMandateSpendStore } from "../dist/redis.js";

// ---------------------------------------------------------------------------
// Rolling windows need different storage, and that is the finding — not a
// preference. A decrementing counter can only fall: nothing re-credits it as
// spend ages out of the trailing period, so a "rolling 30d" budget built on one
// is really a one-way budget that never recovers. These tests pin the property
// a counter cannot have.
// ---------------------------------------------------------------------------

const DAY = 86_400_000;
const WINDOW_MS = 30 * DAY;
const T0 = Date.UTC(2026, 0, 15);

const base = {
  mandateId: "mnd_r",
  window: "r2592000",
  paymentHash: "0xh",
  resource: "/v1/x",
  capAtomic: 100n,
  windowMs: WINDOW_MS,
};

function store() {
  return new RedisMandateSpendStore(new FakeRedis());
}

test("spend accumulates inside the window", async () => {
  const s = store();
  await s.reserveSpendRolling({ ...base, nonce: "n1", amount: 40n, nowMs: T0 });
  await s.reserveSpendRolling({ ...base, nonce: "n2", amount: 30n, nowMs: T0 + DAY });
  assert.equal(await s.rollingSpend(base.mandateId, base.window, WINDOW_MS, T0 + DAY), 70n);
});

test("the cap is enforced against the trailing sum", async () => {
  const s = store();
  await s.reserveSpendRolling({ ...base, nonce: "n1", amount: 80n, nowMs: T0 });
  const over = await s.reserveSpendRolling({ ...base, nonce: "n2", amount: 30n, nowMs: T0 + DAY });
  assert.equal(over.ok, false);
  assert.equal(over.reason, "budget_exhausted");
});

test("spend LEAVES the window as it ages — the property a counter cannot have", async () => {
  const s = store();
  // Fill the window completely.
  await s.reserveSpendRolling({ ...base, nonce: "n1", amount: 100n, nowMs: T0 });
  const blocked = await s.reserveSpendRolling({ ...base, nonce: "n2", amount: 1n, nowMs: T0 + DAY });
  assert.equal(blocked.ok, false);

  // 31 days later the original spend is outside the trailing 30 days, so the
  // budget is available again WITHOUT anyone topping it up. A counter would
  // still read zero here forever.
  const later = T0 + 31 * DAY;
  assert.equal(await s.rollingSpend(base.mandateId, base.window, WINDOW_MS, later), 0n);
  const ok = await s.reserveSpendRolling({ ...base, nonce: "n3", amount: 100n, nowMs: later });
  assert.equal(ok.ok, true);
});

test("spend ages out gradually, not all at once", async () => {
  const s = store();
  await s.reserveSpendRolling({ ...base, nonce: "n1", amount: 50n, nowMs: T0 });
  await s.reserveSpendRolling({ ...base, nonce: "n2", amount: 50n, nowMs: T0 + 10 * DAY });

  // At T0+31d only the first has aged out.
  const at31 = T0 + 31 * DAY;
  assert.equal(await s.rollingSpend(base.mandateId, base.window, WINDOW_MS, at31), 50n);
  // At T0+41d both have.
  assert.equal(await s.rollingSpend(base.mandateId, base.window, WINDOW_MS, T0 + 41 * DAY), 0n);
});

test("a replayed nonce does not double-charge the ledger", async () => {
  const s = store();
  await s.reserveSpendRolling({ ...base, nonce: "n1", amount: 40n, nowMs: T0 });
  const replay = await s.reserveSpendRolling({ ...base, nonce: "n1", amount: 40n, nowMs: T0 });
  assert.equal(replay.reason, "nonce_taken");
  assert.equal(await s.rollingSpend(base.mandateId, base.window, WINDOW_MS, T0), 40n);
});

test("a rejected reservation leaves the ledger untouched", async () => {
  const s = store();
  await s.reserveSpendRolling({ ...base, nonce: "n1", amount: 100n, nowMs: T0 });
  const rejected = await s.reserveSpendRolling({ ...base, nonce: "n2", amount: 5n, nowMs: T0 });
  assert.equal(rejected.ok, false);
  assert.equal(await s.rollingSpend(base.mandateId, base.window, WINDOW_MS, T0), 100n);
  // And the nonce survives the rejection, so it can be retried later.
  const retry = await s.reserveSpendRolling({
    ...base, nonce: "n2", amount: 5n, nowMs: T0 + 31 * DAY,
  });
  assert.equal(retry.ok, true);
});

test("release removes the ledger entry and reopens the nonce", async () => {
  const s = store();
  const r = await s.reserveSpendRolling({ ...base, nonce: "n1", amount: 40n, nowMs: T0 });
  assert.equal(await s.releaseProvenUnsettled(r.reservationId), true);
  assert.equal(await s.rollingSpend(base.mandateId, base.window, WINDOW_MS, T0), 0n);
});

test("release refuses after commit, so a late SUCCESS cannot un-spend", async () => {
  const s = store();
  const r = await s.reserveSpendRolling({ ...base, nonce: "n1", amount: 40n, nowMs: T0 });
  await s.commit(r.reservationId);
  assert.equal(await s.releaseProvenUnsettled(r.reservationId), false);
  assert.equal(await s.rollingSpend(base.mandateId, base.window, WINDOW_MS, T0), 40n);
});

test("concurrent rolling reservations cannot oversell the window", async () => {
  const s = store();
  const results = await Promise.all(
    Array.from({ length: 10 }, (_, i) =>
      s.reserveSpendRolling({ ...base, nonce: `n${i}`, amount: 25n, nowMs: T0 })
    )
  );
  assert.equal(results.filter((r) => r.ok).length, 4);
  assert.equal(await s.rollingSpend(base.mandateId, base.window, WINDOW_MS, T0), 100n);
});

test("the two accounting models do not share state", async () => {
  // Same mandate and window string, different mechanisms. A bucket reservation
  // must not be visible to the rolling sum or vice versa, or a mandate that
  // changed type mid-life would read a budget that was never spent under it.
  const s = store();
  await s.openWindow(base.mandateId, base.window, 100n);
  await s.reserveSpend({
    mandateId: base.mandateId, window: base.window, nonce: "bucket",
    paymentHash: "0xb", resource: "/v1/x", amount: 60n,
  });
  assert.equal(await s.rollingSpend(base.mandateId, base.window, WINDOW_MS, T0), 0n);
  assert.equal(await s.remaining(base.mandateId, base.window), 40n);
});
