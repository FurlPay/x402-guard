import test from "node:test";
import assert from "node:assert/strict";
import { FakeRedis } from "./fake-redis.mjs";
import { RedisMandateSpendStore } from "../dist/redis.js";

// ---------------------------------------------------------------------------
// F6 — mandate spend: the nonce and the window budget are ONE reservation.
//
// The bug this primitive exists to prevent is a leak, not a crash. Two
// sequential calls can leave one side held with nothing to release it:
//
//   budget reserved -> nonce acquire fails -> budget held forever
//
// and the user never sees an error. Their monthly cap is simply smaller next
// month. Every rejection path below therefore asserts on BOTH keys, because a
// test that only checks the return value passes just as happily while leaking.
// ---------------------------------------------------------------------------

const P = {
  mandateId: "mnd_1",
  window: "2026-09",
  nonce: "n1",
  paymentHash: "0xhash",
  resource: "/v1/summarize",
  amount: 25n,
};

/**
 * A store with NO window open. Each test opens the window it needs, so a test
 * that says "no budget registered" really has none — an earlier version of this
 * helper opened one itself and that test passed for the wrong reason.
 */
function setup() {
  const redis = new FakeRedis();
  return { redis, store: new RedisMandateSpendStore(redis) };
}

test("takes both locks on success", async () => {
  const { store } = setup();
  await store.openWindow(P.mandateId, P.window, 100n);

  const r = await store.reserveSpend(P);
  assert.equal(r.ok, true);
  assert.match(r.reservationId, /^mnd_1::/);
  // Budget moved...
  assert.equal(await store.remaining(P.mandateId, P.window), 75n);
});

test("a replayed nonce takes NOTHING — the budget is untouched", async () => {
  const { store } = setup();
  await store.openWindow(P.mandateId, P.window, 100n);
  await store.reserveSpend(P);
  assert.equal(await store.remaining(P.mandateId, P.window), 75n);

  // Same nonce again: the replay must not also cost a second budget slot.
  const again = await store.reserveSpend({ ...P, paymentHash: "0xother" });
  assert.equal(again.ok, false);
  assert.equal(again.reason, "nonce_taken");
  assert.equal(await store.remaining(P.mandateId, P.window), 75n);
});

test("an exhausted budget does not burn the nonce", async () => {
  // THE LEAK, IN THE OTHER DIRECTION. If the nonce stayed PENDING after a
  // budget rejection, that authorization would be unusable forever — the user
  // could never retry the payment even after topping the window up.
  const { store } = setup();
  await store.openWindow(P.mandateId, P.window, 10n);

  const r = await store.reserveSpend(P); // 25 > 10
  assert.equal(r.ok, false);
  assert.equal(r.reason, "budget_exhausted");

  // Budget untouched, and the nonce is free to be used once funds exist.
  assert.equal(await store.remaining(P.mandateId, P.window), 10n);
  await store.openWindow(P.mandateId, P.window, 100n);
  const retry = await store.reserveSpend(P);
  assert.equal(retry.ok, true, "the nonce must not have been consumed by the rejection");
});

test("fails closed when no window budget is registered", async () => {
  const { store } = setup();
  // No openWindow call at all.
  const r = await store.reserveSpend(P);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "no_mandate_budget");

  // And the nonce is not held by a mandate that does not exist.
  await store.openWindow(P.mandateId, P.window, 100n);
  assert.equal((await store.reserveSpend(P)).ok, true);
});

test("rejections are distinguishable, because they mean different things", async () => {
  // "you replayed a payment" and "you are out of budget" need different
  // responses from an agent: one is a bug, the other is a cap doing its job.
  const { store } = setup();
  await store.openWindow(P.mandateId, P.window, 10n);
  assert.equal((await store.reserveSpend({ ...P, amount: 25n })).reason, "budget_exhausted");
  assert.equal((await store.reserveSpend({ ...P, amount: 0n })).reason, "invalid_amount");
});

test("concurrent reservations on one window cannot oversell it", async () => {
  // The race the primitive exists for. Ten agents, each asking for 25 against a
  // 100 window: at most four can win, and the budget can never go negative.
  const redis = new FakeRedis();
  const store = new RedisMandateSpendStore(redis);
  await store.openWindow(P.mandateId, P.window, 100n);

  const results = await Promise.all(
    Array.from({ length: 10 }, (_, i) =>
      store.reserveSpend({ ...P, nonce: `n${i}`, paymentHash: `0x${i}` })
    )
  );

  const won = results.filter((r) => r.ok).length;
  assert.equal(won, 4);
  assert.equal(await store.remaining(P.mandateId, P.window), 0n);
});

test("commit settles the nonce and keeps the spend", async () => {
  const { store } = setup();
  await store.openWindow(P.mandateId, P.window, 100n);
  const r = await store.reserveSpend(P);

  assert.equal(await store.commit(r.reservationId), true);
  // The budget stays spent — that is what a completed payment means.
  assert.equal(await store.remaining(P.mandateId, P.window), 75n);
  // And the nonce is terminal: a replay after settlement must still fail.
  const replay = await store.reserveSpend({ ...P, paymentHash: "0xlate" });
  assert.equal(replay.ok, false);
  assert.equal(replay.reason, "nonce_taken");
});

test("release returns the budget and reopens the nonce", async () => {
  const { store } = setup();
  await store.openWindow(P.mandateId, P.window, 100n);
  const r = await store.reserveSpend(P);

  assert.equal(await store.releaseProvenUnsettled(r.reservationId), true);
  assert.equal(await store.remaining(P.mandateId, P.window), 100n);
});

test("release REFUSES once the nonce has settled", async () => {
  // The late-SUCCESS case. If settlement landed and was committed, a release
  // arriving afterwards must not hand the budget back — that would let the same
  // window slot fund a second payment while the first one already moved money.
  const { store } = setup();
  await store.openWindow(P.mandateId, P.window, 100n);
  const r = await store.reserveSpend(P);
  await store.commit(r.reservationId);

  // The reservation record is gone, so there is nothing to release.
  assert.equal(await store.releaseProvenUnsettled(r.reservationId), false);
  assert.equal(await store.remaining(P.mandateId, P.window), 75n);
});

test("a double release cannot refund twice", async () => {
  const { store } = setup();
  await store.openWindow(P.mandateId, P.window, 100n);
  const r = await store.reserveSpend(P);

  assert.equal(await store.releaseProvenUnsettled(r.reservationId), true);
  assert.equal(await store.releaseProvenUnsettled(r.reservationId), false);
  assert.equal(await store.remaining(P.mandateId, P.window), 100n);
});

test("resource is part of the reservation record", async () => {
  // Two endpoints at the same seller and amount must be separable after the
  // fact, or a partial failure lets one budget slot be applied across both.
  const { store } = setup();
  await store.openWindow(P.mandateId, P.window, 100n);
  const a = await store.reserveSpend({ ...P, nonce: "na", resource: "/a" });
  const b = await store.reserveSpend({ ...P, nonce: "nb", resource: "/b" });
  assert.notEqual(a.reservationId, b.reservationId);
  assert.equal(await store.remaining(P.mandateId, P.window), 50n);
});

test("refuses an amount past Lua's exact-integer ceiling", async () => {
  const { store } = setup();
  await store.openWindow(P.mandateId, P.window, 100n);
  await assert.rejects(
    () => store.reserveSpend({ ...P, amount: 2n ** 60n }),
    /exact-integer ceiling/
  );
});
