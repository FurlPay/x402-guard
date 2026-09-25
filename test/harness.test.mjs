import { test } from "node:test";
import assert from "node:assert/strict";
import { BaselineFacilitator, GuardedFacilitator } from "../harness/facilitators.mjs";
import { SCENARIOS } from "../harness/scenarios.mjs";

// ---------------------------------------------------------------------------
// Differential assertions over the adversarial harness.
//
// guard.test.mjs and guard-f3-f5.test.mjs are DEFENSE tests: they show the
// library refusing bad traffic. On their own they are weak evidence, because a
// component that refuses everything passes them all. These tests add the two
// halves that make the result a measurement rather than an assertion:
//
//   1. THE CONTROL. The unguarded baseline must actually be exploitable. If a
//      baseline stops leaking — because the scenario drifted, or the simulated
//      chain got stricter — then the guarded run proves nothing and this suite
//      fails loudly rather than reporting a comfortable 0%.
//
//   2. LIVENESS. The guarded facilitator must still serve and settle honest
//      traffic. Rejecting everything drives leakage to zero trivially, so every
//      guarded run is checked for delivered > 0 and paid > 0. Without this,
//      `verify() { return false }` would score perfectly.
// ---------------------------------------------------------------------------

const OPTIONS = { F4: { settlementLatencyMs: 8, maxConcurrentSettlements: 3 } };

async function runBoth(scenario) {
  const opts = OPTIONS[scenario.id] ?? {};
  const baseline = await scenario.run(new BaselineFacilitator(opts));
  const guarded = await scenario.run(new GuardedFacilitator(opts));
  return { baseline: { ...baseline.ledger.report(), extra: baseline.extra }, guarded: { ...guarded.ledger.report(), extra: guarded.extra } };
}

// ── The control: every baseline must leak ──────────────────────────────────

test("control: the unguarded baseline is exploitable in every scenario", async () => {
  for (const scenario of SCENARIOS) {
    const { baseline } = await runBoth(scenario);
    const leaked = Math.max(baseline.requestLeakage, baseline.valueLeakage);
    assert.ok(
      leaked > 0,
      `${scenario.id} (${scenario.name}): baseline leaked nothing — the attack no longer reproduces, ` +
        `so the guarded result for this flaw is not evidence of anything`
    );
  }
});

// ── Liveness: the guard must not "win" by refusing service ─────────────────

test("liveness: the guarded facilitator still serves and settles honest traffic", async () => {
  for (const scenario of SCENARIOS) {
    const { guarded } = await runBoth(scenario);
    assert.ok(guarded.delivered > 0, `${scenario.id}: guarded delivered nothing — leakage of 0% would be trivial`);
    assert.ok(guarded.paidRequests > 0, `${scenario.id}: guarded settled nothing`);
  }
});

// ── Per-flaw differentials ─────────────────────────────────────────────────

test("F1: substitution across a sibling cluster leaks 75%, fully closed by binding", async () => {
  const { baseline, guarded } = await runBoth(SCENARIOS[0]);
  // One authorization, four equal-priced siblings: three served free.
  assert.equal(baseline.delivered, 4);
  assert.equal(baseline.paidRequests, 1);
  assert.equal(baseline.requestLeakage, 0.75);
  // The binding check rejects the three substitutions at admission.
  assert.equal(guarded.delivered, 1);
  assert.equal(guarded.requestLeakage, 0);
  assert.equal(guarded.rejected, 3);
});

test("F2: 20 concurrent duplicates leak 95%, fully closed by nonce linearization", async () => {
  const { baseline, guarded } = await runBoth(SCENARIOS[1]);
  // The chain consumes the authorization once; the merchant served 20 times.
  assert.equal(baseline.delivered, 20);
  assert.equal(baseline.paidRequests, 1);
  assert.equal(baseline.requestLeakage, 0.95);
  assert.equal(guarded.delivered, 1, "only the race winner may be served");
  assert.equal(guarded.requestLeakage, 0);
});

test("F3: read-then-deduct overdraws the allowance 2x, reserve-commit holds it at 1x", async () => {
  const { baseline, guarded } = await runBoth(SCENARIOS[2]);
  assert.ok(baseline.extra.overdraftMultiple > 1, "baseline must exceed the signed allowance");
  assert.equal(baseline.extra.overdraftMultiple, 2);
  assert.ok(baseline.valueLeakage > 0, "value drawn beyond the allowance is uncollectible");
  // The escrow is a hard ceiling: never more than the allowance backs.
  assert.equal(guarded.extra.overdraftMultiple, 1);
  assert.equal(guarded.valueLeakage, 0);
});

test("F4: serving before reserving capacity leaks 75%; failing closed leaks nothing", async () => {
  const { baseline, guarded } = await runBoth(SCENARIOS[3]);
  assert.equal(baseline.delivered, 12);
  assert.equal(baseline.requestLeakage, 0.75, "9 of 12 served with no settlement");
  // Capacity is reserved at admission, so the overflow is refused, not served.
  assert.equal(guarded.requestLeakage, 0);
  assert.equal(guarded.rejected, 9);
  assert.equal(guarded.delivered, guarded.paidRequests);
});

test("F5: adaptive billing roughly halves compute free-riding but does NOT close it", async () => {
  const { baseline, guarded } = await runBoth(SCENARIOS[4]);

  // The attack is invisible in request terms — every request settles. It only
  // shows up in value, which is why the harness reports both ratios.
  assert.equal(baseline.requestLeakage, 0);
  assert.equal(guarded.requestLeakage, 0);

  assert.ok(baseline.valueLeakage > 0.5, "fixed quoting should free-ride most adversarial compute");
  assert.ok(
    guarded.valueLeakage < baseline.valueLeakage * 0.75,
    "the learned billing weight must materially reduce leakage"
  );

  // Recorded deliberately: unlike F1–F4 this is a MITIGATION, not a fix. A
  // single quote cannot be tight for honest callers and still cover a 6x
  // outlier, and the paper itself states there is no static defense. If a
  // future change closes it completely, this assertion should fail and the
  // claim in the README should be upgraded on purpose rather than by accident.
  assert.ok(guarded.valueLeakage > 0, "F5 is not expected to reach zero — see AdaptivePricer bounds");
  assert.ok(guarded.extra.learnedRatio > 1, "the pricer must actually learn from observed traffic");
});
