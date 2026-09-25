import test from "node:test";
import assert from "node:assert/strict";
import {
  assertValidWindow,
  evaluateSpendAuthorization,
  isRolling,
  windowEndsAt,
  windowKeyFor,
} from "../dist/mandate.js";

// ---------------------------------------------------------------------------
// The two questions the RFC left open, as tests.
//
// Both are really one question: can the payer-side gate and the facilitator
// reach DIFFERENT answers about the same payment? Every disagreement below
// settles a payment that should not have settled, so the tests are written
// against the disagreement rather than against either side's behaviour.
// ---------------------------------------------------------------------------

const JAN = Date.UTC(2026, 0, 15, 12, 0, 0);

test("both sides derive the same bucket from the same mandate", () => {
  // The whole point of putting the spec in the signed mandate: two independent
  // callers, no shared state, same key.
  const spec = { type: "calendar", unit: "month" };
  const payer = windowKeyFor(spec, JAN);
  const facilitator = windowKeyFor(spec, JAN + 3_600_000);
  assert.equal(payer, facilitator);
  assert.equal(payer, "c-m-2026-01");
});

test("a calendar month rolls at the UTC boundary, not 30 days later", () => {
  const spec = { type: "calendar", unit: "month" };
  assert.equal(windowKeyFor(spec, Date.UTC(2026, 0, 31, 23, 59, 59)), "c-m-2026-01");
  assert.equal(windowKeyFor(spec, Date.UTC(2026, 1, 1, 0, 0, 0)), "c-m-2026-02");
});

test("`30d` is ambiguous and that is the bug — the two types differ by design", () => {
  // Same duration, same instant, deliberately different keys. If a payer read
  // "30d" as rolling and a facilitator as a calendar month, both enforce "$50"
  // and disagree about every payment near a boundary.
  const rolling = windowKeyFor({ type: "rolling", durationSeconds: 2_592_000 }, JAN);
  const calendar = windowKeyFor({ type: "calendar", unit: "month" }, JAN);
  assert.notEqual(rolling, calendar);
});

test("a rolling window has no time-derived bucket", () => {
  // Returning a bucket for a rolling window would silently reset the budget at
  // arbitrary instants and look like it worked.
  const spec = { type: "rolling", durationSeconds: 2_592_000 };
  assert.equal(windowKeyFor(spec, JAN), windowKeyFor(spec, JAN + 40 * 86_400_000));
  assert.equal(windowEndsAt(spec, JAN), null);
  assert.equal(isRolling(spec), true);
});

test("ISO weeks are correct across a year edge", () => {
  // 2026-01-01 is a Thursday, so it belongs to ISO week 1 of 2026.
  assert.equal(windowKeyFor({ type: "calendar", unit: "week" }, Date.UTC(2026, 0, 1)), "c-w-2026-W01");
  // 2025-12-29 is the Monday of that same ISO week — same bucket, prior year.
  assert.equal(windowKeyFor({ type: "calendar", unit: "week" }, Date.UTC(2025, 11, 29)), "c-w-2026-W01");
});

test("fixed periods count from the anchor and do not collapse before it", () => {
  const spec = { type: "fixed_period", durationSeconds: 14 * 86_400, anchor: "2026-01-01T00:00:00Z" };
  assert.equal(windowKeyFor(spec, Date.UTC(2026, 0, 1)), "f-1209600-0");
  assert.equal(windowKeyFor(spec, Date.UTC(2026, 0, 15)), "f-1209600-1");
  // Before the anchor lands in a negative period rather than all in period 0.
  assert.equal(windowKeyFor(spec, Date.UTC(2025, 11, 20)), "f-1209600--1");
});

test("a window that cannot produce a stable key is refused before signing", () => {
  assert.throws(() => assertValidWindow({ type: "rolling", durationSeconds: 0 }), /positive/);
  assert.throws(() => assertValidWindow({ type: "rolling", durationSeconds: 5 }), /at least 60s/);
  // 2592000000 is 30 days in MILLISECONDS — the classic units mistake, caught
  // rather than signed into a mandate as an 82-year window.
  assert.throws(() => assertValidWindow({ type: "rolling", durationSeconds: 2_592_000_000 }), /one year/);
  assert.throws(
    () => assertValidWindow({ type: "fixed_period", durationSeconds: 86_400, anchor: "not-a-date" }),
    /ISO 8601/
  );
});

// ── Threshold evidence ─────────────────────────────────────────────────────

const HASH = "0xpayment";
const policy = { requireApprovalAbove: "5000000", denyAbove: "100000000", stepUpMaxAgeSeconds: 300 };

const ev = (over = {}) => ({ class: "DELEGATED", paymentHash: HASH, verified: true, ...over });

function evaluate(amount, evidence, mode = "settlement", nowMs = JAN) {
  return evaluateSpendAuthorization({ amount, policy, evidence, paymentHash: HASH, nowMs, mode });
}

test("below the threshold, delegated authority is enough", () => {
  assert.deepEqual(evaluate("1000000", ev()), {
    decision: "AUTHORIZED",
    reason: "within_delegated_authority",
  });
});

test("REQUIRE_APPROVAL is a pre-signing answer only", () => {
  // The architectural claim, as a test. A facilitator cannot pause and ask, so
  // the same inputs must resolve differently by layer — and DENY is the safe
  // side of that difference.
  const over = "10000000";
  assert.equal(evaluate(over, ev(), "pre_signing").decision, "REQUIRE_APPROVAL");
  assert.equal(evaluate(over, ev(), "settlement").decision, "DENY");
});

test("step-up evidence lets an above-threshold payment settle", () => {
  const e = ev({ class: "STEP_UP", approvedAtMs: JAN - 60_000 });
  assert.deepEqual(evaluate("10000000", e), {
    decision: "AUTHORIZED",
    reason: "step_up_evidence_valid",
  });
});

test("stale step-up evidence does not", () => {
  // Without an age bound a single approval would authorize above-threshold
  // payments forever, which is the thing a threshold exists to prevent.
  const e = ev({ class: "STEP_UP", approvedAtMs: JAN - 301_000 });
  assert.equal(evaluate("10000000", e).reason, "step_up_evidence_stale");
});

test("future-dated approval is rejected, not treated as very fresh", () => {
  const e = ev({ class: "STEP_UP", approvedAtMs: JAN + 60_000 });
  assert.equal(evaluate("10000000", e).reason, "step_up_timestamp_in_future");
});

test("a human-present payment needs no step-up", () => {
  assert.equal(evaluate("10000000", ev({ class: "DIRECT" })).reason, "human_present");
});

test("evidence for a different payment is not weaker evidence — it is unrelated", () => {
  const e = ev({ class: "DIRECT", paymentHash: "0xsomethingelse" });
  assert.equal(evaluate("1000000", e).decision, "DENY");
  assert.equal(evaluate("1000000", e).reason, "evidence_bound_to_other_payment");
});

test("unverified evidence is refused even below the threshold", () => {
  assert.equal(evaluate("1000000", ev({ verified: false })).reason, "evidence_signature_unverified");
});

test("the hard ceiling beats every form of evidence", () => {
  // Checked first on purpose: no quantity of human approval talks a payment
  // past a limit the user set as absolute.
  for (const cls of ["DIRECT", "DELEGATED", "STEP_UP"]) {
    const e = ev({ class: cls, approvedAtMs: JAN });
    assert.equal(evaluate("200000000", e).reason, "above_deny_ceiling", `${cls} bypassed denyAbove`);
  }
});

test("both layers agree on every amount around the threshold", () => {
  // The invariant that matters: the only permitted divergence between the two
  // modes is REQUIRE_APPROVAL vs DENY. Anything else means the gate would let
  // through something the facilitator refuses, or vice versa.
  const e = ev({ class: "DELEGATED" });
  for (const amt of ["1", "4999999", "5000000", "5000001", "99999999", "100000001"]) {
    const pre = evaluate(amt, e, "pre_signing");
    const set = evaluate(amt, e, "settlement");
    if (pre.decision === set.decision) continue;
    assert.equal(pre.decision, "REQUIRE_APPROVAL", `divergence at ${amt}`);
    assert.equal(set.decision, "DENY", `divergence at ${amt}`);
  }
});

test("a malformed amount is denied rather than coerced", () => {
  assert.equal(evaluate("not-a-number", ev()).reason, "amount_unparseable");
  assert.equal(evaluate("0", ev()).reason, "amount_not_positive");
  assert.equal(evaluate("-5", ev()).reason, "amount_not_positive");
});
