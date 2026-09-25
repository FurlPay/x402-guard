// ---------------------------------------------------------------------------
// F6 — delegated spend authorization: window semantics and approval evidence.
//
// Two questions left open by the RFC thread, both of which are only answerable
// in the SIGNED mandate rather than in either party's local configuration:
//
//   1. What does "$50 per 30d" mean? If the payer measures a rolling 30 days
//      and the facilitator measures a calendar month, both are enforcing "$50"
//      and they still disagree about every payment near a boundary. The
//      disagreement surfaces as a payment that settled when it should not have.
//
//   2. Above a threshold, what counts as proof a human approved THIS payment?
//      A facilitator cannot pause and ask — by settlement time the approval
//      either happened or it did not. So "requires approval" has to be
//      expressible as something the payment CARRIES.
//
// Nothing here touches the network or a key. It is pure and deterministic so
// that the payer-side gate and the facilitator can run the SAME function over
// the same mandate and cannot reach different answers — which is the actual
// defect being fixed, not the individual checks.
// ---------------------------------------------------------------------------

/** Atomic minor units (6-decimal USDC), as a string, matching the stores. */
export type Atomic = string;

// ── Window semantics ───────────────────────────────────────────────────────

/**
 * How a spend window is measured.
 *
 * THE TYPE SELECTS A STORAGE MODEL, not just a label. A `calendar` or
 * `fixed_period` window is a bucket: one counter per bucket, decremented per
 * payment, discarded when the bucket rolls. A `rolling` window is not, and
 * cannot be — a single decrementing counter has nothing that re-credits it as
 * spend ages out of the trailing period. Rolling windows need per-payment
 * timestamps so old spend can leave the sum on its own.
 *
 * That is why this is a tagged union rather than a duration plus a flag: the
 * two are not variations of one mechanism.
 */
export type WindowSpec =
  /**
   * Trailing `durationSeconds` from NOW, recomputed per payment. Spend leaves
   * the window continuously. Requires timestamped accounting.
   */
  | { type: "rolling"; durationSeconds: number }
  /**
   * Aligned to the calendar in UTC. The whole budget is available again the
   * instant the bucket rolls, which is the behaviour most people mean by
   * "per month" and the one a counter implements exactly.
   */
  | { type: "calendar"; unit: "day" | "week" | "month" }
  /**
   * Fixed-length periods counted from `anchor`. Predictable buckets that need
   * not align to a calendar — e.g. 14-day cycles from the mandate's issuance.
   */
  | { type: "fixed_period"; durationSeconds: number; anchor: string };

export class WindowSpecError extends Error {}

/** Reject a spec that cannot produce a stable key before it is signed. */
export function assertValidWindow(w: WindowSpec): void {
  if (w.type === "rolling" || w.type === "fixed_period") {
    if (!Number.isFinite(w.durationSeconds) || w.durationSeconds <= 0) {
      throw new WindowSpecError("durationSeconds must be a positive number");
    }
    // A window shorter than a block time cannot be enforced meaningfully, and a
    // window longer than a year is almost always a units mistake (ms for s).
    if (w.durationSeconds < 60) throw new WindowSpecError("window must be at least 60s");
    if (w.durationSeconds > 366 * 86_400) throw new WindowSpecError("window exceeds one year");
  }
  if (w.type === "fixed_period") {
    if (Number.isNaN(Date.parse(w.anchor))) {
      throw new WindowSpecError("anchor must be an ISO 8601 instant");
    }
  }
}

/** True when the spec needs timestamped accounting rather than a counter. */
export function isRolling(w: WindowSpec): boolean {
  return w.type === "rolling";
}

function utcParts(ms: number) {
  const d = new Date(ms);
  return {
    y: d.getUTCFullYear(),
    m: d.getUTCMonth() + 1,
    d: d.getUTCDate(),
  };
}

/** ISO week-numbering year and week, UTC. Weeks start Monday. */
function isoWeek(ms: number): { year: number; week: number } {
  const d = new Date(ms);
  // Shift to the Thursday of this week: the ISO year is whichever year that
  // Thursday falls in, which is what makes week 1 well defined at a year edge.
  const day = (d.getUTCDay() + 6) % 7; // Mon=0
  d.setUTCDate(d.getUTCDate() - day + 3);
  const thursday = d.getTime();
  const year = d.getUTCFullYear();
  const jan4 = Date.UTC(year, 0, 4);
  const jan4Day = (new Date(jan4).getUTCDay() + 6) % 7;
  const week1Monday = jan4 - jan4Day * 86_400_000;
  const week = Math.floor((thursday - week1Monday) / (7 * 86_400_000)) + 1;
  return { year, week };
}

/**
 * The bucket a payment at `nowMs` falls in.
 *
 * Both sides call this. A payer that computes its own bucket string, however
 * reasonably, is how "$50/30d" becomes two different budgets.
 *
 * Rolling windows have no bucket — there is one continuous ledger per mandate —
 * so this returns a constant key for them and the caller must use the rolling
 * accounting path. Returning a time-derived key for a rolling window would look
 * like it worked and silently reset the budget at arbitrary instants.
 */
export function windowKeyFor(w: WindowSpec, nowMs: number): string {
  assertValidWindow(w);
  switch (w.type) {
    case "rolling":
      return `r${w.durationSeconds}`;
    case "calendar": {
      const { y, m, d } = utcParts(nowMs);
      if (w.unit === "day") {
        return `c-d-${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
      }
      if (w.unit === "month") return `c-m-${y}-${String(m).padStart(2, "0")}`;
      const { year, week } = isoWeek(nowMs);
      return `c-w-${year}-W${String(week).padStart(2, "0")}`;
    }
    case "fixed_period": {
      const start = Date.parse(w.anchor);
      const elapsed = nowMs - start;
      // Floor toward negative infinity so instants before the anchor land in
      // negative periods rather than all collapsing into period 0.
      const period = Math.floor(elapsed / (w.durationSeconds * 1000));
      return `f-${w.durationSeconds}-${period}`;
    }
  }
}

/** When the current bucket ends, so a caller can TTL the counter. */
export function windowEndsAt(w: WindowSpec, nowMs: number): number | null {
  assertValidWindow(w);
  switch (w.type) {
    case "rolling":
      return null; // continuous; nothing to expire
    case "calendar": {
      const { y, m, d } = utcParts(nowMs);
      if (w.unit === "day") return Date.UTC(y, m - 1, d + 1);
      if (w.unit === "month") return Date.UTC(y, m, 1);
      const { year, week } = isoWeek(nowMs);
      const jan4 = Date.UTC(year, 0, 4);
      const jan4Day = (new Date(jan4).getUTCDay() + 6) % 7;
      const week1Monday = jan4 - jan4Day * 86_400_000;
      return week1Monday + week * 7 * 86_400_000;
    }
    case "fixed_period": {
      const start = Date.parse(w.anchor);
      const len = w.durationSeconds * 1000;
      const period = Math.floor((nowMs - start) / len);
      return start + (period + 1) * len;
    }
  }
}

// ── Authorization classes and approval evidence ────────────────────────────

/**
 * How a payment was authorized.
 *
 * DIRECT and DELEGATED are cryptographically distinguishable in AP2: the direct
 * flow has the user signing closed mandates on a Trusted Surface, while the
 * autonomous flow uses open mandates that carry the agent's public key as a
 * `cnf` claim and are closed by the agent's own signature. STEP_UP is the
 * interesting one — delegated authority exists, but this particular payment
 * needs fresh human evidence on top of it.
 */
export type AuthorizationClass = "DIRECT" | "DELEGATED" | "STEP_UP";

/**
 * What the payment carries as proof.
 *
 * `verified` is supplied by the caller, not decided here. Signature checking
 * needs keys and a curve; this module stays pure and dependency-free so the
 * same evaluation runs identically in the payer-side gate and the facilitator.
 * A caller that passes `verified: true` without checking has lied to its own
 * enforcement layer, which no amount of logic here can defend against.
 */
export interface AuthorizationEvidence {
  class: AuthorizationClass;
  /** Binds the evidence to ONE payment. Compared, never trusted loose. */
  paymentHash: string;
  /** Result of verifying the signature over `paymentHash`. */
  verified: boolean;
  /** Present for STEP_UP: when the human evidence was produced. */
  approvedAtMs?: number;
}

export interface ThresholdPolicy {
  /** Above this, DELEGATED alone is not enough. Omit for no threshold. */
  requireApprovalAbove?: Atomic;
  /** Hard ceiling. Nothing settles above it, with any evidence. */
  denyAbove?: Atomic;
  /**
   * How stale step-up evidence may be. Without a bound, an approval signed
   * once could authorize above-threshold payments indefinitely, which is the
   * thing a threshold exists to prevent.
   */
  stepUpMaxAgeSeconds?: number;
}

export type SpendDecision = "AUTHORIZED" | "REQUIRE_APPROVAL" | "DENY";

export interface SpendEvaluation {
  decision: SpendDecision;
  /** Stable, loggable, and safe to put in a receipt. */
  reason: string;
}

export interface EvaluateSpendParams {
  amount: Atomic;
  policy: ThresholdPolicy;
  evidence: AuthorizationEvidence;
  /** The payment this evaluation is about. */
  paymentHash: string;
  nowMs: number;
  /**
   * WHERE this is running, and it changes the OUTCOME, not just the wording.
   *
   * `pre_signing` may answer REQUIRE_APPROVAL: there is still a human to ask.
   * `settlement` may not — a facilitator has two moves, settle or refuse, so an
   * unmet approval requirement collapses to DENY. Running one evaluator in two
   * modes is what keeps the two layers from drifting apart; running two
   * evaluators is how they drift.
   */
  mode: "pre_signing" | "settlement";
}

function gt(a: Atomic, b: Atomic): boolean {
  return BigInt(a) > BigInt(b);
}

/**
 * The single decision function, shared by both layers.
 *
 * Order is deliberate: the hard ceiling is checked before anything else, so no
 * quantity of evidence can talk a payment past `denyAbove`.
 */
export function evaluateSpendAuthorization(p: EvaluateSpendParams): SpendEvaluation {
  let amount: bigint;
  try {
    amount = BigInt(p.amount);
  } catch {
    return { decision: "DENY", reason: "amount_unparseable" };
  }
  if (amount <= 0n) return { decision: "DENY", reason: "amount_not_positive" };

  // 1. Hard ceiling first — unconditional.
  if (p.policy.denyAbove !== undefined && gt(p.amount, p.policy.denyAbove)) {
    return { decision: "DENY", reason: "above_deny_ceiling" };
  }

  // 2. The evidence must be about THIS payment. An approval for a different
  //    payment is not weaker evidence, it is evidence of something else.
  if (p.evidence.paymentHash !== p.paymentHash) {
    return { decision: "DENY", reason: "evidence_bound_to_other_payment" };
  }
  if (!p.evidence.verified) {
    return { decision: "DENY", reason: "evidence_signature_unverified" };
  }

  // 3. Below the threshold, delegated authority is sufficient.
  const needsApproval =
    p.policy.requireApprovalAbove !== undefined && gt(p.amount, p.policy.requireApprovalAbove);
  if (!needsApproval) {
    return { decision: "AUTHORIZED", reason: "within_delegated_authority" };
  }

  // 4. Above it, only fresh human evidence will do.
  if (p.evidence.class === "DIRECT") {
    // The human signed this payment itself; there is nothing to step up from.
    return { decision: "AUTHORIZED", reason: "human_present" };
  }

  if (p.evidence.class === "STEP_UP") {
    const maxAge = p.policy.stepUpMaxAgeSeconds;
    if (maxAge !== undefined) {
      if (p.evidence.approvedAtMs === undefined) {
        return { decision: "DENY", reason: "step_up_missing_timestamp" };
      }
      const ageMs = p.nowMs - p.evidence.approvedAtMs;
      // A future-dated approval is not "very fresh", it is wrong.
      if (ageMs < 0) return { decision: "DENY", reason: "step_up_timestamp_in_future" };
      if (ageMs > maxAge * 1000) return { decision: "DENY", reason: "step_up_evidence_stale" };
    }
    return { decision: "AUTHORIZED", reason: "step_up_evidence_valid" };
  }

  // DELEGATED, above the threshold: the payer-side gate can still go and ask.
  // The facilitator cannot, so for it this is simply a refusal.
  return p.mode === "pre_signing"
    ? { decision: "REQUIRE_APPROVAL", reason: "above_threshold_needs_human" }
    : { decision: "DENY", reason: "above_threshold_without_step_up_evidence" };
}
