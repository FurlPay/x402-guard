import {
  evaluateSpendAuthorization,
  type AuthorizationEvidence,
  type WindowSpec,
  assertValidWindow,
} from "./mandate.js";

// ---------------------------------------------------------------------------
// The canonical settlement authorization, and the one pure function that
// decides whether it may settle.
//
// TWO PROBLEMS THIS EXISTS TO FIX.
//
// 1. MULTIPLE REPRESENTATIONS. If each gate rebuilds its own view of "the
//    payment", authorization can check one representation while settlement
//    checks another, and the gap between them is where an unauthorized payment
//    lives. `SettlementAuthorization` is canonicalized ONCE by the caller and
//    then evaluated everywhere; nothing here reconstructs it.
//
// 2. FLOATING-POINT MONEY. The mandate model in @furlpay/agent-trust expresses
//    caps as `maxTotalUsd: number` and checks them with
//    `spent + amountUsd > maxTotalUsd`. That is arithmetic no security boundary
//    should be built on, and it fails in both directions:
//
//      0.1 + 0.2 > 0.3            -> TRUE. A user with a $0.30 cap who has
//                                   spent $0.10 is refused a legitimate $0.20.
//      69 additions of 0.1        -> 6.8999999999999915, not 6.90. A payer and
//                                   a facilitator summing in different orders
//                                   reach different totals and disagree about
//                                   how much budget is left.
//
//    Everything below is integer atomic units carried as strings and compared
//    as bigint. No float ever touches a limit.
// ---------------------------------------------------------------------------

/** Integer minor units as a decimal string, e.g. "10000" = 0.01 USDC. */
export type AtomicAmount = string;

/**
 * One payment, canonicalized.
 *
 * Every field a policy can decide on is here, so a decision is a function of
 * this object alone. `paymentHash` commits to it; the individual fields are
 * present so the evaluator can say WHICH constraint failed rather than only
 * that the hash did not match.
 */
export interface SettlementAuthorization {
  mandateId: string;
  agentKeyId: string;
  buyerKeyId: string;
  network: string;
  asset: string;
  amountAtomic: AtomicAmount;
  seller: string;
  resource: string;
  method: string;
  paymentHash: string;
  nonce: string;
  policyVersion: string;
}

/** Explicit, because absence is not a lifecycle state. */
export type MandateStatus = "ACTIVE" | "REVOKED" | "EXPIRED";

/**
 * The signed mandate, as the facilitator holds it.
 *
 * `status` is stored rather than inferred: "no record" and "revoked" are
 * different facts, and a store that cannot tell them apart answers ALLOW after
 * a cache eviction. The caller resolves it; this function only reads it.
 */
export interface MandatePolicy {
  mandateId: string;
  /** The ONE agent this mandate empowers. */
  agentKeyId: string;
  /** The user who signed it. */
  buyerKeyId: string;
  status: MandateStatus;
  maxPerTxAtomic: AtomicAmount;
  maxPerWindowAtomic: AtomicAmount;
  window: WindowSpec;
  /** Asset and network the caps are denominated in. */
  asset: string;
  network: string;
  /** Glob patterns, e.g. "*.furlpay.com". Omitted or empty = any seller. */
  allowedSellers?: string[];
  /** Glob patterns over the resource path. Omitted or empty = any resource. */
  allowedResources?: string[];
  /** ISO 8601. */
  notBefore?: string;
  expiresAt: string;
  /** Above this, delegated authority alone is not enough. */
  requireApprovalAboveAtomic?: AtomicAmount;
  stepUpMaxAgeSeconds?: number;
  policyVersion: string;
}

export type MandateDenial =
  | "amount_unparseable"
  | "amount_not_positive"
  | "mandate_revoked"
  | "mandate_expired"
  | "mandate_not_yet_valid"
  | "agent_mismatch"
  | "buyer_mismatch"
  | "asset_mismatch"
  | "network_mismatch"
  | "seller_not_allowed"
  | "resource_not_allowed"
  | "per_tx_limit_exceeded"
  | "window_limit_exceeded"
  | "policy_version_mismatch"
  | "approval_required"
  | "approval_invalid";

export interface MandateEvaluation {
  allowed: boolean;
  reason?: MandateDenial;
  /** True when the amount crossed the threshold, whether or not it was met. */
  requiresApproval: boolean;
  policyVersion: string;
  /** Echoed so a receipt can record what was evaluated, not re-derive it. */
  evaluated: {
    amountAtomic: AtomicAmount;
    windowSpentBeforeAtomic: AtomicAmount;
    windowSpentAfterAtomic: AtomicAmount;
    paymentHash: string;
  };
}

export interface EvaluateMandateParams {
  policy: MandatePolicy;
  authorization: SettlementAuthorization;
  /**
   * Spend already recorded in the current window, atomic.
   *
   * Passed in rather than read, because this function must stay pure: the same
   * inputs give the same answer, so the whole policy is testable without Redis,
   * a clock, or a network.
   */
  windowSpentAtomic: AtomicAmount;
  /** Step-up evidence, already signature-checked by the caller. */
  approval?: AuthorizationEvidence;
  nowMs: number;
}

/**
 * Glob match supporting a single leading `*.` wildcard, plus bare `*`.
 *
 * Deliberately not a general glob: a pattern language rich enough to be
 * interesting is rich enough to have surprising matches, and this one decides
 * who may be paid. `*.example.com` matches a subdomain and NOT the apex, which
 * is the conservative reading — a mandate for `*.example.com` did not say
 * `example.com`.
 */
export function matchesPattern(value: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1); // ".example.com"
    return value.endsWith(suffix) && value.length > suffix.length;
  }
  return value === pattern;
}

function allowedBy(list: string[] | undefined, value: string): boolean {
  if (!list || list.length === 0) return true; // unconstrained
  return list.some((p) => matchesPattern(value, p));
}

function parseAtomic(v: string): bigint | null {
  if (typeof v !== "string" || !/^-?\d+$/.test(v.trim())) return null;
  try {
    return BigInt(v.trim());
  } catch {
    return null;
  }
}

/**
 * Decide whether this payment may settle under this mandate.
 *
 * PURE. No Redis, no clock of its own, no settlement call, no side effects.
 * That is what makes the ~20 denial paths exhaustively testable without a
 * network, and what lets the payer-side gate run the identical function.
 *
 * Order is deliberate: identity and lifecycle before limits, limits before
 * approval. A revoked mandate must not be able to produce "approval required"
 * as its reason, because that invites a caller to go and get one.
 */
export function evaluateMandate(p: EvaluateMandateParams): MandateEvaluation {
  const { policy, authorization: a } = p;

  const amount = parseAtomic(a.amountAtomic);
  const spent = parseAtomic(p.windowSpentAtomic);
  const perTx = parseAtomic(policy.maxPerTxAtomic);
  const perWindow = parseAtomic(policy.maxPerWindowAtomic);

  const base = {
    requiresApproval: false,
    policyVersion: policy.policyVersion,
    evaluated: {
      amountAtomic: a.amountAtomic,
      windowSpentBeforeAtomic: p.windowSpentAtomic,
      windowSpentAfterAtomic: p.windowSpentAtomic,
      paymentHash: a.paymentHash,
    },
  };

  if (amount === null || spent === null || perTx === null || perWindow === null) {
    return { ...base, allowed: false, reason: "amount_unparseable" };
  }
  if (amount <= 0n) return { ...base, allowed: false, reason: "amount_not_positive" };

  const after = spent + amount;
  const withTotals = {
    ...base,
    evaluated: { ...base.evaluated, windowSpentAfterAtomic: after.toString() },
  };

  // Version first: an old mandate evaluated under new semantics is a mandate
  // whose author agreed to different rules than the ones being applied.
  if (policy.policyVersion !== a.policyVersion) {
    return { ...withTotals, allowed: false, reason: "policy_version_mismatch" };
  }

  // Lifecycle.
  if (policy.status === "REVOKED") {
    return { ...withTotals, allowed: false, reason: "mandate_revoked" };
  }
  if (policy.status === "EXPIRED") {
    return { ...withTotals, allowed: false, reason: "mandate_expired" };
  }
  const expiresAt = Date.parse(policy.expiresAt);
  if (!Number.isFinite(expiresAt) || p.nowMs >= expiresAt) {
    return { ...withTotals, allowed: false, reason: "mandate_expired" };
  }
  if (policy.notBefore) {
    const notBefore = Date.parse(policy.notBefore);
    if (Number.isFinite(notBefore) && p.nowMs < notBefore) {
      return { ...withTotals, allowed: false, reason: "mandate_not_yet_valid" };
    }
  }

  // Identity. A mandate empowers ONE agent for ONE user.
  if (policy.agentKeyId !== a.agentKeyId) {
    return { ...withTotals, allowed: false, reason: "agent_mismatch" };
  }
  if (policy.buyerKeyId !== a.buyerKeyId) {
    return { ...withTotals, allowed: false, reason: "buyer_mismatch" };
  }

  // Denomination. A cap in USDC-on-Base says nothing about a payment in another
  // asset, and comparing the two numbers would be comparing unlike units.
  if (policy.asset !== a.asset) {
    return { ...withTotals, allowed: false, reason: "asset_mismatch" };
  }
  if (policy.network !== a.network) {
    return { ...withTotals, allowed: false, reason: "network_mismatch" };
  }

  // Scope.
  if (!allowedBy(policy.allowedSellers, a.seller)) {
    return { ...withTotals, allowed: false, reason: "seller_not_allowed" };
  }
  if (!allowedBy(policy.allowedResources, a.resource)) {
    return { ...withTotals, allowed: false, reason: "resource_not_allowed" };
  }

  // Limits, in integers. `>` not `>=`: spending exactly the cap is permitted,
  // which is what a cap means.
  if (amount > perTx) {
    return { ...withTotals, allowed: false, reason: "per_tx_limit_exceeded" };
  }
  if (after > perWindow) {
    return { ...withTotals, allowed: false, reason: "window_limit_exceeded" };
  }

  // Threshold and evidence, delegated to the single evaluator both layers use
  // so the two cannot drift apart.
  const threshold = policy.requireApprovalAboveAtomic;
  const requiresApproval = threshold !== undefined && amount > (parseAtomic(threshold) ?? 0n);
  if (!requiresApproval) {
    return { ...withTotals, allowed: true, requiresApproval: false };
  }

  if (!p.approval) {
    return { ...withTotals, allowed: false, requiresApproval: true, reason: "approval_required" };
  }

  const verdict = evaluateSpendAuthorization({
    amount: a.amountAtomic,
    policy: {
      requireApprovalAbove: threshold,
      stepUpMaxAgeSeconds: policy.stepUpMaxAgeSeconds,
    },
    evidence: p.approval,
    paymentHash: a.paymentHash,
    nowMs: p.nowMs,
    // At this layer there is no human to ask — this IS the settlement decision.
    mode: "settlement",
  });

  if (verdict.decision !== "AUTHORIZED") {
    return { ...withTotals, allowed: false, requiresApproval: true, reason: "approval_invalid" };
  }
  return { ...withTotals, allowed: true, requiresApproval: true };
}

/** Re-exported so callers validate a mandate's window before signing it. */
export { assertValidWindow };
