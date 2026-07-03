// ---------------------------------------------------------------------------
// @furlpay/x402-guard — facilitator-layer hardening for the x402 agentic
// payment protocol.
//
// x402 decouples off-chain verification from on-chain settlement for
// throughput. That gap is where the money leaks. "Free-Riding the Agentic
// Web: A Systematic Security Analysis of x402 Payments" (Ling et al.,
// arXiv:2605.30998) catalogues five flaw classes against production x402
// deployments, reaching resource-leakage ratios up to 100%. This library
// implements the paper's protocol/SDK-layer fixes so a facilitator preserves
// the invariants a naïve one violates:
//
//   F1  Cross-resource substitution (violates I3, Context Binding)
//        → §5.1 Cryptographic Context Binding: commit H(method|uri|body) into
//          the authorization and reject any payment presented for a different
//          request. Closes the "Pattern 3: blind trust in facilitator" gap
//          where a stateless verify() checks value+payee but not the resource.
//
//   F2  Duplicate-settlement race (violates I4, Authorization Uniqueness)
//        → §5.2 Stateful Nonce Linearization: a nonce moves Null → PENDING →
//          SETTLED via an atomic check-and-set. Concurrent requests carrying
//          the same nonce cannot all clear verification; only the first
//          acquires the lock. A settlement whose outcome is UNKNOWN (timeout)
//          is never rolled back to Null — the classic replay hole.
//
//   F3  Allowance overdraft, "upto" scheme (violates I5, Balance Sufficiency)
//        → §5.3 Pessimistic Reserve-Commit: atomically move Vmax from the
//          allowance to escrow BEFORE execution, bill the actual amount at
//          settle, refund the remainder. Concurrent read-then-deduct is the
//          overdraft; the atomic reserve is the fix.
//
//   F4  Denial of settlement (violates I2, Settlement Guarantee)
//        → §5.4 Failure-Closed Capacity Reservation: reserve settlement
//          capacity before delivering the resource. When capacity is
//          exhausted, reject (HTTP 429) rather than serve and hope the
//          settlement queue drains — never deliver for free.
//
//   F5  Hidden-compute pricing (G2, dynamic per-token billing)
//        → §5.5 Adaptive Billing Weight: for pay-per-token inference the true
//          cost is unknown at quote time; a fixed quote lets an adversary
//          maximize compute per price. Learn the observed actual/estimated
//          ratio (EWMA) and quote Vmax = estimate × ratio × margin — feed it
//          into the F3 escrow so honest callers get the overshoot refunded.
//
// Zero dependencies. The nonce store is an interface: the in-memory default is
// correct within one process; back it with Redis SETNX for multi-instance
// facilitators (the atomic check-and-set maps directly).
// ---------------------------------------------------------------------------

import crypto from "crypto";

// ── F1: Cryptographic Context Binding (paper §5.1) ─────────────────────────

/**
 * Canonical hash of the HTTP request an authorization is meant to pay for.
 * The paper signs H(Req) = H(Method ∥ URI ∥ Body) into the EIP-712 payload;
 * here we compute the same commitment so a facilitator can verify it even
 * when the underlying scheme's signed fields omit the resource.
 */
export function requestBindingHash(method: string, uri: string, body: string | Buffer = ""): string {
  const b = typeof body === "string" ? body : body.toString("utf8");
  return crypto
    .createHash("sha256")
    .update(`${method.toUpperCase()}\n${uri}\n${b}`)
    .digest("hex");
}

/**
 * Constant-time check that a presented binding matches the request actually
 * being served. Returns false on any mismatch or malformed input — never
 * throws, so a caller can fail closed.
 */
export function verifyRequestBinding(
  presentedBinding: string | undefined,
  method: string,
  uri: string,
  body: string | Buffer = ""
): boolean {
  if (!presentedBinding) return false;
  const expected = requestBindingHash(method, uri, body);
  const a = Buffer.from(expected);
  const b = Buffer.from(presentedBinding);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ── F2: Stateful Nonce Linearization (paper §5.2) ──────────────────────────

export type NonceState = "pending" | "settled";

/**
 * The linearization barrier. `acquire` is an atomic check-and-set: it succeeds
 * only if the nonce is currently unknown (Null), transitioning it to PENDING.
 * A production implementation is a Redis `SET key PENDING NX` (or Postgres
 * `INSERT … ON CONFLICT DO NOTHING`); the contract is that at most one caller
 * ever gets `true` for a given nonce until it is released.
 */
export interface NonceStore {
  /** Atomically claim `nonce` if unknown. Returns true iff this caller won. */
  acquire(nonce: string): boolean | Promise<boolean>;
  /** Promote a claimed nonce to SETTLED (terminal — never replayable). */
  markSettled(nonce: string): void | Promise<void>;
  /** Release a claimed nonce back to Null (ONLY when the chain proves no tx landed). */
  release(nonce: string): void | Promise<void>;
  state(nonce: string): NonceState | undefined | Promise<NonceState | undefined>;
}

/** In-memory NonceStore. Correct within one process; swap for Redis at scale. */
export class MemoryNonceStore implements NonceStore {
  private readonly states = new Map<string, NonceState>();

  acquire(nonce: string): boolean {
    // Synchronous check-and-set: no await between read and write, so within a
    // single Node process this is atomic against concurrent settle() calls.
    if (this.states.has(nonce)) return false;
    this.states.set(nonce, "pending");
    return true;
  }
  markSettled(nonce: string): void {
    this.states.set(nonce, "settled");
  }
  release(nonce: string): void {
    if (this.states.get(nonce) === "pending") this.states.delete(nonce);
  }
  state(nonce: string): NonceState | undefined {
    return this.states.get(nonce);
  }
}

// ── Guarded settle wrapper (failure-closed, paper §5.4) ────────────────────

/**
 * The outcome a settler reports back. The critical distinction the paper draws
 * is between a settlement that provably did NOT land (safe to release the
 * nonce) and one whose result is UNKNOWN — a facilitator timeout while the tx
 * may still confirm. Rolling the latter back to Null is the F2/F4 replay hole.
 */
export type SettleOutcome =
  | { status: "confirmed"; transaction: string }
  | { status: "failed_no_tx" } // chain proves nothing settled → release
  | { status: "unknown" }; // timeout / indeterminate → keep PENDING, never free

export type GuardedSettler<TReq> = (req: TReq) => Promise<SettleOutcome> | SettleOutcome;

export interface GuardResult {
  success: boolean;
  transaction?: string;
  reason?: string;
}

export interface GuardOptions<TReq> {
  nonce: string;
  store: NonceStore;
  settler: GuardedSettler<TReq>;
  /** Optional F1 binding check — supply the request context to enforce it. */
  binding?: { presented: string | undefined; method: string; uri: string; body?: string | Buffer };
  /** Optional F4 gate — settlement capacity is reserved before the nonce is claimed. */
  capacity?: SettlementCapacityLimiter;
}

// ── F4: Failure-Closed Capacity Reservation (paper §5.4) ───────────────────

/**
 * The denial-of-settlement attack floods a facilitator with slow settlements
 * until honest ones time out — and a server that has already delivered the
 * resource eats the loss. The paper's fix inverts the order: reserve
 * settlement capacity FIRST, and if none is available return 429 *instead of
 * serving*. Failing closed converts a free-riding vector into ordinary
 * back-pressure.
 *
 * Reservation is a synchronous check-and-increment — atomic within one Node
 * process. For a multi-instance facilitator, map it onto Redis `INCR` with a
 * bound check (DECR on release), same shape as the NonceStore.
 */
export class SettlementCapacityLimiter {
  private inFlightCount = 0;

  constructor(private readonly maxConcurrent: number) {
    if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1) {
      throw new RangeError("maxConcurrent must be a positive integer");
    }
  }

  /**
   * Claim one settlement slot. Returns a release function, or null when
   * capacity is exhausted (caller must refuse service — HTTP 429). The
   * release function is idempotent, so calling it from a `finally` is safe.
   */
  tryReserve(): (() => void) | null {
    if (this.inFlightCount >= this.maxConcurrent) return null;
    this.inFlightCount++;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.inFlightCount--;
    };
  }

  get inFlight(): number {
    return this.inFlightCount;
  }
  get available(): number {
    return this.maxConcurrent - this.inFlightCount;
  }
}

/**
 * Verify-once, settle-once. Wraps a settler with the paper's two defenses:
 * F1 (optional request-binding gate) and F2 (atomic nonce linearization with
 * failure-closed release semantics).
 */
export async function guardedSettle<TReq>(req: TReq, opts: GuardOptions<TReq>): Promise<GuardResult> {
  const { nonce, store, settler, binding, capacity } = opts;

  // F1: reject a payment presented for a different resource before doing work.
  if (binding) {
    const ok = verifyRequestBinding(binding.presented, binding.method, binding.uri, binding.body ?? "");
    if (!ok) return { success: false, reason: "resource_binding_mismatch" };
  }

  // F4: reserve settlement capacity before touching the nonce, so a rejected
  // request leaves the authorization intact for an honest retry (map to 429).
  const releaseCapacity = capacity ? capacity.tryReserve() : undefined;
  if (capacity && !releaseCapacity) {
    return { success: false, reason: "settlement_capacity_exhausted" };
  }

  try {
    // F2: atomic claim. Losers of the race are rejected here, before any work.
    const won = await store.acquire(nonce);
    if (!won) {
      const s = await store.state(nonce);
      return { success: false, reason: s === "settled" ? "nonce_already_settled" : "nonce_in_flight" };
    }

    let outcome: SettleOutcome;
    try {
      outcome = await settler(req);
    } catch {
      // An exception is indeterminate — treat as UNKNOWN, keep the nonce locked.
      return { success: false, reason: "settlement_unknown_locked" };
    }

    if (outcome.status === "confirmed") {
      await store.markSettled(nonce);
      return { success: true, transaction: outcome.transaction };
    }
    if (outcome.status === "failed_no_tx") {
      await store.release(nonce); // chain proved no settlement → safe to retry
      return { success: false, reason: "settlement_failed" };
    }
    // unknown: do NOT release — a later confirmation must not be replayable.
    return { success: false, reason: "settlement_unknown_locked" };
  } finally {
    releaseCapacity?.();
  }
}

// ── F3: Pessimistic Reserve-Commit for "upto" allowances (paper §5.3) ──────

/**
 * The overdraft: with the upto scheme a server bills actual usage against a
 * signed allowance. A read-then-deduct implementation lets N concurrent
 * requests each see the full remaining balance and all proceed — total spend
 * N × Vmax against a balance of Vmax. The fix is an escrow: atomically move
 * Vmax out of the allowance BEFORE execution, then commit the actual amount
 * and refund the rest.
 *
 * Amounts are bigint (atomic units, e.g. USDC 6-decimals). The in-memory
 * store is atomic within one process; in production map `reserve` onto a
 * conditional decrement (`UPDATE … SET remaining = remaining - $1 WHERE
 * remaining >= $1` / Lua on Redis).
 */
export interface AllowanceStore {
  /** Atomically escrow `vmax` if the allowance covers it. Returns a reservation id, or null (insufficient / unknown allowance). */
  reserve(allowanceId: string, vmax: bigint): string | null | Promise<string | null>;
  /** Settle a reservation: bill `actual` (clamped to the reserved amount), refund the remainder. Returns the amount charged. */
  commit(reservationId: string, actual: bigint): bigint | Promise<bigint>;
  /** Cancel a reservation, refunding the full escrow (execution provably did no billable work). */
  release(reservationId: string): void | Promise<void>;
  remaining(allowanceId: string): bigint | undefined | Promise<bigint | undefined>;
}

/** In-memory AllowanceStore. Correct within one process; swap for SQL/Redis at scale. */
export class MemoryAllowanceStore implements AllowanceStore {
  private readonly balances = new Map<string, bigint>();
  private readonly reservations = new Map<string, { allowanceId: string; amount: bigint }>();
  private seq = 0;

  /** Register an allowance (e.g. on receipt of a signed upto authorization). */
  create(allowanceId: string, total: bigint): void {
    if (total < 0n) throw new RangeError("allowance total must be non-negative");
    this.balances.set(allowanceId, total);
  }

  reserve(allowanceId: string, vmax: bigint): string | null {
    // Synchronous check-and-decrement — the atomicity that read-then-deduct lacks.
    const remaining = this.balances.get(allowanceId);
    if (remaining === undefined || vmax <= 0n || remaining < vmax) return null;
    this.balances.set(allowanceId, remaining - vmax);
    const id = `res-${++this.seq}`;
    this.reservations.set(id, { allowanceId, amount: vmax });
    return id;
  }

  commit(reservationId: string, actual: bigint): bigint {
    const r = this.reservations.get(reservationId);
    if (!r) return 0n; // unknown or already settled — idempotent
    this.reservations.delete(reservationId);
    // Never bill outside [0, reserved] — the escrow is the hard ceiling.
    const charged = actual < 0n ? 0n : actual > r.amount ? r.amount : actual;
    this.balances.set(r.allowanceId, (this.balances.get(r.allowanceId) ?? 0n) + (r.amount - charged));
    return charged;
  }

  release(reservationId: string): void {
    this.commit(reservationId, 0n);
  }

  remaining(allowanceId: string): bigint | undefined {
    return this.balances.get(allowanceId);
  }
}

export type ChargeResult<T> =
  | { success: true; value: T; charged: bigint }
  | { success: false; reason: "allowance_exhausted" | "execution_failed" };

/**
 * Reserve-execute-commit in one call: escrows `vmax`, runs `execute`, bills
 * the actual amount it reports and refunds the difference. If `execute`
 * throws, the full escrow is refunded — nothing billable was delivered.
 * (If your execution can partially deliver before failing, call the store
 * directly and commit the partial amount instead.)
 */
export async function guardedCharge<T>(opts: {
  allowanceId: string;
  vmax: bigint;
  store: AllowanceStore;
  execute: () => Promise<{ actual: bigint; value: T }> | { actual: bigint; value: T };
}): Promise<ChargeResult<T>> {
  const reservation = await opts.store.reserve(opts.allowanceId, opts.vmax);
  if (!reservation) return { success: false, reason: "allowance_exhausted" };

  let result: { actual: bigint; value: T };
  try {
    result = await opts.execute();
  } catch {
    await opts.store.release(reservation);
    return { success: false, reason: "execution_failed" };
  }

  const charged = await opts.store.commit(reservation, result.actual);
  return { success: true, value: result.value, charged };
}

// ── F5: Adaptive Billing Weight for hidden-compute pricing (paper §5.5) ────

/**
 * Pay-per-token inference prices a request before its true compute cost is
 * known — the paper's G2: an adversary crafts prompts that maximize output
 * tokens per fixed quote and free-rides the difference. There is no static
 * fix (the cost is genuinely unknowable up front); the defense is adaptive:
 * learn the observed actual/estimated ratio and quote enough headroom that
 * the F3 escrow always covers the realized bill. Honest callers are refunded
 * the overshoot at commit, so the margin costs them nothing.
 *
 * `quoteMax` → Vmax for `guardedCharge`; `bill(actualUnits)` → the amount to
 * commit; `observe` → feed back each settlement so the weight tracks the
 * traffic actually being served.
 */
export interface AdaptivePricerOptions {
  /** Price per billed unit (e.g. per output token), in atomic currency units. */
  unitPrice: bigint;
  /** EWMA smoothing factor in (0, 1]; higher adapts faster. Default 0.2. */
  alpha?: number;
  /** Multiplicative headroom on quotes. Default 1.25. */
  safetyMargin?: number;
  /** Floor for the learned ratio — 1 means never quote below the caller's own estimate. Default 1. */
  minRatio?: number;
  /** Ceiling for the learned ratio, bounding how far one abuse wave can inflate quotes. Default 10. */
  maxRatio?: number;
}

export class AdaptivePricer {
  private readonly unitPrice: bigint;
  private readonly alpha: number;
  private readonly safetyMargin: number;
  private readonly minRatio: number;
  private readonly maxRatio: number;
  private ewmaRatio: number;

  constructor(opts: AdaptivePricerOptions) {
    if (opts.unitPrice <= 0n) throw new RangeError("unitPrice must be positive");
    this.unitPrice = opts.unitPrice;
    this.alpha = opts.alpha ?? 0.2;
    this.safetyMargin = opts.safetyMargin ?? 1.25;
    this.minRatio = opts.minRatio ?? 1;
    this.maxRatio = opts.maxRatio ?? 10;
    if (this.alpha <= 0 || this.alpha > 1) throw new RangeError("alpha must be in (0, 1]");
    if (this.minRatio > this.maxRatio) throw new RangeError("minRatio must not exceed maxRatio");
    this.ewmaRatio = this.minRatio;
  }

  /** Vmax to demand (and escrow via F3) for a request estimated at `estimatedUnits`. */
  quoteMax(estimatedUnits: number): bigint {
    if (!(estimatedUnits > 0)) throw new RangeError("estimatedUnits must be positive");
    const units = Math.ceil(estimatedUnits * this.ewmaRatio * this.safetyMargin);
    return BigInt(units) * this.unitPrice;
  }

  /** The settle-time bill for the compute actually consumed. */
  bill(actualUnits: number): bigint {
    if (!(actualUnits >= 0)) throw new RangeError("actualUnits must be non-negative");
    return BigInt(Math.ceil(actualUnits)) * this.unitPrice;
  }

  /** Feed back a completed settlement so the weight tracks real traffic. */
  observe(estimatedUnits: number, actualUnits: number): void {
    if (!(estimatedUnits > 0) || !(actualUnits >= 0)) return;
    const observed = Math.min(actualUnits / estimatedUnits, this.maxRatio);
    const next = this.ewmaRatio * (1 - this.alpha) + observed * this.alpha;
    this.ewmaRatio = Math.min(Math.max(next, this.minRatio), this.maxRatio);
  }

  get ratio(): number {
    return this.ewmaRatio;
  }
}
