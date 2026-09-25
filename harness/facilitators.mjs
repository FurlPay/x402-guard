// ---------------------------------------------------------------------------
// The two facilitators under test, plus the simulated chain they both settle
// against. Both expose the SAME surface so a scenario is written once and run
// against each — any difference in reported leakage is attributable to the
// defense and nothing else.
//
// THE FLOW BEING MODELLED is x402's, not a generic request/response:
//
//   1. client presents a payment payload
//   2. server calls verify()   — off-chain, fast, no chain round-trip
//   3. server DELIVERS the resource
//   4. server calls settle()   — on-chain, slow
//
// Step 3 sitting before step 4 is not a bug; it is the entire reason x402
// splits verification from settlement. Every flaw below lives in that gap.
// Ling et al.'s §5.2 fix is therefore applied at step 2 — a duplicate must fail
// VERIFICATION, because by step 4 the resource is already gone.
//
// ON THE FAITHFULNESS OF THE BASELINE. A strawman baseline would make this
// harness worthless. Each vulnerable behaviour is a pattern the paper observed
// in shipping x402 code:
//
//   - verify() checks value and payee but not the resource ("Pattern 3: blind
//     trust in facilitator", found near-universal). A stateless facilitator has
//     no idea which resource the caller is about to receive.
//   - verify() is stateless with respect to the nonce, so N concurrent callers
//     presenting one authorization all pass.
//   - Settlement capacity is discovered at settle() time — after delivery.
//   - The quote is fixed from the caller's own estimate, because at request
//     time the true compute cost genuinely is not known.
//
// None of these is stupid. That is why the paper found them everywhere.
// ---------------------------------------------------------------------------

import {
  MemoryNonceStore,
  MemoryAllowanceStore,
  SettlementCapacityLimiter,
  AdaptivePricer,
  guardedCharge,
  verifyRequestBinding,
} from "../dist/index.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * The chain, as physics rather than policy.
 *
 * An x402 authorization carries a nonce that the token contract consumes on
 * transfer (EIP-3009 `authorizationState`, or a consumed SPL nonce account).
 * One authorization moves funds exactly once, no matter how many times a
 * facilitator submits it. Modelling that is what makes the F2 measurement
 * meaningful: the merchant may serve twenty times, but only one settlement can
 * ever land, and the other nineteen are the leak.
 *
 * A facilitator cannot opt out of this, so both implementations share it.
 */
export class SimulatedChain {
  #consumed = new Set();
  confirmed = 0;

  async settle(nonce, { latencyMs = 5, outcome = "confirmed" } = {}) {
    await sleep(latencyMs);
    if (outcome !== "confirmed") return { status: outcome };
    if (this.#consumed.has(nonce)) {
      // The authorization was already spent. The chain proves no second
      // transfer occurred, so this is `failed_no_tx`, not `unknown`.
      return { status: "failed_no_tx", reason: "authorization_already_consumed" };
    }
    this.#consumed.add(nonce);
    this.confirmed++;
    return { status: "confirmed", transaction: `0x${nonce}-${this.confirmed}` };
  }
}

// ── Baseline: a naïve-but-realistic x402 facilitator ───────────────────────

export class BaselineFacilitator {
  static label = "baseline (unguarded)";

  constructor({ settlementLatencyMs = 5, maxConcurrentSettlements = Infinity, chain } = {}) {
    this.chain = chain ?? new SimulatedChain();
    this.settlementLatencyMs = settlementLatencyMs;
    this.maxConcurrentSettlements = maxConcurrentSettlements;
    this.inFlight = 0;
    this.allowances = new Map();
  }

  /**
   * The stateless check the paper describes: is the payee right, is the value
   * enough? The resource being served never enters the comparison, and the
   * nonce is not consulted at all — so concurrent duplicates all pass.
   */
  verify({ price, offeredValue }) {
    return offeredValue >= price
      ? { ok: true }
      : { ok: false, reason: "insufficient_value" };
  }

  async settle({ nonce, outcome = "confirmed" }) {
    if (this.inFlight >= this.maxConcurrentSettlements) {
      // Capacity is discovered here — after the merchant has already served.
      // The refusal is cosmetic; the loss is booked. This is F4.
      return { success: false, reason: "settlement_queue_full" };
    }
    this.inFlight++;
    try {
      const res = await this.chain.settle(nonce, {
        latencyMs: this.settlementLatencyMs,
        outcome,
      });
      return res.status === "confirmed"
        ? { success: true, transaction: res.transaction }
        : { success: false, reason: res.reason ?? res.status };
    } finally {
      this.inFlight--;
    }
  }

  /** F3 surface: read the balance, then deduct. The gap between is the overdraft. */
  createAllowance(id, total) {
    this.allowances.set(id, BigInt(total));
  }

  async charge({ allowanceId, vmax, execute }) {
    const remaining = this.allowances.get(allowanceId);
    if (remaining === undefined || remaining < vmax) {
      return { success: false, reason: "allowance_exhausted" };
    }
    // Every concurrent caller reads the same `remaining` and all pass, because
    // the deduction happens only after an await.
    const result = await execute();
    this.allowances.set(allowanceId, this.allowances.get(allowanceId) - result.actual);
    return { success: true, value: result.value, charged: result.actual };
  }

  /** F5 surface: the quote is the caller's estimate, taken on trust. */
  quote({ estimatedUnits, unitPrice }) {
    return BigInt(Math.ceil(estimatedUnits)) * BigInt(unitPrice);
  }

  /** Billing is capped by the quote — compute beyond it is delivered free. */
  bill({ actualUnits, unitPrice, quoted }) {
    const full = BigInt(Math.ceil(actualUnits)) * BigInt(unitPrice);
    return full > quoted ? quoted : full;
  }

  observe() {
    /* a fixed quote learns nothing */
  }
}

// ── Guarded: the same facilitator wearing x402-guard ───────────────────────

export class GuardedFacilitator {
  static label = "guarded (x402-guard)";

  constructor({ settlementLatencyMs = 5, maxConcurrentSettlements = Infinity, chain, pricer } = {}) {
    this.chain = chain ?? new SimulatedChain();
    this.nonces = new MemoryNonceStore();
    this.allowanceStore = new MemoryAllowanceStore();
    this.settlementLatencyMs = settlementLatencyMs;
    this.capacity =
      maxConcurrentSettlements === Infinity
        ? undefined
        : new SettlementCapacityLimiter(maxConcurrentSettlements);
    // Capacity is reserved at verify() and released after settle(), so the
    // release handle has to survive between the two calls.
    this.heldCapacity = new Map();
    this.pricer =
      pricer ?? new AdaptivePricer({ unitPrice: 1n, alpha: 0.35, safetyMargin: 1.25, maxRatio: 20 });
  }

  /**
   * Admission control, which is where all three of F1, F2 and F4 must be
   * decided — after this returns ok, the resource is gone.
   *
   * The primitives are used directly rather than via `guardedSettle` because
   * that helper bundles the nonce claim with the settlement, which suits a
   * one-phase integration. x402 is two-phase, and the claim has to happen a
   * whole network round-trip before the settlement.
   */
  verify({ nonce, price, offeredValue, binding, method, uri, body }) {
    if (offeredValue < price) return { ok: false, reason: "insufficient_value" };

    // F1: is this authorization for the resource actually being requested?
    if (binding !== undefined) {
      if (!verifyRequestBinding(binding.presented, method, uri, body ?? "")) {
        return { ok: false, reason: "resource_binding_mismatch" };
      }
    }

    // F4: reserve settlement capacity BEFORE serving. Exhaustion becomes a 429
    // instead of a free resource.
    let release;
    if (this.capacity) {
      release = this.capacity.tryReserve();
      if (!release) return { ok: false, reason: "settlement_capacity_exhausted" };
    }

    // F2: atomic nonce claim. Only the first of N concurrent duplicates wins.
    if (nonce !== undefined && !this.nonces.acquire(nonce)) {
      release?.();
      const s = this.nonces.state(nonce);
      return { ok: false, reason: s === "settled" ? "nonce_already_settled" : "nonce_in_flight" };
    }

    if (release && nonce !== undefined) this.heldCapacity.set(nonce, release);
    else release?.();

    return { ok: true };
  }

  async settle({ nonce, outcome = "confirmed" }) {
    try {
      const res = await this.chain.settle(nonce, {
        latencyMs: this.settlementLatencyMs,
        outcome,
      });
      if (res.status === "confirmed") {
        this.nonces.markSettled(nonce);
        return { success: true, transaction: res.transaction };
      }
      if (res.status === "failed_no_tx") {
        // The chain proved nothing landed, so an honest retry is safe.
        this.nonces.release(nonce);
        return { success: false, reason: res.reason ?? "settlement_failed" };
      }
      // unknown: keep the nonce locked. Releasing it here is the replay hole.
      return { success: false, reason: "settlement_unknown_locked" };
    } finally {
      this.heldCapacity.get(nonce)?.();
      this.heldCapacity.delete(nonce);
    }
  }

  createAllowance(id, total) {
    this.allowanceStore.create(id, BigInt(total));
  }

  async charge({ allowanceId, vmax, execute }) {
    const res = await guardedCharge({ allowanceId, vmax, store: this.allowanceStore, execute });
    return res.success
      ? { success: true, value: res.value, charged: res.charged }
      : { success: false, reason: res.reason };
  }

  /** F5: quote the learned ratio, not the caller's self-reported estimate. */
  quote({ estimatedUnits }) {
    return this.pricer.quoteMax(estimatedUnits);
  }

  bill({ actualUnits, quoted }) {
    const full = this.pricer.bill(actualUnits);
    // The escrow is the hard ceiling, exactly as in guardedCharge's commit().
    return full > quoted ? quoted : full;
  }

  observe(estimatedUnits, actualUnits) {
    this.pricer.observe(estimatedUnits, actualUnits);
  }
}
