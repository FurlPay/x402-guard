// ---------------------------------------------------------------------------
// Evaluation accounting for the adversarial harness.
//
// The headline number in Ling et al. (arXiv:2605.30998) is the RESOURCE-LEAKAGE
// RATIO: of the service a merchant actually rendered, what fraction was never
// paid for. The paper reports ratios up to 100% against production x402
// deployments. Reproducing that number is the whole point of this harness — a
// defense test that only shows the guard refusing traffic proves nothing about
// how much was leaking before.
//
// Two ratios are reported because they answer different questions and can
// diverge sharply:
//
//   requestLeakage — fraction of DELIVERED REQUESTS with no confirmed
//     settlement. This is the paper's framing and the right number for
//     substitution/replay attacks, where each free request is one stolen unit
//     of service regardless of price.
//
//   valueLeakage — fraction of EXPECTED REVENUE never realized on-chain. This
//     is the right number for F3 and F5, where the attack is not "more requests
//     than paid for" but "more value consumed per request than quoted". A
//     hidden-compute attack can show 0% request leakage and 80% value leakage.
//
// A settlement counts only when the chain CONFIRMS it. An x402 facilitator that
// returns success on an unconfirmed or timed-out settlement is exactly the bug
// under test, so `settle()` here is deliberately the confirmed-only path.
// ---------------------------------------------------------------------------

/** Accounting for one scenario run against one facilitator. */
export class Ledger {
  #deliveries = new Map(); // requestId -> { resource, units, price }
  #settlements = new Map(); // requestId -> amount (bigint, atomic units)
  #rejections = 0;

  /**
   * Record that the merchant rendered service. Call this at the moment the
   * resource leaves the server — NOT when payment clears. The gap between the
   * two is the vulnerability being measured.
   */
  deliver(requestId, { resource = "", units = 1, price = 0n } = {}) {
    if (this.#deliveries.has(requestId)) {
      throw new Error(`duplicate delivery for ${requestId} — request ids must be unique`);
    }
    this.#deliveries.set(requestId, { resource, units, price: BigInt(price) });
  }

  /** Record a CONFIRMED on-chain settlement attributable to one delivered request. */
  settle(requestId, amount) {
    this.#settlements.set(requestId, BigInt(amount));
  }

  /** Record a request the facilitator refused to serve (429 / rejected auth). */
  reject() {
    this.#rejections++;
  }

  report() {
    const delivered = this.#deliveries.size;
    let expected = 0n;
    let unitsDelivered = 0;
    for (const d of this.#deliveries.values()) {
      expected += d.price;
      unitsDelivered += d.units;
    }

    let realized = 0n;
    let paidRequests = 0;
    for (const [requestId, amount] of this.#settlements) {
      // A settlement for a request that was never delivered is not leakage —
      // it is just revenue. Counting it would let a facilitator hide leakage by
      // over-settling, so paid-request attribution is restricted to deliveries.
      if (this.#deliveries.has(requestId)) paidRequests++;
      realized += amount;
    }

    const unpaidRequests = delivered - paidRequests;
    const valueLost = expected > realized ? expected - realized : 0n;

    return {
      delivered,
      paidRequests,
      unpaidRequests,
      rejected: this.#rejections,
      unitsDelivered,
      revenueExpected: expected,
      revenueRealized: realized,
      revenueLost: valueLost,
      requestLeakage: delivered === 0 ? 0 : unpaidRequests / delivered,
      valueLeakage: expected === 0n ? 0 : Number(valueLost) / Number(expected),
    };
  }
}

/** Format a report row for the results table. */
export function formatRow(label, r) {
  const pct = (x) => `${(x * 100).toFixed(1)}%`;
  return {
    facilitator: label,
    delivered: r.delivered,
    paid: r.paidRequests,
    unpaid: r.unpaidRequests,
    rejected: r.rejected,
    requestLeakage: pct(r.requestLeakage),
    valueLeakage: pct(r.valueLeakage),
    revenueLost: r.revenueLost.toString(),
  };
}

/**
 * Deterministic PRNG (mulberry32). Every scenario that needs randomness draws
 * from a seeded stream so a reported table is reproducible from the seed alone
 * — a result nobody can replicate is not evidence.
 */
export function seededRandom(seed) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
