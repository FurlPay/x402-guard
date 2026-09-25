// ---------------------------------------------------------------------------
// The five attacks from Ling et al. (arXiv:2605.30998), each written once and
// executed against both facilitators.
//
// Every scenario is an ADVERSARY, not a unit test: it plays the attacker's side
// of the protocol honestly and records what the merchant actually handed over.
// The facilitator decides whether to serve; the scenario never asserts. All
// judgement lives in the metrics, so a scenario cannot be tuned to flatter the
// defense.
//
// The merchant loop is the same everywhere and matches x402's real shape:
//
//     const v = facilitator.verify(...)   // off-chain admission
//     if (!v.ok) { ledger.reject(); return }
//     ledger.deliver(...)                 // the resource is now GONE
//     const s = await facilitator.settle(...)   // on-chain, slow
//     if (s.success) ledger.settle(...)
//
// A scenario returns { ledger, extra } where `extra` carries flaw-specific
// numbers the generic ledger cannot express.
// ---------------------------------------------------------------------------

import { requestBindingHash } from "../dist/index.js";
import { Ledger, seededRandom } from "./metrics.mjs";

const PRICE = 1_000n; // 0.001 USDC in 6-decimal atomic units

// ── F1: cross-resource substitution ────────────────────────────────────────
//
// The paper found 38% of hosts expose "sibling clusters" — distinct resources
// at an identical price. One signature minted for one sibling is presented
// against every other. The facilitator sees a valid signature for the correct
// value and payee and cannot tell the resources apart.

export async function f1CrossResourceSubstitution(facilitator) {
  const ledger = new Ledger();
  const cluster = ["/premium/report-A", "/premium/report-B", "/premium/report-C", "/premium/report-D"];

  // The attacker pays once, legitimately, for exactly one sibling — and then
  // replays that single authorization across the whole cluster.
  const paidResource = cluster[0];
  const presented = requestBindingHash("GET", paidResource, "");
  const nonce = "f1-single-auth";

  for (const [i, resource] of cluster.entries()) {
    const requestId = `f1-${i}`;
    const v = facilitator.verify({
      nonce,
      price: PRICE,
      offeredValue: PRICE,
      binding: { presented },
      method: "GET",
      uri: resource, // the resource actually being requested
      body: "",
    });

    if (!v.ok) {
      ledger.reject();
      continue;
    }

    ledger.deliver(requestId, { resource, price: PRICE });
    const s = await facilitator.settle({ nonce });
    if (s.success) ledger.settle(requestId, PRICE);
  }

  return { ledger, extra: { clusterSize: cluster.length, paidResource } };
}

// ── F2: duplicate-settlement race ──────────────────────────────────────────
//
// The paper's reproduction: 20 concurrent requests carrying one authorization
// nonce. All clear off-chain verification before any on-chain settlement lands,
// so the merchant serves 20 times. The chain consumes the authorization once.

export async function f2DuplicateSettlementRace(facilitator, { concurrency = 20 } = {}) {
  const ledger = new Ledger();
  const nonce = "f2-shared-nonce";

  await Promise.all(
    Array.from({ length: concurrency }, async (_, i) => {
      const requestId = `f2-${i}`;
      const v = facilitator.verify({ nonce, price: PRICE, offeredValue: PRICE });
      if (!v.ok) {
        ledger.reject();
        return;
      }
      ledger.deliver(requestId, { resource: "/premium/stream", price: PRICE });

      const s = await facilitator.settle({ nonce });
      if (s.success) ledger.settle(requestId, PRICE);
    })
  );

  return { ledger, extra: { concurrency } };
}

// ── F3: allowance overdraft (upto scheme) ──────────────────────────────────
//
// A signed "upto" allowance of 500 units, drawn by 10 concurrent requests each
// authorised up to 100. A read-then-deduct implementation lets all 10 observe
// the full remaining balance and proceed: 1000 drawn against 500 that exists.
//
// Only what the allowance actually backs is collectible, so the ledger settles
// draws in order until the allowance is exhausted — the rest is service the
// merchant delivered against funds that were never there.

export async function f3AllowanceOverdraft(
  facilitator,
  { concurrency = 10, allowance = 500n, vmax = 100n } = {}
) {
  const ledger = new Ledger();
  const allowanceId = "f3-allowance";
  facilitator.createAllowance(allowanceId, allowance);

  const draws = [];

  await Promise.all(
    Array.from({ length: concurrency }, async (_, i) => {
      const requestId = `f3-${i}`;
      const res = await facilitator.charge({
        allowanceId,
        vmax,
        execute: async () => {
          await new Promise((r) => setTimeout(r, 2));
          ledger.deliver(requestId, { resource: "/premium/inference", price: vmax });
          return { actual: vmax, value: "ok" };
        },
      });
      if (res.success) draws.push({ requestId, charged: res.charged });
      else ledger.reject();
    })
  );

  // Settle against real backing only. Anything drawn beyond the signed
  // allowance is uncollectible — that is the I5 violation in revenue terms.
  let backing = allowance;
  let drawn = 0n;
  for (const d of draws) {
    drawn += d.charged;
    if (backing <= 0n) continue;
    const collectible = d.charged > backing ? backing : d.charged;
    ledger.settle(d.requestId, collectible);
    backing -= collectible;
  }

  return {
    ledger,
    extra: {
      allowance: allowance.toString(),
      drawn: drawn.toString(),
      // >1 means the signed allowance was exceeded — the I5 violation.
      overdraftMultiple: Number(drawn) / Number(allowance),
    },
  };
}

// ── F4: denial of settlement ───────────────────────────────────────────────
//
// The attacker saturates settlement capacity with slow transactions. Honest
// requests pass verification and are served, but their settlements are refused.
// A facilitator that discovers capacity at settle() time has already given the
// resource away.

export async function f4DenialOfSettlement(facilitator, { honest = 12, capacity = 3 } = {}) {
  const ledger = new Ledger();

  await Promise.all(
    Array.from({ length: honest }, async (_, i) => {
      const requestId = `f4-${i}`;
      const v = facilitator.verify({ nonce: `f4-nonce-${i}`, price: PRICE, offeredValue: PRICE });
      if (!v.ok) {
        // Guarded: refused at admission. No resource left the building.
        ledger.reject();
        return;
      }
      ledger.deliver(requestId, { resource: "/premium/job", price: PRICE });

      const s = await facilitator.settle({ nonce: `f4-nonce-${i}` });
      if (s.success) ledger.settle(requestId, PRICE);
    })
  );

  return { ledger, extra: { honest, capacity } };
}

// ── F5: hidden-compute pricing ─────────────────────────────────────────────
//
// Pay-per-token inference. The caller supplies an estimate; the true cost is
// unknowable until the work is done. An adversary crafts prompts whose actual
// consumption is a large multiple of the estimate and free-rides the gap.

export async function f5HiddenComputePricing(
  facilitator,
  { requests = 40, seed = 42, abuseRatio = 6 } = {}
) {
  const ledger = new Ledger();
  const rand = seededRandom(seed);
  const unitPrice = 1n;

  let unitsDelivered = 0;
  let unitsPaid = 0;
  // Over-quoting is not free: an escrow larger than the eventual bill locks an
  // honest caller's capital until commit refunds it. Tracking it is what makes
  // the F5 margin a trade-off rather than a free win.
  let honestQuoteRatioSum = 0;
  let honestCount = 0;

  for (let i = 0; i < requests; i++) {
    const requestId = `f5-${i}`;
    const estimatedUnits = 100;

    // Two-thirds honest traffic (actual ≈ estimate), one-third adversarial
    // (actual ≫ estimate). Seeded, so the mix is reproducible.
    const adversarial = rand() < 0.34;
    const actualUnits = adversarial
      ? Math.round(estimatedUnits * abuseRatio * (0.9 + rand() * 0.2))
      : Math.round(estimatedUnits * (0.85 + rand() * 0.3));

    const quoted = facilitator.quote({ estimatedUnits, unitPrice });
    const price = BigInt(actualUnits) * unitPrice; // what the compute was truly worth

    ledger.deliver(requestId, { resource: "/premium/inference", units: actualUnits, price });

    const charged = facilitator.bill({ actualUnits, unitPrice, quoted });
    ledger.settle(requestId, charged);

    unitsDelivered += actualUnits;
    unitsPaid += Number(charged / unitPrice);
    if (!adversarial) {
      honestQuoteRatioSum += Number(quoted) / actualUnits;
      honestCount++;
    }

    // Feed the observation back. The baseline discards it; the guarded pricer
    // raises its quote so the escrow covers what traffic actually costs.
    facilitator.observe(estimatedUnits, actualUnits);
  }

  return {
    ledger,
    extra: {
      unitsDelivered,
      unitsPaid,
      unitsFreeRidden: unitsDelivered - unitsPaid,
      learnedRatio: facilitator.pricer ? Number(facilitator.pricer.ratio.toFixed(3)) : null,
      // Mean escrow-to-actual ratio for honest callers. 1.0 is perfect; higher
      // means honest users lock more capital than their bill turns out to be.
      honestOverQuote: honestCount === 0 ? null : Number((honestQuoteRatioSum / honestCount).toFixed(3)),
    },
  };
}

export const SCENARIOS = [
  { id: "F1", name: "Cross-resource substitution", invariant: "I3 Context Binding", run: f1CrossResourceSubstitution },
  { id: "F2", name: "Duplicate-settlement race", invariant: "I4 Authorization Uniqueness", run: f2DuplicateSettlementRace },
  { id: "F3", name: "Allowance overdraft (upto)", invariant: "I5 Balance Sufficiency", run: f3AllowanceOverdraft },
  { id: "F4", name: "Denial of settlement", invariant: "I2 Settlement Guarantee", run: f4DenialOfSettlement },
  { id: "F5", name: "Hidden-compute pricing", invariant: "G2 Dynamic Billing", run: f5HiddenComputePricing },
];
