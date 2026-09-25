#!/usr/bin/env node
// ---------------------------------------------------------------------------
// F5 parameter sweep — is the residual compute leakage tunable or fundamental?
//
//   node harness/sweep.mjs [--seed 42]
//
// The main run reports F5 as a MITIGATION rather than a fix: adaptive billing
// roughly halves free-ridden compute but does not eliminate it. That invites
// the obvious question — just raise the safety margin until it does.
//
// This sweep answers it by measuring both sides of the trade. Raising the
// margin escrows more per request, which does close leakage; it also locks more
// of an HONEST caller's capital, since they are quoted against an average that
// includes the abusers. `honestOverQuote` is that cost: the mean ratio of
// escrow to eventual bill for non-adversarial traffic.
//
// Reporting only the leakage column would make an arbitrarily large margin look
// free. It is not — it is a transfer from honest callers to the merchant's risk
// budget, refunded at commit but unavailable in the meantime.
// ---------------------------------------------------------------------------

import { AdaptivePricer } from "../dist/index.js";
import { GuardedFacilitator, BaselineFacilitator } from "./facilitators.mjs";
import { f5HiddenComputePricing } from "./scenarios.mjs";

const argv = process.argv.slice(2);
const seedArg = argv.indexOf("--seed");
const seed = seedArg >= 0 ? Number(argv[seedArg + 1]) : 42;

const MARGINS = [1.0, 1.25, 1.5, 2.0, 3.0, 4.0, 6.0];
const ALPHA = 0.35;

const baseline = await f5HiddenComputePricing(new BaselineFacilitator(), { seed });
const b = baseline.ledger.report();

console.log("\nF5 sensitivity — safety margin vs. honest-caller cost");
console.log(`seed ${seed} · 40 requests · ~1/3 adversarial at 6x their estimate\n`);
console.log(`baseline (fixed quote): valueLeakage ${(b.valueLeakage * 100).toFixed(1)}%, ` +
  `${baseline.extra.unitsFreeRidden} of ${baseline.extra.unitsDelivered} units free-ridden\n`);

const rows = [];
for (const safetyMargin of MARGINS) {
  const facilitator = new GuardedFacilitator({
    pricer: new AdaptivePricer({ unitPrice: 1n, alpha: ALPHA, safetyMargin, maxRatio: 20 }),
  });
  const run = await f5HiddenComputePricing(facilitator, { seed });
  const r = run.ledger.report();
  rows.push({
    safetyMargin,
    valueLeakage: `${(r.valueLeakage * 100).toFixed(1)}%`,
    unitsFreeRidden: run.extra.unitsFreeRidden,
    learnedRatio: run.extra.learnedRatio,
    honestOverQuote: run.extra.honestOverQuote,
  });
}
console.table(rows);

const closed = rows.find((r) => r.unitsFreeRidden === 0);
console.log(
  closed
    ? `Leakage reaches zero at margin ${closed.safetyMargin}, at the cost of ` +
        `${closed.honestOverQuote}x over-escrow on honest traffic.\n`
    : `Leakage does not reach zero within the tested range — F5 is a mitigation, not a fix.\n`
);
