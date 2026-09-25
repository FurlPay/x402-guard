#!/usr/bin/env node
// ---------------------------------------------------------------------------
// Adversarial evaluation runner for @furlpay/x402-guard.
//
//   node harness/run.mjs            # table to stdout
//   node harness/run.mjs --json     # machine-readable results
//   node harness/run.mjs --seed 7   # re-run the stochastic scenario (F5)
//
// Each of the five flaw classes from arXiv:2605.30998 is executed twice —
// against an unguarded facilitator reproducing the paper's observed patterns,
// and against the same facilitator wearing x402-guard. The delta is the claim.
//
// Every run builds FRESH facilitator instances per scenario, so no state (a
// burnt nonce, a learned pricing ratio) leaks between measurements.
// ---------------------------------------------------------------------------

import { BaselineFacilitator, GuardedFacilitator } from "./facilitators.mjs";
import { SCENARIOS } from "./scenarios.mjs";
import { formatRow } from "./metrics.mjs";

/** Per-scenario facilitator construction. F4 is the only one needing capacity. */
const OPTIONS = {
  F4: { settlementLatencyMs: 8, maxConcurrentSettlements: 3 },
};

const argv = process.argv.slice(2);
const asJson = argv.includes("--json");
const seedArg = argv.indexOf("--seed");
const seed = seedArg >= 0 ? Number(argv[seedArg + 1]) : 42;

async function runScenario(scenario) {
  const opts = OPTIONS[scenario.id] ?? {};
  const scenarioArgs = scenario.id === "F5" ? { seed } : undefined;

  const baseline = await scenario.run(new BaselineFacilitator(opts), scenarioArgs);
  const guarded = await scenario.run(new GuardedFacilitator(opts), scenarioArgs);

  return {
    id: scenario.id,
    name: scenario.name,
    invariant: scenario.invariant,
    baseline: { ...baseline.ledger.report(), extra: baseline.extra },
    guarded: { ...guarded.ledger.report(), extra: guarded.extra },
  };
}

/** BigInt values cannot go through JSON.stringify; render them as strings. */
function jsonSafe(value) {
  if (typeof value === "bigint") return value.toString();
  if (Array.isArray(value)) return value.map(jsonSafe);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, jsonSafe(v)]));
  }
  return value;
}

const results = [];
for (const scenario of SCENARIOS) {
  results.push(await runScenario(scenario));
}

if (asJson) {
  console.log(JSON.stringify(jsonSafe({ seed, generatedAt: new Date().toISOString(), results }), null, 2));
  process.exit(0);
}

console.log("\nx402-guard — adversarial evaluation");
console.log(`Flaw classes from Ling et al., arXiv:2605.30998 · seed ${seed}\n`);

for (const r of results) {
  console.log(`${r.id}  ${r.name}`);
  console.log(`    invariant: ${r.invariant}`);
  console.table([formatRow("baseline (unguarded)", r.baseline), formatRow("guarded (x402-guard)", r.guarded)]);

  // Flaw-specific numbers the generic ledger cannot express.
  const b = r.baseline.extra;
  const g = r.guarded.extra;
  if (r.id === "F3") {
    console.log(
      `    overdraft: baseline drew ${b.drawn} against a ${b.allowance} allowance ` +
        `(${b.overdraftMultiple.toFixed(2)}x) · guarded drew ${g.drawn} (${g.overdraftMultiple.toFixed(2)}x)`
    );
  }
  if (r.id === "F5") {
    console.log(
      `    compute: baseline free-rode ${b.unitsFreeRidden} of ${b.unitsDelivered} units · ` +
        `guarded ${g.unitsFreeRidden} of ${g.unitsDelivered} (learned ratio ${g.learnedRatio})`
    );
  }
  console.log("");
}

// Summary: the one line that belongs in an abstract.
const worstBaseline = Math.max(...results.map((r) => Math.max(r.baseline.requestLeakage, r.baseline.valueLeakage)));
const worstGuarded = Math.max(...results.map((r) => Math.max(r.guarded.requestLeakage, r.guarded.valueLeakage)));
console.log(
  `Peak leakage — unguarded ${(worstBaseline * 100).toFixed(1)}% · ` +
    `guarded ${(worstGuarded * 100).toFixed(1)}%\n`
);
