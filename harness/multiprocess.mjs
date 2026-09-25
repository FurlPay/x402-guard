#!/usr/bin/env node
// ---------------------------------------------------------------------------
// Multi-process concurrency proof — the evidence behind the paper's atomicity
// claims.
//
//   npm run mp                    # requires a real Redis (see redis-env.mjs)
//   node harness/multiprocess.mjs --workers 8 --attempts 25
//
// WHY A SEPARATE RUNNER. Every other test in this repo, including the ones
// against the Redis stores, runs inside ONE Node process. That is enough to
// check the store's logic, and it is not enough to support a claim about
// concurrency, because a single-threaded runtime cannot preempt a function
// mid-body. The in-memory stores pass those tests trivially. So would a store
// with no locking at all, if it never had to survive a second machine.
//
// Here each worker is a real OS process with its own heap and its own event
// loop. Nothing is shared except Redis. Workers align to a common start
// timestamp so their attempts genuinely overlap rather than queueing politely.
// If the Lua is wrong — if `reserve` reads before it writes, if `acquire` is
// not one round trip — the invariants below break, and they cannot break in the
// single-process tests.
//
// This is the run to cite. Everything else is a unit test.
// ---------------------------------------------------------------------------

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { RedisAllowanceStore, RedisNonceStore } from "../dist/index.js";
import { redisFromEnv, runPrefix, HINT } from "./redis-env.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKER = join(HERE, "mp-worker.mjs");

const argv = process.argv.slice(2);
const numArg = (flag, fallback) => {
  const i = argv.indexOf(flag);
  return i >= 0 ? Number(argv[i + 1]) : fallback;
};
const WORKERS = numArg("--workers", 8);
const ATTEMPTS = numArg("--attempts", 25);

const client = redisFromEnv();
if (!client) {
  console.error(`\nCannot run the multi-process proof: no Redis configured.\n${HINT}\n`);
  process.exit(2);
}

function runWorkers(job) {
  const startAt = Date.now() + 750; // give every process time to boot and connect
  return Promise.all(
    Array.from({ length: WORKERS }, (_, worker) => {
      const payload = JSON.stringify({ ...job, worker, startAt, attemptsPerWorker: ATTEMPTS });
      return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [WORKER, payload], {
          stdio: ["ignore", "pipe", "pipe"],
          env: process.env,
        });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (d) => (stdout += d));
        child.stderr.on("data", (d) => (stderr += d));
        child.on("close", (code) => {
          if (code !== 0) return reject(new Error(`worker ${worker} exited ${code}: ${stderr}`));
          try {
            resolve(JSON.parse(stdout.trim().split("\n").pop()));
          } catch {
            reject(new Error(`worker ${worker} produced unparseable output: ${stdout}`));
          }
        });
      });
    })
  );
}

const total = (rows, field) => rows.reduce((n, r) => n + Number(r[field] ?? 0), 0);
const failures = [];

function check(label, actual, expected, note) {
  const ok = actual === expected;
  if (!ok) failures.push(`${label}: expected ${expected}, got ${actual}`);
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}: ${actual}${note ? ` ${note}` : ""}`);
}

console.log(`\nx402-guard — multi-process concurrency proof`);
console.log(`${WORKERS} OS processes x ${ATTEMPTS} attempts, sharing nothing but Redis\n`);

// ── F2: one authorization, many machines ───────────────────────────────────

{
  const prefix = runPrefix("nonce");
  console.log(`F2  nonce linearization (${WORKERS * ATTEMPTS} concurrent acquires of ONE nonce)`);
  const rows = await runWorkers({ kind: "nonce", prefix, nonce: "shared-authorization" });
  const wins = total(rows, "wins");
  check("exactly one acquire succeeds fleet-wide", wins, 1);

  const store = new RedisNonceStore(client, { prefix, ttlSeconds: 300 });
  check("nonce is PENDING after the race", (await store.state("shared-authorization")) === "pending", true);
}

// ── F3: one allowance, many machines ───────────────────────────────────────

{
  const prefix = runPrefix("alw");
  const ALLOWANCE = 500n;
  const VMAX = 100n;
  console.log(`\nF3  allowance reserve-commit (allowance ${ALLOWANCE}, vmax ${VMAX})`);

  const store = new RedisAllowanceStore(client, { prefix, reservationTtlSeconds: 300 });
  await store.create("shared-allowance", ALLOWANCE);

  const rows = await runWorkers({
    kind: "allowance",
    prefix,
    allowanceId: "shared-allowance",
    vmax: VMAX.toString(),
  });

  const wins = total(rows, "wins");
  const charged = rows.reduce((n, r) => n + BigInt(r.charged ?? "0"), 0n);
  check("reservations granted", wins, Number(ALLOWANCE / VMAX), `(allowance / vmax)`);
  check("total charged never exceeds the signed allowance", charged <= ALLOWANCE, true, `— charged ${charged}`);
  check("remaining balance is exactly zero", (await store.remaining("shared-allowance")) === 0n, true);
}

// ── F4: one capacity budget, many machines ─────────────────────────────────

{
  const prefix = runPrefix("cap");
  const MAX = 3;
  console.log(`\nF4  settlement capacity (fleet ceiling ${MAX}, all winners hold their slots)`);
  const rows = await runWorkers({ kind: "capacity", prefix, maxConcurrent: MAX });
  check("slots admitted fleet-wide", total(rows, "wins"), MAX);
}

console.log("");
if (failures.length) {
  console.error(`FAILED (${failures.length}):`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log(`All invariants held across ${WORKERS} independent processes.\n`);
