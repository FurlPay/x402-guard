// One worker in the multi-process concurrency proof.
//
// Spawned by multiprocess.mjs with a job description on argv. Everything this
// process knows about the other workers arrives through Redis — there is no
// shared memory, no shared event loop, and no coordination. That is the whole
// point: the in-memory stores would report perfect results here purely because
// each process has its own Map.
//
// Emits one JSON line on stdout so the parent can aggregate.

import {
  RedisNonceStore,
  RedisAllowanceStore,
  RedisSettlementCapacityLimiter,
} from "../dist/index.js";
import { redisFromEnv } from "./redis-env.mjs";

const job = JSON.parse(process.argv[2]);
const client = redisFromEnv();
if (!client) {
  process.stdout.write(JSON.stringify({ error: "no redis" }) + "\n");
  process.exit(1);
}

/** Start all attempts at the same wall-clock instant so they genuinely race. */
async function alignToStart(startAt) {
  const delay = startAt - Date.now();
  if (delay > 0) await new Promise((r) => setTimeout(r, delay));
}

const out = { worker: job.worker, wins: 0, losses: 0, charged: "0", errors: [] };

try {
  await alignToStart(job.startAt);

  if (job.kind === "nonce") {
    const store = new RedisNonceStore(client, { prefix: job.prefix, ttlSeconds: 300 });
    const results = await Promise.all(
      Array.from({ length: job.attemptsPerWorker }, () => store.acquire(job.nonce))
    );
    out.wins = results.filter(Boolean).length;
    out.losses = results.length - out.wins;
  }

  if (job.kind === "allowance") {
    const store = new RedisAllowanceStore(client, { prefix: job.prefix, reservationTtlSeconds: 300 });
    const ids = await Promise.all(
      Array.from({ length: job.attemptsPerWorker }, () => store.reserve(job.allowanceId, BigInt(job.vmax)))
    );
    const won = ids.filter(Boolean);
    out.wins = won.length;
    out.losses = ids.length - won.length;
    // Bill the full escrow so the run's total spend is directly comparable to
    // the signed allowance — an overdraft shows up as spend > allowance.
    let charged = 0n;
    for (const id of won) charged += await store.commit(id, BigInt(job.vmax));
    out.charged = charged.toString();
  }

  if (job.kind === "capacity") {
    const limiter = new RedisSettlementCapacityLimiter(client, job.maxConcurrent, {
      key: `${job.prefix}capacity`,
      leaseMs: 30_000,
    });
    const slots = await Promise.all(
      Array.from({ length: job.attemptsPerWorker }, () => limiter.tryReserve())
    );
    out.wins = slots.filter(Boolean).length;
    out.losses = slots.length - out.wins;
    // Hold the slots: the parent asserts the fleet-wide ceiling was respected
    // while every winner was still holding.
  }
} catch (err) {
  out.errors.push(err instanceof Error ? err.message : String(err));
}

process.stdout.write(JSON.stringify(out) + "\n");
