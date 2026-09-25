import crypto from "node:crypto";
import { SCRIPTS } from "../dist/redis.js";

// ---------------------------------------------------------------------------
// A Redis stand-in for the store tests.
//
// WHAT THIS DOES AND DOES NOT PROVE. It models the two properties the stores
// actually depend on:
//
//   1. a command reaches Redis over a network, so callers interleave freely
//      BETWEEN commands (each command awaits a real tick first), and
//   2. a script runs to completion without interleaving, so the twins below
//      execute synchronously — which in single-threaded JS is exactly Redis's
//      guarantee.
//
// It does NOT prove the Lua is correct. The twins are a second implementation
// of the same intent in a different language, and a second implementation can
// be wrong in the same way. Only `npm run test:redis` against a real server
// executes the actual scripts. That distinction is stated in the README rather
// than left for a reviewer to discover.
//
// THE STALENESS GUARD. Twins are registered against a hash of the script text,
// hard-coded below. Edit the Lua and the hash moves, the lookup misses, and the
// double throws instead of silently exercising an outdated stand-in.
// ---------------------------------------------------------------------------

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex").slice(0, 16);

/** Yield to the event loop, standing in for the network round trip. */
const tick = () => new Promise((r) => setImmediate(r));

class Entry {
  constructor(value, expiresAt = Infinity) {
    this.value = value;
    this.expiresAt = expiresAt;
  }
}

export class FakeRedis {
  #data = new Map(); // key -> Entry (value: string | Map | sorted array)
  commandCount = 0;

  #live(key) {
    const e = this.#data.get(key);
    if (!e) return undefined;
    if (e.expiresAt <= Date.now()) {
      this.#data.delete(key);
      return undefined;
    }
    return e;
  }

  async command(args) {
    // The interleaving point. Everything after this runs synchronously.
    await tick();
    this.commandCount++;
    return this._exec(args.map((a) => (typeof a === "number" ? String(a) : a)));
  }

  /** Synchronous command execution — the twins' equivalent of `redis.call`. */
  _exec(args) {
    const op = args[0].toUpperCase();
    switch (op) {
      case "SET": {
        const [, key, value, ...rest] = args;
        const nx = rest.some((f) => f.toUpperCase() === "NX");
        if (nx && this.#live(key)) return null;
        const exAt = rest.findIndex((f) => f.toUpperCase() === "EX");
        const ttl = exAt >= 0 ? Number(rest[exAt + 1]) * 1000 : undefined;
        this.#data.set(key, new Entry(value, ttl ? Date.now() + ttl : Infinity));
        return "OK";
      }
      case "GET": {
        const e = this.#live(args[1]);
        return e ? e.value : null;
      }
      case "DEL":
        return this.#data.delete(args[1]) ? 1 : 0;
      case "HSET": {
        const key = args[1];
        const e = this.#live(key) ?? new Entry(new Map());
        for (let i = 2; i < args.length; i += 2) e.value.set(args[i], args[i + 1]);
        this.#data.set(key, e);
        return 1;
      }
      case "HGET": {
        const e = this.#live(args[1]);
        return e ? (e.value.get(args[2]) ?? null) : null;
      }
      case "HMGET": {
        // Redis returns an array positionally, with null for absent fields and
        // for a missing key — never a short array. Callers index by position.
        const e = this.#live(args[1]);
        return args.slice(2).map((f) => (e ? (e.value.get(f) ?? null) : null));
      }
      case "EXPIRE": {
        const e = this.#live(args[1]);
        if (e) e.expiresAt = Date.now() + Number(args[2]) * 1000;
        return e ? 1 : 0;
      }
      case "PEXPIRE": {
        const e = this.#live(args[1]);
        if (e) e.expiresAt = Date.now() + Number(args[2]);
        return e ? 1 : 0;
      }
      case "ZADD": {
        const key = args[1];
        const e = this.#live(key) ?? new Entry([]);
        const [, , score, member] = args;
        const existing = e.value.find((m) => m.member === member);
        if (existing) existing.score = Number(score);
        else e.value.push({ score: Number(score), member });
        this.#data.set(key, e);
        return 1;
      }
      case "ZCARD": {
        const e = this.#live(args[1]);
        return e ? e.value.length : 0;
      }
      case "ZREM": {
        const e = this.#live(args[1]);
        if (!e) return 0;
        const before = e.value.length;
        e.value = e.value.filter((m) => m.member !== args[2]);
        return before - e.value.length;
      }
      case "ZRANGE": {
        // Members in score order, which is what the rolling sum iterates. Only
        // the index form the scripts use is supported; anything else would be a
        // stand-in for a command the real Lua never issues.
        const e = this.#live(args[1]);
        if (!e) return [];
        const sorted = [...e.value].sort((a, b) => a.score - b.score);
        const start = Number(args[2]);
        const stop = Number(args[3]);
        const end = stop < 0 ? sorted.length + stop + 1 : stop + 1;
        return sorted.slice(start, end).map((m) => m.member);
      }
      case "ZREMRANGEBYSCORE": {
        const e = this.#live(args[1]);
        if (!e) return 0;
        const max = Number(args[3]);
        const before = e.value.length;
        e.value = e.value.filter((m) => m.score > max);
        return before - e.value.length;
      }
      case "EVAL":
        return this._eval(args);
      default:
        throw new Error(`FakeRedis: unimplemented command ${op}`);
    }
  }

  _eval(args) {
    const script = args[1];
    const numKeys = Number(args[2]);
    const keys = args.slice(3, 3 + numKeys);
    const argv = args.slice(3 + numKeys);
    const twin = TWINS[sha(script)];
    if (!twin) {
      throw new Error(
        `FakeRedis: no twin registered for script ${sha(script)}. The Lua changed — ` +
          `update the twin in test/fake-redis.mjs and its hash, or this double is testing stale logic.`
      );
    }
    return twin(this, keys, argv);
  }
}

// ── Twins: the Lua, re-expressed. Synchronous, i.e. atomic. ────────────────

const TWINS = {
  [sha(SCRIPTS.releaseIfPending)]: (r, keys) => {
    if (r._exec(["GET", keys[0]]) === "pending") return r._exec(["DEL", keys[0]]);
    return 0;
  },

  [sha(SCRIPTS.reserve)]: (r, keys, argv) => {
    const bal = r._exec(["GET", keys[0]]);
    if (bal === null) return 0;
    const remaining = Number(bal);
    const vmax = Number(argv[0]);
    if (vmax <= 0 || remaining < vmax) return 0;
    r._exec(["SET", keys[0], String(remaining - vmax)]);
    r._exec(["HSET", keys[1], "allowance", keys[0], "amount", argv[0]]);
    r._exec(["EXPIRE", keys[1], argv[1]]);
    return 1;
  },

  [sha(SCRIPTS.commit)]: (r, keys, argv) => {
    const amount = r._exec(["HGET", keys[1], "amount"]);
    if (amount === null) return "0";
    r._exec(["DEL", keys[1]]);
    const reserved = Number(amount);
    let actual = Number(argv[0]);
    if (actual < 0) actual = 0;
    if (actual > reserved) actual = reserved;
    const refund = reserved - actual;
    if (refund > 0) {
      const bal = Number(r._exec(["GET", keys[0]]) ?? "0");
      r._exec(["SET", keys[0], String(bal + refund)]);
    }
    return String(actual);
  },

  // F6: nonce + mandate budget, together or not at all. The rollback branches
  // are the point — each one must leave BOTH keys as it found them.
  [sha(SCRIPTS.reserveSpend)]: (r, keys, argv) => {
    if (r._exec(["SET", keys[0], "pending", "NX", "EX", argv[1]]) === null) {
      return [0, "nonce_taken"];
    }
    const bal = r._exec(["GET", keys[1]]);
    if (bal === null) {
      r._exec(["DEL", keys[0]]);
      return [0, "no_mandate_budget"];
    }
    const remaining = Number(bal);
    const amount = Number(argv[0]);
    if (amount <= 0) {
      r._exec(["DEL", keys[0]]);
      return [0, "invalid_amount"];
    }
    if (remaining < amount) {
      r._exec(["DEL", keys[0]]);
      return [0, "budget_exhausted"];
    }
    r._exec(["SET", keys[1], String(remaining - amount)]);
    r._exec([
      "HSET", keys[2],
      "budget", keys[1],
      "amount", argv[0],
      "nonce", keys[0],
      "paymentHash", argv[3],
      "mandateId", argv[4],
      "resource", argv[5],
    ]);
    r._exec(["EXPIRE", keys[2], argv[2]]);
    return [1, "ok"];
  },

  // Rolling: the trailing sum is recomputed from the ledger every time, which
  // is the whole difference from the counter above.
  [sha(SCRIPTS.reserveSpendRolling)]: (r, keys, argv) => {
    if (r._exec(["SET", keys[0], "pending", "NX", "EX", argv[1]]) === null) {
      return [0, "nonce_taken"];
    }
    const amount = Number(argv[0]);
    if (amount <= 0) {
      r._exec(["DEL", keys[0]]);
      return [0, "invalid_amount"];
    }
    const now = Number(argv[6]);
    const windowMs = Number(argv[7]);
    r._exec(["ZREMRANGEBYSCORE", keys[1], "-inf", String(now - windowMs)]);
    const members = r._exec(["ZRANGE", keys[1], "0", "-1"]) ?? [];
    let spent = 0;
    for (const m of members) {
      const sep = m.indexOf(":");
      if (sep >= 0) spent += Number(m.slice(sep + 1));
    }
    if (spent + amount > Number(argv[8])) {
      r._exec(["DEL", keys[0]]);
      return [0, "budget_exhausted"];
    }
    const member = `${argv[9]}:${argv[0]}`;
    r._exec(["ZADD", keys[1], String(now), member]);
    r._exec(["PEXPIRE", keys[1], String(windowMs * 2)]);
    r._exec([
      "HSET", keys[2],
      "ledger", keys[1],
      "amount", argv[0],
      "nonce", keys[0],
      "member", member,
      "paymentHash", argv[3],
      "mandateId", argv[4],
      "resource", argv[5],
    ]);
    r._exec(["EXPIRE", keys[2], argv[2]]);
    return [1, "ok"];
  },

  [sha(SCRIPTS.releaseSpendRolling)]: (r, keys, argv) => {
    if (r._exec(["GET", keys[0]]) !== "pending") return 0;
    r._exec(["ZREM", keys[1], argv[0]]);
    r._exec(["DEL", keys[0]]);
    r._exec(["DEL", keys[2]]);
    return 1;
  },

  [sha(SCRIPTS.releaseSpend)]: (r, keys, argv) => {
    if (r._exec(["GET", keys[0]]) !== "pending") return 0;
    const bal = r._exec(["GET", keys[1]]);
    if (bal !== null) r._exec(["SET", keys[1], String(Number(bal) + Number(argv[0]))]);
    r._exec(["DEL", keys[0]]);
    r._exec(["DEL", keys[2]]);
    return 1;
  },

  [sha(SCRIPTS.reserveCapacity)]: (r, keys, argv) => {
    const now = Number(argv[0]);
    const leaseMs = Number(argv[1]);
    const max = Number(argv[2]);
    r._exec(["ZREMRANGEBYSCORE", keys[0], "-inf", String(now - leaseMs)]);
    if (r._exec(["ZCARD", keys[0]]) >= max) return 0;
    r._exec(["ZADD", keys[0], String(now), argv[3]]);
    r._exec(["PEXPIRE", keys[0], String(leaseMs * 2)]);
    return 1;
  },
};
