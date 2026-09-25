// Build a RedisCommandClient from the environment, or explain why we can't.
//
// Only the Upstash REST protocol is supported here, deliberately: it needs no
// client library, so the zero-dependency promise survives, and it is what the
// rest of FurlPay already runs. A TCP `redis://` URL would require ioredis or
// node-redis — wire one in with `fromIoRedis` / `fromNodeRedis` if you prefer.

import { fromUpstashRest } from "../dist/redis.js";

export const REST_URL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
export const REST_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

export const HINT =
  "Set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN (or KV_REST_API_URL / KV_REST_API_TOKEN) " +
  "to run against a real Redis. Without them the Lua scripts are never executed.";

/** A live client, or null when the environment is not configured. */
export function redisFromEnv() {
  if (!REST_URL || !REST_TOKEN) return null;
  return fromUpstashRest(REST_URL, REST_TOKEN);
}

/** Namespace each run so concurrent or repeated runs cannot collide. */
export function runPrefix(label) {
  return `x402g:test:${label}:${Date.now().toString(36)}:${Math.random().toString(36).slice(2, 8)}:`;
}
