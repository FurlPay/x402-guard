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
}

/**
 * Verify-once, settle-once. Wraps a settler with the paper's two defenses:
 * F1 (optional request-binding gate) and F2 (atomic nonce linearization with
 * failure-closed release semantics).
 */
export async function guardedSettle<TReq>(req: TReq, opts: GuardOptions<TReq>): Promise<GuardResult> {
  const { nonce, store, settler, binding } = opts;

  // F1: reject a payment presented for a different resource before doing work.
  if (binding) {
    const ok = verifyRequestBinding(binding.presented, binding.method, binding.uri, binding.body ?? "");
    if (!ok) return { success: false, reason: "resource_binding_mismatch" };
  }

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
}
