import test from "node:test";
import assert from "node:assert/strict";
import { evaluateMandate, matchesPattern } from "../dist/policy.js";

// ---------------------------------------------------------------------------
// The policy evaluator, exhaustively.
//
// This function is pure on purpose, and this file is why: every denial path
// below is reachable with no Redis, no clock and no network, so the policy can
// be tested at the boundary rather than through a settlement.
//
// MONEY IS INTEGER HERE, and that is the point of the module. The mandate model
// in @furlpay/agent-trust checks `spent + amountUsd > maxTotalUsd` on doubles,
// which fails in both directions — `0.1 + 0.2 > 0.3` is TRUE, refusing a user
// $0.20 of a $0.30 cap they hold. The last test in this file pins that the
// integer path does not.
// ---------------------------------------------------------------------------

const NOW = Date.UTC(2026, 5, 15, 12, 0, 0);
const VERSION = "furlpay-mandate-v1";

const policy = (over = {}) => ({
  mandateId: "mnd_1",
  agentKeyId: "ak_agent",
  buyerKeyId: "uk_buyer",
  status: "ACTIVE",
  maxPerTxAtomic: "5000000", // $5
  maxPerWindowAtomic: "50000000", // $50
  window: { type: "calendar", unit: "month" },
  asset: "0xUSDC",
  network: "base",
  expiresAt: new Date(NOW + 30 * 86_400_000).toISOString(),
  policyVersion: VERSION,
  ...over,
});

const auth = (over = {}) => ({
  mandateId: "mnd_1",
  agentKeyId: "ak_agent",
  buyerKeyId: "uk_buyer",
  network: "base",
  asset: "0xUSDC",
  amountAtomic: "1000000", // $1
  seller: "api.furlpay.com",
  resource: "https://api.furlpay.com/v1/summarize",
  method: "POST",
  paymentHash: "0xhash",
  nonce: "0xnonce",
  policyVersion: VERSION,
  ...over,
});

const evaluate = (over = {}) =>
  evaluateMandate({
    policy: policy(over.policy),
    authorization: auth(over.auth),
    windowSpentAtomic: over.spent ?? "0",
    approval: over.approval,
    nowMs: over.nowMs ?? NOW,
  });

const denies = (reason, over) => {
  const r = evaluate(over);
  assert.equal(r.allowed, false, `expected denial ${reason}, got allow`);
  assert.equal(r.reason, reason);
};

test("a payment inside every constraint is allowed", () => {
  const r = evaluate();
  assert.equal(r.allowed, true);
  assert.equal(r.requiresApproval, false);
  assert.equal(r.evaluated.windowSpentAfterAtomic, "1000000");
});

// ── limits, at the boundary ────────────────────────────────────────────────

test("amount EXACTLY at the per-tx cap is allowed", () => {
  // A cap is a ceiling you may reach. `>=` here would silently make every
  // mandate one unit smaller than it says.
  assert.equal(evaluate({ auth: { amountAtomic: "5000000" } }).allowed, true);
});

test("amount one unit over the per-tx cap is denied", () => {
  denies("per_tx_limit_exceeded", { auth: { amountAtomic: "5000001" } });
});

test("window spend EXACTLY at the cap is allowed", () => {
  assert.equal(evaluate({ spent: "45000000", auth: { amountAtomic: "5000000" } }).allowed, true);
});

test("window spend one unit over the cap is denied", () => {
  denies("window_limit_exceeded", { spent: "45000001", auth: { amountAtomic: "5000000" } });
});

test("a zero or negative amount is denied", () => {
  denies("amount_not_positive", { auth: { amountAtomic: "0" } });
  denies("amount_not_positive", { auth: { amountAtomic: "-1" } });
});

test("a non-integer amount is denied rather than coerced", () => {
  denies("amount_unparseable", { auth: { amountAtomic: "1.5" } });
  denies("amount_unparseable", { auth: { amountAtomic: "1e6" } });
  denies("amount_unparseable", { auth: { amountAtomic: "abc" } });
});

// ── lifecycle ──────────────────────────────────────────────────────────────

test("an expired mandate is denied", () => {
  denies("mandate_expired", { nowMs: NOW + 40 * 86_400_000 });
});

test("a not-yet-valid mandate is denied", () => {
  denies("mandate_not_yet_valid", {
    policy: { notBefore: new Date(NOW + 86_400_000).toISOString() },
  });
});

test("a REVOKED mandate is denied, and says so", () => {
  denies("mandate_revoked", { policy: { status: "REVOKED" } });
});

test("revocation outranks everything, including the approval threshold", () => {
  // A revoked mandate must never answer "approval_required" — that would invite
  // the caller to go and fetch one for authority that no longer exists.
  const r = evaluate({
    policy: { status: "REVOKED", requireApprovalAboveAtomic: "1" },
    auth: { amountAtomic: "5000000" },
  });
  assert.equal(r.reason, "mandate_revoked");
});

test("an unparseable expiry is treated as expired, not as no expiry", () => {
  denies("mandate_expired", { policy: { expiresAt: "whenever" } });
});

// ── identity ───────────────────────────────────────────────────────────────

test("a different agent cannot use this mandate", () => {
  denies("agent_mismatch", { auth: { agentKeyId: "ak_someone_else" } });
});

test("a different buyer cannot use this mandate", () => {
  denies("buyer_mismatch", { auth: { buyerKeyId: "uk_someone_else" } });
});

// ── denomination ───────────────────────────────────────────────────────────

test("a cap in one asset does not govern a payment in another", () => {
  // Comparing the numbers would be comparing unlike units.
  denies("asset_mismatch", { auth: { asset: "0xDAI" } });
});

test("a cap on one network does not govern a payment on another", () => {
  denies("network_mismatch", { auth: { network: "arbitrum" } });
});

// ── scope ──────────────────────────────────────────────────────────────────

test("a seller outside the allowlist is denied", () => {
  denies("seller_not_allowed", {
    policy: { allowedSellers: ["*.openai.com"] },
  });
});

test("a wildcard seller pattern matches subdomains", () => {
  assert.equal(
    evaluate({ policy: { allowedSellers: ["*.furlpay.com"] } }).allowed,
    true
  );
});

test("`*.example.com` does NOT match the apex", () => {
  // The conservative reading: a mandate for subdomains did not say the apex.
  assert.equal(matchesPattern("example.com", "*.example.com"), false);
  assert.equal(matchesPattern("api.example.com", "*.example.com"), true);
  // And it must not match a domain that merely ends with the same text.
  assert.equal(matchesPattern("evil-example.com", "*.example.com"), false);
});

test("an empty allowlist means unconstrained, not deny-all", () => {
  assert.equal(evaluate({ policy: { allowedSellers: [] } }).allowed, true);
  assert.equal(evaluate({ policy: { allowedSellers: undefined } }).allowed, true);
});

test("a resource outside the allowlist is denied", () => {
  denies("resource_not_allowed", {
    policy: { allowedResources: ["https://api.furlpay.com/v1/translate"] },
  });
});

// ── version ────────────────────────────────────────────────────────────────

test("a policy version mismatch is denied before anything else", () => {
  // An old mandate evaluated under new semantics is a mandate whose author
  // agreed to different rules than the ones being applied.
  denies("policy_version_mismatch", { auth: { policyVersion: "furlpay-mandate-v2" } });
});

// ── approval threshold ─────────────────────────────────────────────────────

const approved = (over = {}) => ({
  class: "STEP_UP",
  paymentHash: "0xhash",
  verified: true,
  approvedAtMs: NOW - 30_000,
  ...over,
});

test("below the threshold no approval is needed", () => {
  const r = evaluate({
    policy: { requireApprovalAboveAtomic: "2000000" },
    auth: { amountAtomic: "1000000" },
  });
  assert.equal(r.allowed, true);
  assert.equal(r.requiresApproval, false);
});

test("above the threshold with NO approval is denied", () => {
  denies("approval_required", {
    policy: { requireApprovalAboveAtomic: "500000" },
    auth: { amountAtomic: "1000000" },
  });
});

test("above the threshold WITH valid approval is allowed", () => {
  const r = evaluate({
    policy: { requireApprovalAboveAtomic: "500000", stepUpMaxAgeSeconds: 300 },
    auth: { amountAtomic: "1000000" },
    approval: approved(),
  });
  assert.equal(r.allowed, true);
  assert.equal(r.requiresApproval, true);
});

test("approval for a DIFFERENT payment does not authorize this one", () => {
  denies("approval_invalid", {
    policy: { requireApprovalAboveAtomic: "500000" },
    auth: { amountAtomic: "1000000" },
    approval: approved({ paymentHash: "0xanotherpayment" }),
  });
});

test("unverified approval is refused", () => {
  denies("approval_invalid", {
    policy: { requireApprovalAboveAtomic: "500000" },
    auth: { amountAtomic: "1000000" },
    approval: approved({ verified: false }),
  });
});

test("stale approval is refused", () => {
  denies("approval_invalid", {
    policy: { requireApprovalAboveAtomic: "500000", stepUpMaxAgeSeconds: 60 },
    auth: { amountAtomic: "1000000" },
    approval: approved({ approvedAtMs: NOW - 600_000 }),
  });
});

test("future-dated approval is refused", () => {
  denies("approval_invalid", {
    policy: { requireApprovalAboveAtomic: "500000", stepUpMaxAgeSeconds: 300 },
    auth: { amountAtomic: "1000000" },
    approval: approved({ approvedAtMs: NOW + 600_000 }),
  });
});

test("a DIRECT (human-present) payment needs no step-up", () => {
  const r = evaluate({
    policy: { requireApprovalAboveAtomic: "500000" },
    auth: { amountAtomic: "1000000" },
    approval: approved({ class: "DIRECT", approvedAtMs: undefined }),
  });
  assert.equal(r.allowed, true);
});

test("limits are checked BEFORE approval — an over-cap payment is not approvable", () => {
  // Otherwise a caller is told to fetch approval for a payment that can never
  // settle, and a valid approval would then be spent on a refusal.
  denies("per_tx_limit_exceeded", {
    policy: { requireApprovalAboveAtomic: "1" },
    auth: { amountAtomic: "9999999999" },
    approval: approved(),
  });
});

// ── the reason this module uses integers ───────────────────────────────────

test("INTEGER MONEY: the 0.1 + 0.2 > 0.3 refusal does not happen here", () => {
  // In the float model a $0.30 cap with $0.10 spent refuses a legitimate $0.20,
  // because 0.1 + 0.2 === 0.30000000000000004. In atomic units the same case is
  // exact and the payment is allowed.
  assert.equal(0.1 + 0.2 > 0.3, true, "the float bug this replaces");

  const r = evaluate({
    policy: { maxPerWindowAtomic: "300000", maxPerTxAtomic: "300000" }, // $0.30
    spent: "100000", // $0.10
    auth: { amountAtomic: "200000" }, // $0.20
  });
  assert.equal(r.allowed, true);
  assert.equal(r.evaluated.windowSpentAfterAtomic, "300000");
});

test("INTEGER MONEY: repeated addition does not drift", () => {
  // 69 additions of 0.1 reach 6.8999999999999915 in floats, so two parties
  // summing in different orders disagree about remaining budget. Integers do
  // not have that property, so both sides always agree.
  let float = 0;
  for (let i = 0; i < 69; i++) float += 0.1;
  assert.notEqual(float, 6.9);

  let atomic = 0n;
  for (let i = 0; i < 69; i++) atomic += 100000n;
  assert.equal(atomic.toString(), "6900000");
});

test("amounts beyond Number.MAX_SAFE_INTEGER compare correctly", () => {
  // A cap above 2^53 would be silently rounded by a Number comparison.
  const big = "9007199254740993"; // 2^53 + 1
  const r = evaluate({
    policy: { maxPerTxAtomic: big, maxPerWindowAtomic: big },
    auth: { amountAtomic: "9007199254740992" }, // 2^53, genuinely smaller
  });
  assert.equal(r.allowed, true, "must not round the cap down to the amount");
});
