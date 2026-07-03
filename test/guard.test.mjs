import { test } from "node:test";
import assert from "node:assert/strict";
import {
  requestBindingHash,
  verifyRequestBinding,
  MemoryNonceStore,
  guardedSettle,
} from "../dist/index.js";

// A settler that always confirms (mock chain). Counts how many times it runs.
function countingSettler() {
  const state = { runs: 0 };
  const settler = async () => {
    state.runs++;
    // simulate the async verify→settle gap the paper's F2 race exploits
    await new Promise((r) => setTimeout(r, 5));
    return { status: "confirmed", transaction: "0x" + state.runs };
  };
  return { settler, state };
}

test("F1: cross-resource substitution is rejected (paper §4.1 / §5.1)", () => {
  // A signature minted for resource A carries a binding to A's request.
  const bindingForA = requestBindingHash("GET", "/premium/report-A", "");

  // Honest replay against the SAME resource verifies.
  assert.equal(verifyRequestBinding(bindingForA, "GET", "/premium/report-A", ""), true);

  // Attacker attaches A's binding to an equal-priced resource B → rejected.
  assert.equal(verifyRequestBinding(bindingForA, "GET", "/premium/report-B", ""), false);

  // Body tampering is also caught (Pattern 2: malleable metadata).
  const bindingWithBody = requestBindingHash("POST", "/premium/analyze", '{"n":1}');
  assert.equal(verifyRequestBinding(bindingWithBody, "POST", "/premium/analyze", '{"n":2}'), false);
});

test("F1: guardedSettle blocks a payment bound to a different resource", async () => {
  const store = new MemoryNonceStore();
  const { settler, state } = countingSettler();

  const res = await guardedSettle({}, {
    nonce: "n-f1",
    store,
    settler,
    binding: { presented: requestBindingHash("GET", "/a", ""), method: "GET", uri: "/b" },
  });

  assert.equal(res.success, false);
  assert.equal(res.reason, "resource_binding_mismatch");
  assert.equal(state.runs, 0, "settler must not run when binding fails (fail-closed, no wasted compute)");
});

test("F2: concurrent duplicate settlement — only ONE request settles (paper §4.2 / §5.2)", async () => {
  const store = new MemoryNonceStore();
  const { settler, state } = countingSettler();
  const nonce = "n-race";

  // 20 concurrent requests all carrying the SAME authorization nonce,
  // mirroring the paper's 20-concurrent-request reproduction on Base.
  const results = await Promise.all(
    Array.from({ length: 20 }, () => guardedSettle({}, { nonce, store, settler }))
  );

  const settled = results.filter((r) => r.success);
  assert.equal(settled.length, 1, "exactly one concurrent request may settle");
  assert.equal(state.runs, 1, "the settler must execute exactly once (I4: Authorization Uniqueness)");

  // Every loser is told why, and the nonce is terminal.
  const losers = results.filter((r) => !r.success);
  assert.equal(losers.length, 19);
  assert.equal(await store.state(nonce), "settled");
});

test("F2 replay hole: an UNKNOWN settlement is never rolled back to replayable", async () => {
  const store = new MemoryNonceStore();
  const nonce = "n-timeout";

  // First attempt times out (facilitator gave up, but the tx MAY confirm).
  const first = await guardedSettle({}, {
    nonce,
    store,
    settler: async () => ({ status: "unknown" }),
  });
  assert.equal(first.success, false);
  assert.equal(first.reason, "settlement_unknown_locked");
  assert.equal(await store.state(nonce), "pending", "nonce stays PENDING, not freed");

  // A replay of the same nonce must NOT get a second bite — this is the exact
  // hole that deleting the nonce on failure (naïve facilitators) opens.
  let secondSettlerRan = false;
  const second = await guardedSettle({}, {
    nonce,
    store,
    settler: async () => {
      secondSettlerRan = true;
      return { status: "confirmed", transaction: "0xreplay" };
    },
  });
  assert.equal(second.success, false);
  assert.equal(second.reason, "nonce_in_flight");
  assert.equal(secondSettlerRan, false, "no compute spent on a replayed locked nonce");
});

test("F2: a provably-failed settlement DOES free the nonce for a legit retry", async () => {
  const store = new MemoryNonceStore();
  const nonce = "n-fail";

  const first = await guardedSettle({}, {
    nonce,
    store,
    settler: async () => ({ status: "failed_no_tx" }),
  });
  assert.equal(first.success, false);
  assert.equal(first.reason, "settlement_failed");
  assert.equal(await store.state(nonce), undefined, "chain proved no tx → nonce released");

  // Now an honest retry can succeed.
  const retry = await guardedSettle({}, {
    nonce,
    store,
    settler: async () => ({ status: "confirmed", transaction: "0xok" }),
  });
  assert.equal(retry.success, true);
  assert.equal(retry.transaction, "0xok");
});
