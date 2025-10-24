import test from "node:test";
import assert from "node:assert/strict";

test("requestAuth returns a stubbed auth response bundle", async () => {
  globalThis.window = { location: { origin: "http://localhost" } };

  const { requestAuth } = await import("../dist/browser/requestAuth.js");

  const bundle = await requestAuth({
    requested_claims: [{ type: "age_over_18", purpose: "Test" }]
  });

  assert.ok(bundle.did);
  assert.ok(bundle.did_document);
  assert.ok(bundle.assertion);
  assert.strictEqual(bundle.credentials[0]?.claim_type, "age_over_18");
});
