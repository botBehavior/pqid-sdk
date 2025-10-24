import test from "node:test";
import assert from "node:assert/strict";

globalThis.window = { location: { origin: "http://localhost" } };

test("requestAuth returns a signed auth response bundle", async () => {
  const { requestAuth } = await import("../dist/browser/requestAuth.js");
  const { verifyAssertion } = await import("../dist/server/verifyAssertion.js");

  const bundle = await requestAuth({
    requested_claims: [{ type: "age_over_18", purpose: "Test" }]
  });

  assert.ok(bundle.did.startsWith("did:pqid-dev:"));
  assert.ok(bundle.assertion_signatureBase64);

  const result = await verifyAssertion(bundle);
  assert.ok(result.ok);
  assert.strictEqual(result.did, bundle.did);
});

test("verifyAssertion rejects tampered assertions", async () => {
  const { requestAuth } = await import("../dist/browser/requestAuth.js");
  const { verifyAssertion } = await import("../dist/server/verifyAssertion.js");

  const bundle = await requestAuth({
    requested_claims: [{ type: "age_over_18" }]
  });

  const tampered = JSON.parse(JSON.stringify(bundle));
  tampered.assertion.challenge = "malicious";

  const result = await verifyAssertion(tampered);
  assert.ok(!result.ok);
  assert.strictEqual(result.error, "invalid assertion signature");
});

test("verifyAssertion rejects stale assertions", async () => {
  const { requestAuth } = await import("../dist/browser/requestAuth.js");
  const { verifyAssertion } = await import("../dist/server/verifyAssertion.js");

  const bundle = await requestAuth({
    requested_claims: [{ type: "age_over_18" }]
  });

  const staleBundle = JSON.parse(JSON.stringify(bundle));
  const issuedAt = Date.parse(staleBundle.assertion.timestamp);

  const originalNow = Date.now;
  Date.now = () => issuedAt + 3 * 60 * 1000;

  const result = await verifyAssertion(staleBundle);

  Date.now = originalNow;

  assert.ok(!result.ok);
  assert.strictEqual(result.error, "stale assertion");
});

test("verifyAssertion rejects DID documents without verification methods", async () => {
  const { requestAuth } = await import("../dist/browser/requestAuth.js");
  const { verifyAssertion } = await import("../dist/server/verifyAssertion.js");

  const bundle = await requestAuth({
    requested_claims: [{ type: "age_over_18" }]
  });

  const invalidBundle = JSON.parse(JSON.stringify(bundle));
  delete invalidBundle.did_document.verificationMethod;

  const result = await verifyAssertion(invalidBundle);

  assert.ok(!result.ok);
  assert.strictEqual(result.error, "missing verification method");
});
