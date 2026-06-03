import test from "node:test";
import assert from "node:assert/strict";

globalThis.window = { location: { origin: "http://localhost" } };

async function getAuthBundle() {
  const { requestAuth } = await import("../dist/browser/requestAuth.js");
  return requestAuth({
    requested_claims: [
      { type: "age_over_18" },
      { type: "good_standing" },
      { type: "account_age_days_over_30" }
    ]
  });
}

test("verifyCredentials collects claims from trusted issuers", async () => {
  const { verifyCredentials } = await import("../dist/server/verifyCredentials.js");
  const { DEV_ISSUER_DID } = await import("../dist/issuer/devIssuer.js");

  const bundle = await getAuthBundle();
  const result = await verifyCredentials(bundle.credentials, {
    trustedIssuers: [DEV_ISSUER_DID],
    expectedSubjectDid: bundle.did
  });

  assert.ok(result.ok);
  assert.strictEqual(result.claims.age_over_18, true);
  assert.strictEqual(result.claims.good_standing, true);
  assert.strictEqual(result.claims.account_age_days_over_30, 60);
  assert.deepStrictEqual(result.errors, []);
});

test("verifyCredentials flags untrusted issuers", async () => {
  const { verifyCredentials } = await import("../dist/server/verifyCredentials.js");
  const bundle = await getAuthBundle();

  const result = await verifyCredentials(bundle.credentials, {
    trustedIssuers: [],
    expectedSubjectDid: bundle.did
  });

  assert.ok(!result.ok);
  assert.ok(
    result.errors.some((error) =>
      error.reason.includes("is not trusted")
    )
  );
});

test("verifyCredentials rejects expired credentials", async () => {
  const { verifyCredentials } = await import("../dist/server/verifyCredentials.js");
  const { DEV_ISSUER_DID } = await import("../dist/issuer/devIssuer.js");

  const bundle = await getAuthBundle();
  const expiredCredential = JSON.parse(JSON.stringify(bundle.credentials[0]));
  expiredCredential.validUntil = new Date(Date.now() - 60 * 60 * 1000).toISOString();

  const result = await verifyCredentials([expiredCredential], {
    trustedIssuers: [DEV_ISSUER_DID],
    expectedSubjectDid: bundle.did
  });

  assert.ok(!result.ok);
  assert.ok(
    result.errors.some((error) => error.reason === "credential expired")
  );
});

test("verifyCredentials detects tampered claims", async () => {
  const { verifyCredentials } = await import("../dist/server/verifyCredentials.js");
  const { DEV_ISSUER_DID } = await import("../dist/issuer/devIssuer.js");

  const bundle = await getAuthBundle();
  const tampered = JSON.parse(JSON.stringify(bundle.credentials[0]));
  tampered.claim_value = false;

  const result = await verifyCredentials([tampered], {
    trustedIssuers: [DEV_ISSUER_DID],
    expectedSubjectDid: bundle.did
  });

  assert.ok(!result.ok);
  assert.ok(
    result.errors.some((error) => error.reason === "invalid credential signature")
  );
});

test("verifyCredentials rejects credentials for another subject", async () => {
  const { verifyCredentials } = await import("../dist/server/verifyCredentials.js");
  const { DEV_ISSUER_DID } = await import("../dist/issuer/devIssuer.js");

  const bundle = await getAuthBundle();
  const mismatched = JSON.parse(JSON.stringify(bundle.credentials[0]));
  mismatched.subject = "did:pqid-dev:attacker";

  const result = await verifyCredentials([mismatched], {
    trustedIssuers: [DEV_ISSUER_DID],
    expectedSubjectDid: bundle.did
  });

  assert.ok(!result.ok);
  assert.ok(
    result.errors.some((error) =>
      error.reason.includes("does not match expected DID")
    )
  );
  assert.deepStrictEqual(result.claims, {});
});
