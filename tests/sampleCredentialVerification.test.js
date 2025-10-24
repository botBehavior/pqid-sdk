import test from "node:test";
import assert from "node:assert/strict";

test("verifyCredentials collects claims from trusted issuers", async () => {
  const now = new Date().toISOString();

  const { verifyCredentials } = await import("../dist/server/verifyCredentials.js");

  const { ok, claims } = verifyCredentials(
    [
      {
        id: "urn:uuid:cred-1",
        issuer: "did:pq:issuer.local",
        subject: "did:pq:example123",
        claim_type: "age_over_18",
        claim_value: true,
        issuanceDate: now,
        proof: {
          type: "DilithiumSignature2025",
          created: now,
          verificationMethod: "did:pq:issuer.local#sign",
          signatureBase64: "stub"
        }
      }
    ],
    { trustedIssuers: ["did:pq:issuer.local"] }
  );

  assert.ok(ok);
  assert.strictEqual(claims.age_over_18, true);
});
