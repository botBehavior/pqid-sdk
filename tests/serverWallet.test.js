import test from "node:test";
import assert from "node:assert/strict";

// Regression test for the server-wallet DID bug.
//
// createDevelopmentWallet previously minted a DID of the form `did:pqid:dev-<first 16 chars>`,
// but verifyAssertion derives the verification key from the DID's last `:`-delimited segment.
// The truncated `dev-...` segment is not the public key, so every server-wallet bundle failed
// verification with "did document key mismatch". The fix uses the full base64url public key.

test("server-wallet bundle verifies end-to-end (did:pqid:<full key>)", async () => {
  const { createDevelopmentWallet, createTestAuthBundle } = await import("../dist/server/wallet.js");
  const { verifyAssertion } = await import("../dist/server/verifyAssertion.js");

  const wallet = await createDevelopmentWallet();

  // DID must carry the full key, not a truncated `dev-` prefix.
  assert.ok(wallet.did.startsWith("did:pqid:"));
  assert.ok(!wallet.did.startsWith("did:pqid:dev-"), "DID must not use the truncated dev- form");

  const bundle = await createTestAuthBundle(wallet, [{ type: "age_over_18" }]);
  const result = await verifyAssertion(bundle);

  if (!result.ok) {
    console.error("verifyAssertion error:", result.error, "did:", bundle.did);
  }
  assert.ok(result.ok, "server-wallet assertion should verify");
  assert.strictEqual(result.did, wallet.did);
});

test("verifyCredentials no longer honors a '*' trusted-issuer wildcard", async () => {
  const { createDevelopmentWallet, createTestAuthBundle } = await import("../dist/server/wallet.js");
  const { verifyCredentials } = await import("../dist/server/verifyCredentials.js");

  const wallet = await createDevelopmentWallet();
  const bundle = await createTestAuthBundle(wallet, [{ type: "age_over_18" }]);

  // "*" used to trust every issuer. It must now be treated as a literal (non-matching) DID.
  const result = await verifyCredentials(bundle.credentials, {
    trustedIssuers: ["*"],
    expectedSubjectDid: wallet.did
  });

  assert.ok(!result.ok);
  assert.ok(result.errors.some((e) => e.reason.includes("is not trusted")));
});
