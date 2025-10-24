# pqid-sdk (v0.1 draft)

pqid-sdk is the developer kit for integrating PQID login.

PQID is a post-quantum, decentralized identity system. Users control a DID and a set of credentials (like "age_over_18", "good_standing") issued by an attester. Sites can request those claims at login without ever seeing PII like birthday or email.

## Browser usage

```ts
import { requestAuth } from "pqid-sdk/browser";

async function login() {
  const bundle = await requestAuth({
    requested_claims: [
      { type: "age_over_18", purpose: "Access mature area" },
      { type: "good_standing", purpose: "Bypass cooldown" }
    ]
  });

  await fetch("/api/login-pqid", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(bundle)
  });
}
```

## Server usage

```ts
import {
  verifyAssertion,
  verifyCredentials
} from "pqid-sdk/server";

app.post("/api/login-pqid", async (req, res) => {
  const bundle = req.body;

  const okAssert = verifyAssertion(bundle);
  const { ok: okCreds, claims } = verifyCredentials(bundle.credentials, {
    trustedIssuers: ["did:pq:issuer.local"]
  });

  if (!okAssert || !okCreds) {
    return res.status(401).json({ error: "invalid" });
  }

  // Example session:
  // req.session.did = bundle.did;
  // req.session.claims = claims;

  return res.json({
    did: bundle.did,
    claims
  });
});
```

## Status

* v0.1 is stubbed. Signatures are not yet cryptographically verified.
* Future versions:

  * Real Dilithium signing / verification via WASM.
  * Timestamp freshness and replay protection.
  * Issuer public key lookup and revocation checks.

