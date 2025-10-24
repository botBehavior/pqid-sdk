# pqid-sdk (v0.1.1 working draft)

pqid-sdk is the developer kit for integrating PQID login.

PQID is a post-quantum ready, decentralized identity system. Users control a DID and a set of credentials (like `"age_over_18"`, `"good_standing"`) issued by attesters. Sites can request those claims at login without ever seeing PII such as birthday or email.

## Installation

```bash
npm install pqid-sdk
# or
pnpm add pqid-sdk
```

Local development helpers:

```bash
npm install
npm run build
npm test
```

## Browser usage

```ts
import { requestAuth } from "pqid-sdk/browser";

async function loginWithPQID() {
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

`requestAuth` is meant to run in a first-party browser context (user present). In v0.1.1 it provisions a development wallet, signs the relying party challenge using Ed25519, and bundles credentials issued by the development issuer.

## Server usage

```ts
import { verifyAssertion, verifyCredentials } from "pqid-sdk/server";

app.post("/api/login-pqid", async (req, res) => {
  const bundle = req.body;

  const assertionResult = await verifyAssertion(bundle);
  if (!assertionResult.ok) {
    return res.status(401).json({ error: assertionResult.error });
  }

  const credentialResult = await verifyCredentials(bundle.credentials, {
    trustedIssuers: ["did:pqid-issuer:dev"]
  });

  if (!credentialResult.ok) {
    return res.status(401).json({
      error: "invalid_credentials",
      details: credentialResult.errors
    });
  }

  // Example session bootstrap
  // req.session.did = assertionResult.did;
  // req.session.claims = credentialResult.claims;

  return res.json({
    did: assertionResult.did,
    claims: credentialResult.claims
  });
});
```

`verifyAssertion` resolves to `{ ok, did?, error? }` after checking signature validity, DID binding, and timestamp freshness (2 minute window). `verifyCredentials` resolves to `{ ok, claims, errors }` after enforcing issuer trust, verifying credential signatures, and ensuring each credential is still valid.

## Security model (draft)

- **Browser / wallet** – Generates a per-session Ed25519 keypair, derives a DID (`did:pqid-dev:<pubkey>`), and signs the relying party challenge locally. The wallet only discloses credentials for claims explicitly requested.
- **Issuer** – The development issuer (`did:pqid-issuer:dev`) issues single-claim credentials with a 24-hour lifetime and signs them using Ed25519.
- **Server** – Must call both `verifyAssertion` and `verifyCredentials` before trusting any bundle. Do **not** accept credentials from issuers that are not in your allow-list. Reject assertions that are stale, missing, or fail signature verification.
- **Challenges & replay** – The relying party should mint and persist a unique `challenge` for each login attempt and ensure it is only accepted once. v0.1.1 validates timestamps; replay protection storage is left to integrators.

## Protocol details

- `AuthAssertion.spec_version` identifies the handshake revision (`"pqid-auth-0.1.1"`). Upgrades will bump this string so verifiers can roll out safely.
- Timestamps are ISO 8601 strings and must be within **2 minutes** of server time during verification.
- Credentials include `validUntil` (ISO) and are rejected when expired.
- All signatures in v0.1.1 use Ed25519 for ease of integration. Production deployments should replace this with Dilithium/Falcon when available.

## Flow overview

```
[Frontend] requestAuth() ──→ AuthResponseBundle
                │
                ▼
[Backend] verifyAssertion(bundle)
                │
                ▼
          verifyCredentials(bundle.credentials)
                │
                ▼
           ✅ Verified claims
```

## Status & future work

- ✅ v0.1.1: working Ed25519-backed signing wallet, credential issuer, and verification pipeline with comprehensive tests.
- 🔜 v0.2+: swap signatures for post-quantum primitives (Dilithium), add issuer key resolution & revocation, and ship replay protection helpers.

