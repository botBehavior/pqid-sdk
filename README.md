# PQID SDK

**Post-quantum authentication for the web.** Sign in with a decentralized identity backed by NIST-standardized post-quantum signatures — no passwords, no shared secrets, no quantum-vulnerable keys.

PQID is a TypeScript SDK for **DID-based authentication built on ML-DSA-65 (Dilithium, [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final))**. A client holds a post-quantum keypair, derives a decentralized identifier from its public key, and signs a short-lived assertion; a relying party verifies that assertion and any attached verifiable credentials — end to end with post-quantum-secure signatures.

It's built for the *harvest-now, decrypt-later* threat model: the identities and the signatures that prove them stay sound even against an adversary holding a future quantum computer.

## How it works

```
Client (browser / extension / server)         Relying-party backend
─────────────────────────────────────         ─────────────────────
1. generate ML-DSA-65 keypair
2. did:pqid:<base64url(publicKey)>
3. sign assertion(challenge, audience)   ──▶   verifyAssertion()
   + attach verifiable credentials               ├─ ML-DSA signature
                                                  ├─ DID ⇄ key binding
                                                  ├─ freshness (2 min)
                                                  └─ spec version
                                         ──▶   verifyCredentials()
                                                  ├─ trusted issuer
                                                  ├─ issuer signature
                                                  ├─ expiry
                                                  └─ subject match
```

The identifier *is* the public key — `did:pqid:<base64url(pubkey)>` — so the verifier re-derives and binds the key straight from the DID. No registry, no key distribution, nothing to look up.

## Features

- **ML-DSA-65 signatures** (FIPS 204) for assertions and credentials, via [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum).
- **Self-certifying DIDs** derived directly from the public key — no registry, no central authority.
- **Assertion verification** — signature, DID/key binding, freshness window, and spec-version checks.
- **Verifiable credentials** — explicit trusted-issuer model, issuer-signature verification, expiry, and subject binding.
- **One API, three client environments** — a browser wallet extension, an in-browser development wallet, and a server/test wallet, selected automatically.
- **Optional encrypted storage** — AES-256-GCM at rest, keyed by PBKDF2-HMAC-SHA256 (600k iterations) derived from a user PIN.
- **Zero native dependencies** — pure JavaScript and Web Crypto; no WebAssembly to ship or sandbox.

## Installation

```bash
npm install pqid-sdk
```

## Quick start

### Client

```typescript
import { requestAuth } from "pqid-sdk/browser";

const bundle = await requestAuth({
  requested_claims: [
    { type: "age_over_18", purpose: "Verify adult content access" },
    { type: "good_standing", purpose: "Account status check" }
  ],
  challenge: "<single-use challenge from your backend>",
  audience: "https://yourapp.com"
});

await fetch("/api/auth/verify", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(bundle)
});
```

`requestAuth` picks its environment automatically: the PQID wallet extension (`window.pqid`) when present, an in-browser development wallet otherwise, or `createDevelopmentWallet` under Node.

### Relying party

```typescript
import { verifyAssertion, verifyCredentials } from "pqid-sdk/server";

app.post("/api/auth/verify", async (req, res) => {
  const assertion = await verifyAssertion(req.body);
  if (!assertion.ok) return res.status(401).json({ error: assertion.error });

  const credentials = await verifyCredentials(req.body.credentials, {
    trustedIssuers: ["did:pqid-issuer:main"],   // enumerate the issuers you trust
    expectedSubjectDid: assertion.did
  });
  if (!credentials.ok) return res.status(401).json({ error: "invalid_credentials" });

  req.session.did = assertion.did;
  req.session.claims = credentials.claims;
  res.json({ success: true, did: assertion.did, claims: credentials.claims });
});
```

## API

### `requestAuth(options): Promise<AuthResponseBundle>` — browser

```typescript
interface RequestAuthOptions {
  requested_claims: RequestedClaim[];   // required
  challenge?: string;                   // server-issued, single-use
  audience?: string;
  purpose?: string;
}
```

### `verifyAssertion(bundle): Promise<AssertionVerificationResult>` — server

Validates the ML-DSA signature, DID/key binding, a 2-minute freshness window, and the spec version. Returns `{ ok, did?, error? }`.

### `verifyCredentials(credentials, options): Promise<CredentialVerificationResult>` — server

```typescript
interface VerifyCredentialsOptions {
  trustedIssuers: string[];                    // required — enumerate explicitly
  expectedSubjectDid: string;                  // required
  now?: Date;
  issuerPublicKeys?: Record<string, string>;   // optional, for custom issuers
}
```

Validates issuer trust, the ML-DSA issuer signature, expiry, and subject binding. Returns `{ ok, claims, errors }`.

### Crypto & wallets

- `generateDilithiumKeyPair`, `signDilithium`, `verifyDilithium` — the ML-DSA-65 core.
- `generateKeyPair`, `sign`, `verify` — algorithm-abstracted (ML-DSA or Ed25519).
- `encrypt` / `decrypt`, `deriveStorageKey` / `verifyStorageKey` — AES-256-GCM + PBKDF2 at-rest helpers (`DEFAULT_PBKDF2_ITERATIONS = 600_000`).
- `createDevelopmentWallet`, `createTestAuthBundle` — server-side ML-DSA wallet + signed bundles for tests.

## Supported claim types

`age_over_18`, `good_standing`, `account_age_days_over_30`, `email_verified`, `google_account_age_over_365`, `github_account_age_over_180`, `apple_user`, `human_user`.

Credentials are issued and signed by a separate PQID issuer service; this SDK verifies them against an issuer key you trust.

## Protocol

- **Spec version** `pqid-auth-0.1.2`.
- **Canonicalization** — fields sorted alphabetically, URL-encoded, joined with `&`, then signed.
- **Freshness** — assertions older than 2 minutes are rejected.
- **Replay protection** — relying parties issue single-use challenges and reject reuse; the SDK checks the signature and freshness, the RP owns challenge uniqueness.

## Runtime

Node ≥ 20 or a modern browser (requires a global Web Crypto API). Uses Web Crypto (AES-GCM, PBKDF2, Ed25519) and the pure-JS `@noble/post-quantum` library for ML-DSA / ML-KEM. No WebAssembly required.

## Status & scope

Alpha. The ML-DSA-65 signing core and the assertion/credential verification path are implemented and covered by the test suite; the browser-extension end-to-end flow is verified manually rather than in CI. The post-quantum guarantee applies to the **signature layer** — the optional at-rest storage helpers use classical AES-256-GCM and PBKDF2. It has not had an independent security audit; treat it as a reference implementation rather than a turnkey production identity provider.

## Testing

```bash
npm install
npm test   # builds, then runs the node:test suite over tests/*.test.js
```

## License

MIT — see [LICENSE](./LICENSE).
