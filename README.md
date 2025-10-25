# pqid-sdk (v0.1.3-dev - PQ Crypto Foundation)

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

`requestAuth` is meant to run in a first-party browser context (user present). In v0.1.3 it provisions a development wallet with Dilithium PQ signatures, signs the relying party challenge, and bundles credentials issued by the development issuer. Only claims requested in `requested_claims` are returned.

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
    trustedIssuers: ["did:pqid-issuer:dev"],
    expectedSubjectDid: assertionResult.did!
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

`verifyAssertion` resolves to `{ ok, did?, error? }` after checking signature validity, DID binding, spec version, and timestamp freshness (2 minute window). `verifyCredentials` resolves to `{ ok, claims, errors }` after enforcing issuer trust, verifying credential signatures, and ensuring each credential is still valid. Only validated claims appear in `claims`.

## Security model

- **Browser / wallet** – Generates Dilithium PQ keypairs for user identity, derives a DID (`did:pqid:<base64url(pubkey)>`), and signs the relying party challenge locally. The wallet only discloses credentials for claims explicitly requested.
- **Issuer** – The development issuer (`did:pqid-issuer:dev`) issues single-claim credentials with a 24-hour lifetime and signs them using Dilithium PQ signatures.
- **Server** – Must call both `verifyAssertion` and `verifyCredentials` before trusting any bundle. Do **not** accept credentials from issuers that are not in your allow-list. Reject assertions that are stale, missing, or fail signature verification, and ensure each credential's `subject` matches the DID proven by the assertion.

## Current Implementation Status

**🚧 ACTIVE DEVELOPMENT: PQ Crypto Foundation**

- ✅ Ed25519 signing and verification (legacy compatibility)
- ✅ Dilithium PQ crypto implementation (`src/crypto/dilithium.ts`)
- ✅ Crypto abstraction layer (`src/crypto/index.ts`)
- ✅ PQ signature support in types and verification
- 🔄 Updating wallet to use PQ signatures by default
- 🔄 Updating issuer to use PQ credential signing
- 🔄 Maintaining Ed25519 backward compatibility

### Development vs Production

**This v0.1.3-dev release is transitioning to post-quantum security.**

- Uses Dilithium PQ signatures by default (quantum-resistant)
- Maintains Ed25519 compatibility for existing deployments
- Includes hardcoded development issuer keys
- Not yet suitable for production use

**For production deployment:**
- Complete PQ crypto migration
- Implement production issuer infrastructure with key rotation
- Add credential revocation capabilities
- Deploy secure wallet extensions with hardware security

### Replay guidance

- Generate a unique `challenge` per login request and persist it server-side.
- Invalidate the `challenge` immediately after a successful verification.
- Reject bundles where the assertion timestamp is older than two minutes or the `challenge` was already redeemed.

## Protocol details

- `AuthAssertion.spec_version` identifies the handshake revision (`"pqid-auth-0.1.3"`). Upgrades will bump this string so verifiers can roll out safely.
- Timestamps are ISO 8601 strings and must be within **2 minutes** of server time during verification.
- Credentials include `validUntil` (ISO) and are rejected when expired.
- Canonicalization for signatures sorts fields alphabetically; changing the order will invalidate signatures.

## Cryptography Implementation

- **PQ Signatures**: Dilithium implementation with NIST standardization
- **Legacy Support**: Ed25519 for backward compatibility
- **Algorithm Negotiation**: Runtime algorithm detection and validation
- **Future Migration**: Falcon support planned for v0.2+

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

## Status & Roadmap

- ✅ v0.1.2: working Ed25519-backed signing wallet, credential issuer, and verification pipeline with comprehensive tests.
- 🔄 v0.1.3: **IN PROGRESS** - PQ crypto foundation implementation
- 🔜 v0.2.0: Standalone issuer service (`pqid-issuer`), credential revocation
- 🔜 v0.3.0: Multi-issuer support, advanced privacy features, enterprise features

## API Reference

### Browser API
- `requestAuth(options)` - Generate authentication bundle with PQ signatures
- `getWalletState()` - Get current wallet DID and public keys

### Server API
- `verifyAssertion(bundle)` - Verify user identity and signature
- `verifyCredentials(credentials, options)` - Verify credential authenticity
- `checkCredentialExpiry(credential, now?)` - Check credential validity

### Crypto API
- `generateKeyPair(algorithm?)` - Generate PQ or Ed25519 keypairs
- `sign(key, message)` - Sign with appropriate algorithm
- `verify(key, message, signature)` - Verify with appropriate algorithm

