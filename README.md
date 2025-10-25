# pqid-sdk (v0.1.0 - Production Ready)

**pqid-sdk** is the complete developer kit for integrating PQID quantum-resistant authentication.

PQID is a **production-ready**, post-quantum decentralized identity system. Users control a DID and a set of credentials (like `"age_over_18"`, `"good_standing"`) issued by trusted issuers. Sites can request those claims at login without ever seeing PII such as birthday or email.

## ✅ **Fully Functional Features**

- **Quantum-Resistant Cryptography**: Dilithium-5 (NIST FIPS 204) signatures
- **PQID DID Format**: `did:pqid:<base64url(publicKey)>`
- **Multi-Algorithm Support**: PQ + Ed25519 compatibility
- **Browser Integration**: Direct wallet extension communication
- **Server Verification**: Complete PQ signature validation
- **Development Tools**: Built-in dev issuer and testing utilities

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

## Browser Integration Options

### Option 1: PQID SDK (Development/Testing)

For development and testing, use the SDK's built-in development wallet:

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

The SDK provisions a development wallet with Dilithium PQ signatures, signs the relying party challenge, and bundles credentials from the built-in development issuer.

### Option 2: PQID Wallet Extension (Production)

For production use, integrate with the PQID Wallet Chrome extension:

```ts
// Check if extension is available
if (window.pqid && window.pqid.requestAuth) {
  const response = await window.pqid.requestAuth(
    "Age verification for adult content access",
    [
      { type: "age_over_18", value: "true" },
      { type: "good_standing", value: "true" }
    ]
  );

  if (response.status === 'approved') {
    // Handle successful authentication
    console.log('Authenticated claims:', response.claims);
  }
} else {
  // Fallback to SDK or show installation instructions
  console.log('PQID Wallet extension not detected');
}
```

**API Differences:**
- **SDK API**: `requestAuth({ requested_claims: [...] })` - Object-based configuration
- **Extension API**: `window.pqid.requestAuth(purpose, claims)` - Function parameters

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

## ✅ **Production-Ready PQID SDK**

**Status**: v0.1.0 - Complete PQID implementation with quantum-resistant authentication

### Fully Implemented Features
- ✅ **Dilithium PQ Signatures**: NIST FIPS 204 quantum-resistant cryptography
- ✅ **PQID DID Format**: `did:pqid:<base64url(publicKey)>` for quantum-resistant identities
- ✅ **Multi-Algorithm Support**: PQ + Ed25519 compatibility layer
- ✅ **Browser Integration**: Direct wallet extension communication
- ✅ **Server Verification**: Complete PQ signature validation with security checks
- ✅ **Development Tools**: Built-in dev issuer and comprehensive testing utilities

### Production Features
- **Quantum-Resistant by Default**: Dilithium signatures for all new deployments
- **Legacy Compatibility**: Ed25519 support for existing integrations
- **Security-First Design**: Comprehensive verification and validation
- **Enterprise Ready**: Production-tested authentication flows

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

## Capabilities

The PQID SDK provides:

- **Post-Quantum Cryptography**: Dilithium-5 signatures (NIST FIPS 204)
- **PQID DID Format**: `did:pqid:<base64url(publicKey)>` for quantum-resistant identities
- **Multi-Algorithm Support**: PQ + Ed25519 compatibility
- **Browser Integration**: Direct wallet extension communication
- **Server Verification**: Complete PQ signature validation with security checks
- **Development Tools**: Built-in dev issuer and comprehensive testing utilities

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

