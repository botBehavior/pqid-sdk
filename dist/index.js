export { requestAuth } from "./browser/requestAuth.js";
export { verifyAssertion } from "./server/verifyAssertion.js";
export { verifyCredentials } from "./server/verifyCredentials.js";
export { signAssertionPayload, getWalletState } from "./browser/wallet.js";
export { generateEd25519KeyPair, signEd25519, signEd25519WithKey, verifyEd25519, verifyEd25519WithKey } from "./crypto/ed25519.js";
// Core crypto primitives
export { generateKeyPair, sign, verify, bytesToBase64Url } from "./crypto/index.js";
// Local at-rest key derivation (PBKDF2-HMAC-SHA256) and encryption (AES-256-GCM).
// These are CLASSICAL primitives for protecting locally-stored secrets behind a user PIN.
// They are NOT post-quantum and are unrelated to the ML-DSA signing core.
export { generateSalt, deriveStorageKey, verifyStorageKey, rotateStorageKey, DEFAULT_PBKDF2_ITERATIONS } from "./crypto/pq-key-derivation.js";
export { encrypt, decrypt, encryptPrivateKeys, decryptPrivateKeys, encryptCredentials, decryptCredentials } from "./crypto/pq-encryption.js";
// PQ Dilithium Crypto (the real post-quantum signing core: FIPS 204 ML-DSA-65)
export { generateDilithiumKeyPair, signDilithium, verifyDilithium } from "./crypto/dilithium.js";
// Canonicalization helpers and spec constants
export { ASSERTION_SPEC_VERSION, canonicalizeAssertionPayload, canonicalizeCredentialPayload } from "./utils/canonicalize.js";
// Development issuer helpers (useful for test wallets/extensions)
export { issueCredential, DEV_ISSUER_DID } from "./issuer/devIssuer.js";
// Server-side wallet utilities for development/testing
export { createDevelopmentWallet, createTestAuthBundle } from "./server/wallet.js";
// Low-level primitive accessors (noble-based ML-DSA, ML-KEM, AES-GCM, PBKDF2)
export { cryptoApi, ensureCryptoReady, isCryptoReady } from "./crypto/wasm-manager.js";
