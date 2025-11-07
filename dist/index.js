export { requestAuth } from "./browser/requestAuth.js";
export { verifyAssertion } from "./server/verifyAssertion.js";
export { verifyCredentials } from "./server/verifyCredentials.js";
export { signAssertionPayload, getWalletState } from "./browser/wallet.js";
export { generateEd25519KeyPair, signEd25519, signEd25519WithKey, verifyEd25519, verifyEd25519WithKey } from "./crypto/ed25519.js";
export { generateKeyPair, sign, verify, bytesToBase64Url, 
// PQ Key Derivation
generatePQSalt, deriveStorageKey, stretchKey, verifyStorageKey, rotateStorageKey, 
// PQ Encryption Layer
pqEncrypt, pqDecrypt, encryptPrivateKeys, decryptPrivateKeys, encryptCredentials, decryptCredentials, 
// PQ Secure Storage
PQSecureStorage, 
// PQ Session Security
createAuthSession, performPQKeyExchange, signAuthResponse, verifyAuthResponse, createTemporalProof, verifyTemporalProof, createSessionAttestation, verifySessionAttestation, isSessionValid, generatePQNonce, createPQChallenge, 
// PQ Auth Bundle
createPQAuthBundle, verifyPQAuthBundle, extractClaimsFromBundle, getBundleSecurityMetadata, 
// PQ Selective Disclosure
generateCredentialProof, verifyCredentialProof, generateZKCredentialProof, verifyZKCredentialProof, composeDisclosureBundle, verifyDisclosureBundle, extractClaimsFromBundle as extractClaimsFromDisclosureBundle, determineDisclosureLevel } from "./crypto/index.js";
// PQ Dilithium Crypto
export { generateDilithiumKeyPair, signDilithium, verifyDilithium } from "./crypto/dilithium.js";
// Canonicalization helpers and spec constants
export { ASSERTION_SPEC_VERSION, canonicalizeAssertionPayload, canonicalizeCredentialPayload } from "./utils/canonicalize.js";
// Development issuer helpers (useful for test wallets/extensions)
export { issueCredential, DEV_ISSUER_DID } from "./issuer/devIssuer.js";
// WASM manager for consistent initialization
export { wasmApi, ensureWasmReady, isWasmReady } from "./crypto/wasm-manager.js";
