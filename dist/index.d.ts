export { requestAuth } from "./browser/requestAuth.js";
export { verifyAssertion } from "./server/verifyAssertion.js";
export { verifyCredentials } from "./server/verifyCredentials.js";
export { signAssertionPayload, getWalletState } from "./browser/wallet.js";
export { generateEd25519KeyPair, signEd25519, signEd25519WithKey, verifyEd25519, verifyEd25519WithKey } from "./crypto/ed25519.js";
export { generateKeyPair, sign, verify, KeyPair, SigningKey, VerificationKey, bytesToBase64Url, generatePQSalt, deriveStorageKey, stretchKey, verifyStorageKey, rotateStorageKey, pqEncrypt, pqDecrypt, encryptPrivateKeys, decryptPrivateKeys, encryptCredentials, decryptCredentials, PQSecureStorage, createAuthSession, performPQKeyExchange, signAuthResponse, verifyAuthResponse, createTemporalProof, verifyTemporalProof, createSessionAttestation, verifySessionAttestation, isSessionValid, generatePQNonce, createPQChallenge, createPQAuthBundle, verifyPQAuthBundle, extractClaimsFromBundle, getBundleSecurityMetadata, generateCredentialProof, verifyCredentialProof, generateZKCredentialProof, verifyZKCredentialProof, composeDisclosureBundle, verifyDisclosureBundle, extractClaimsFromBundle as extractClaimsFromDisclosureBundle, determineDisclosureLevel } from "./crypto/index.js";
export type { PQSalt, PQStorageKey, PQStretchedKey, PQEncryptedData, VerifiedData, PQEncryptedKeys, PQEncryptedCredentials, PQStorageOptions, PQStoredItem, PQStorageStats, PQSessionKeys, PQSharedSecret, PQTemporalProof, PQSessionAttestation, PQAuthBundle, PQBundleVerification, PQCredentialProof, PQDisclosureProof, PQDisclosureBundle } from "./crypto/index.js";
export type { AuthResponseBundle, AuthAssertion, Credential, AssertionCheckResult, VerifiedClaimsResult } from "./types.js";
export { generateDilithiumKeyPair, signDilithium, verifyDilithium, type DilithiumKeyPair } from "./crypto/dilithium.js";
export { ASSERTION_SPEC_VERSION, canonicalizeAssertionPayload, canonicalizeCredentialPayload } from "./utils/canonicalize.js";
export { issueCredential, DEV_ISSUER_DID } from "./issuer/devIssuer.js";
export { wasmApi, ensureWasmReady, isWasmReady } from "./crypto/wasm-manager.js";
//# sourceMappingURL=index.d.ts.map