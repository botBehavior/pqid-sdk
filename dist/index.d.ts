export { requestAuth } from "./browser/requestAuth.js";
export { verifyAssertion } from "./server/verifyAssertion.js";
export { verifyCredentials } from "./server/verifyCredentials.js";
export { signAssertionPayload, getWalletState } from "./browser/wallet.js";
export { generateEd25519KeyPair, signEd25519, signEd25519WithKey, verifyEd25519, verifyEd25519WithKey } from "./crypto/ed25519.js";
export { generateKeyPair, sign, verify, KeyPair, SigningKey, VerificationKey, bytesToBase64Url } from "./crypto/index.js";
export { generateSalt, deriveStorageKey, verifyStorageKey, rotateStorageKey, DEFAULT_PBKDF2_ITERATIONS } from "./crypto/pq-key-derivation.js";
export { encrypt, decrypt, encryptPrivateKeys, decryptPrivateKeys, encryptCredentials, decryptCredentials } from "./crypto/pq-encryption.js";
export type { DerivationSalt, StorageKey, EncryptedData, DecryptedData, EncryptedKeys, EncryptedCredentials } from "./crypto/index.js";
export type { AuthResponseBundle, AuthAssertion, Credential, AssertionCheckResult, VerifiedClaimsResult } from "./types.js";
export { generateDilithiumKeyPair, signDilithium, verifyDilithium, type DilithiumKeyPair } from "./crypto/dilithium.js";
export { ASSERTION_SPEC_VERSION, canonicalizeAssertionPayload, canonicalizeCredentialPayload } from "./utils/canonicalize.js";
export { issueCredential, DEV_ISSUER_DID } from "./issuer/devIssuer.js";
export { createDevelopmentWallet, createTestAuthBundle, type ServerWalletState } from "./server/wallet.js";
export { cryptoApi, ensureCryptoReady, isCryptoReady } from "./crypto/wasm-manager.js";
//# sourceMappingURL=index.d.ts.map