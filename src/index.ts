export { requestAuth } from "./browser/requestAuth.js";
export { verifyAssertion } from "./server/verifyAssertion.js";
export { verifyCredentials } from "./server/verifyCredentials.js";
export {
  signAssertionPayload,
  getWalletState
} from "./browser/wallet.js";
export {
  generateEd25519KeyPair,
  signEd25519,
  signEd25519WithKey,
  verifyEd25519,
  verifyEd25519WithKey
} from "./crypto/ed25519.js";
export {
  generateKeyPair,
  sign,
  verify,
  KeyPair,
  SigningKey,
  VerificationKey,
  bytesToBase64Url,
  // PQ Key Derivation
  generatePQSalt,
  deriveStorageKey,
  stretchKey,
  verifyStorageKey,
  rotateStorageKey,
  // PQ Encryption Layer
  pqEncrypt,
  pqDecrypt,
  encryptPrivateKeys,
  decryptPrivateKeys,
  encryptCredentials,
  decryptCredentials,
  // PQ Secure Storage
  PQSecureStorage,
  // PQ Session Security
  createAuthSession,
  performPQKeyExchange,
  signAuthResponse,
  verifyAuthResponse,
  createTemporalProof,
  verifyTemporalProof,
  createSessionAttestation,
  verifySessionAttestation,
  isSessionValid,
  generatePQNonce,
  createPQChallenge,
  // PQ Auth Bundle
  createPQAuthBundle,
  verifyPQAuthBundle,
  extractClaimsFromBundle,
  getBundleSecurityMetadata,
  // PQ Selective Disclosure
  generateCredentialProof,
  verifyCredentialProof,
  generateZKCredentialProof,
  verifyZKCredentialProof,
  composeDisclosureBundle,
  verifyDisclosureBundle,
  extractClaimsFromBundle as extractClaimsFromDisclosureBundle,
  determineDisclosureLevel
} from "./crypto/index.js";
export type {
  // PQ Types
  PQSalt,
  PQStorageKey,
  PQStretchedKey,
  PQEncryptedData,
  VerifiedData,
  PQEncryptedKeys,
  PQEncryptedCredentials,
  PQStorageOptions,
  PQStoredItem,
  PQStorageStats,
  PQSessionKeys,
  PQSharedSecret,
  PQTemporalProof,
  PQSessionAttestation,
  PQAuthBundle,
  PQBundleVerification,
  PQCredentialProof,
  PQDisclosureProof,
  PQDisclosureBundle
} from "./crypto/index.js";
export type {
  AuthResponseBundle,
  AuthAssertion,
  Credential,
  AssertionCheckResult,
  VerifiedClaimsResult
} from "./types.js";

// PQ Dilithium Crypto
export {
  generateDilithiumKeyPair,
  signDilithium,
  verifyDilithium,
  type DilithiumKeyPair
} from "./crypto/dilithium.js";

// WASM manager for consistent initialization
export { wasmApi, ensureWasmReady, isWasmReady } from "./crypto/wasm-manager.js";
