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
  bytesToBase64Url
} from "./crypto/index.js";
export type {
  AuthResponseBundle,
  AuthAssertion,
  Credential,
  AssertionCheckResult,
  VerifiedClaimsResult
} from "./types.js";
