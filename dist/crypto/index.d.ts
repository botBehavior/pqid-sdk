import { SignatureAlgorithm } from "../types.js";
export interface KeyPair {
    publicKey: Uint8Array | CryptoKey;
    privateKey: Uint8Array | CryptoKey;
    publicKeyBase64: string;
    privateKeyBase64?: string;
    algorithm: SignatureAlgorithm;
}
export interface SigningKey {
    privateKey: Uint8Array | CryptoKey;
    algorithm: SignatureAlgorithm;
}
export interface VerificationKey {
    publicKey: Uint8Array | CryptoKey | string;
    algorithm: SignatureAlgorithm;
}
export declare function generateKeyPair(algorithm?: SignatureAlgorithm): Promise<KeyPair>;
export declare function sign(key: SigningKey, message: string): Promise<string>;
export declare function verify(key: VerificationKey, message: string, signature: string): Promise<boolean>;
export { generatePQSalt, deriveStorageKey, stretchKey, verifyStorageKey, rotateStorageKey, type PQSalt, type PQStorageKey, type PQStretchedKey } from "./pq-key-derivation.js";
export { pqEncrypt, pqDecrypt, encryptPrivateKeys, decryptPrivateKeys, encryptCredentials, decryptCredentials, type PQEncryptedData, type VerifiedData, type PQEncryptedKeys, type PQEncryptedCredentials } from "./pq-encryption.js";
export { generateDilithiumKeyPair, signDilithium, verifyDilithium, type DilithiumKeyPair } from "./dilithium.js";
export { PQSecureStorage, type PQStorageOptions, type PQStoredItem, type PQStorageStats } from "./pq-secure-storage.js";
export { createAuthSession, performPQKeyExchange, signAuthResponse, verifyAuthResponse, createTemporalProof, verifyTemporalProof, createSessionAttestation, verifySessionAttestation, isSessionValid, generatePQNonce, createPQChallenge, type PQSessionKeys, type PQSharedSecret, type PQTemporalProof, type PQSessionAttestation } from "./pq-session-security.js";
export { createPQAuthBundle, verifyPQAuthBundle, extractClaimsFromBundle, getBundleSecurityMetadata, type PQAuthBundle, type PQBundleVerification } from "./pq-auth-bundle.js";
export { generateCredentialProof, verifyCredentialProof, generateZKCredentialProof, verifyZKCredentialProof, composeDisclosureBundle, verifyDisclosureBundle, extractClaimsFromBundle as extractClaimsFromDisclosureBundle, determineDisclosureLevel, type PQCredentialProof, type PQDisclosureProof, type PQDisclosureBundle } from "./pq-selective-disclosure.js";
export { bytesToBase64Url } from "./base64.js";
export { wasmApi, ensureWasmReady, isWasmReady } from "./wasm-manager.js";
//# sourceMappingURL=index.d.ts.map