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
export { generateSalt, deriveStorageKey, verifyStorageKey, rotateStorageKey, type DerivationSalt, type StorageKey } from "./pq-key-derivation.js";
export { encrypt, decrypt, encryptPrivateKeys, decryptPrivateKeys, encryptCredentials, decryptCredentials, type EncryptedData, type DecryptedData, type EncryptedKeys, type EncryptedCredentials } from "./pq-encryption.js";
export { generateDilithiumKeyPair, signDilithium, verifyDilithium, type DilithiumKeyPair } from "./dilithium.js";
export { bytesToBase64Url } from "./base64.js";
export { cryptoApi, ensureCryptoReady, isCryptoReady } from "./wasm-manager.js";
//# sourceMappingURL=index.d.ts.map