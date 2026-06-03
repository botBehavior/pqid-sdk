import { StorageKey } from "./pq-key-derivation.js";
export interface EncryptedData {
    ciphertext: Uint8Array;
    iv: Uint8Array;
    algorithm: string;
    keyId: string;
    timestamp: number;
}
export interface EncryptedDataSerializable {
    ciphertext: string;
    iv: string;
    algorithm: string;
    keyId: string;
    timestamp: number;
}
export interface DecryptedData {
    data: Uint8Array;
    verified: boolean;
    timestamp: number;
}
export interface EncryptedKeys {
    encryptedKeys: EncryptedData[];
    keyCount: number;
    algorithm: string;
}
export interface EncryptedCredentials {
    encryptedCredentials: EncryptedData[];
    credentialCount: number;
    algorithm: string;
}
/**
 * Encrypt data using AES-256-GCM with a PIN-derived storage key.
 * Classical authenticated encryption — not quantum-resistant.
 */
export declare function encrypt(data: Uint8Array, key: StorageKey): Promise<EncryptedData>;
/**
 * Decrypt data encrypted with {@link encrypt}. The GCM authentication tag is verified
 * during decryption; a tampered ciphertext throws and is reported as not verified.
 */
export declare function decrypt(encrypted: EncryptedData, key: StorageKey): Promise<DecryptedData>;
/**
 * Encrypt multiple private keys at rest.
 */
export declare function encryptPrivateKeys(keys: Array<{
    id: string;
    key: Uint8Array;
}>, storageKey: StorageKey): Promise<EncryptedKeys>;
/**
 * Decrypt private keys encrypted with {@link encryptPrivateKeys}.
 */
export declare function decryptPrivateKeys(encryptedKeys: EncryptedKeys, storageKey: StorageKey): Promise<Array<{
    id: string;
    key: Uint8Array;
    verified: boolean;
}>>;
/**
 * Encrypt credentials at rest.
 */
export declare function encryptCredentials(credentials: Array<{
    id: string;
    data: any;
}>, storageKey: StorageKey): Promise<EncryptedCredentials>;
/**
 * Decrypt credentials encrypted with {@link encryptCredentials}.
 */
export declare function decryptCredentials(encryptedCredentials: EncryptedCredentials, storageKey: StorageKey): Promise<Array<{
    id: string;
    data: any;
    verified: boolean;
}>>;
//# sourceMappingURL=pq-encryption.d.ts.map