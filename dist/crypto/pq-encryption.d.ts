import { PQStorageKey } from "./pq-key-derivation.js";
export interface PQEncryptedData {
    ciphertext: Uint8Array;
    iv: Uint8Array;
    salt: Uint8Array;
    algorithm: string;
    keyId: string;
    integrityHash: Uint8Array;
    timestamp: number;
}
export interface PQEncryptedDataSerializable {
    ciphertext: string;
    iv: string;
    salt: string;
    algorithm: string;
    keyId: string;
    integrityHash: string;
    timestamp: number;
}
export interface VerifiedData {
    data: Uint8Array;
    verified: boolean;
    timestamp: number;
}
export interface PQEncryptedKeys {
    encryptedKeys: PQEncryptedData[];
    keyCount: number;
    algorithm: string;
}
export interface PQEncryptedCredentials {
    encryptedCredentials: PQEncryptedData[];
    credentialCount: number;
    algorithm: string;
}
/**
 * Encrypt data using quantum-resistant AES-GCM with PQ-derived key
 */
export declare function pqEncrypt(data: Uint8Array, key: PQStorageKey): Promise<PQEncryptedData>;
/**
 * Decrypt data with quantum-resistant integrity verification
 */
export declare function pqDecrypt(encrypted: PQEncryptedData, key: PQStorageKey): Promise<VerifiedData>;
/**
 * Encrypt multiple private keys with quantum-resistant protection
 */
export declare function encryptPrivateKeys(keys: Array<{
    id: string;
    key: Uint8Array;
}>, storageKey: PQStorageKey): Promise<PQEncryptedKeys>;
/**
 * Decrypt private keys with integrity verification
 */
export declare function decryptPrivateKeys(encryptedKeys: PQEncryptedKeys, storageKey: PQStorageKey): Promise<Array<{
    id: string;
    key: Uint8Array;
    verified: boolean;
}>>;
/**
 * Encrypt credentials with quantum-resistant protection
 */
export declare function encryptCredentials(credentials: Array<{
    id: string;
    data: any;
}>, storageKey: PQStorageKey): Promise<PQEncryptedCredentials>;
/**
 * Decrypt credentials with integrity verification
 */
export declare function decryptCredentials(encryptedCredentials: PQEncryptedCredentials, storageKey: PQStorageKey): Promise<Array<{
    id: string;
    data: any;
    verified: boolean;
}>>;
//# sourceMappingURL=pq-encryption.d.ts.map