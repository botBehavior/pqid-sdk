import { PQStorageKey } from "./pq-key-derivation.js";
import { PQEncryptedDataSerializable } from "./pq-encryption.js";
export interface PQStorageOptions {
    namespace?: string;
    compression?: boolean;
    integrity?: boolean;
}
export interface PQStoredItem {
    key: string;
    data: PQEncryptedDataSerializable;
    metadata: {
        created: number;
        modified: number;
        version: string;
        checksum: string;
    };
}
export interface PQStorageStats {
    totalItems: number;
    totalSize: number;
    encryptedItems: number;
    lastModified: number;
}
/**
 * Quantum-resistant secure storage abstraction
 * Replaces vulnerable Chrome localStorage with encrypted, integrity-protected storage
 */
export declare class PQSecureStorage {
    private storageKey;
    private options;
    private cache;
    constructor(storageKey: PQStorageKey, options?: PQStorageOptions);
    /**
     * Securely store data with quantum-resistant encryption
     */
    secureStore(key: string, data: Uint8Array): Promise<void>;
    /**
     * Retrieve and verify data from secure storage
     */
    secureRetrieve(key: string): Promise<{
        data: Uint8Array;
        verified: boolean;
    } | null>;
    /**
     * Check data integrity without decrypting
     */
    verifyDataIntegrity(key: string): Promise<boolean>;
    /**
     * Secure deletion with quantum-resistant wiping
     */
    secureDelete(key: string): Promise<boolean>;
    /**
     * Get storage statistics
     */
    getStorageStats(): Promise<PQStorageStats>;
    /**
     * Update storage key (for key rotation)
     */
    updateStorageKey(newKey: PQStorageKey): Promise<void>;
    private getFullKey;
    private decryptAndVerify;
    private signStorageItem;
    private verifyStorageSignature;
    protected persistToStorage(key: string, data: any): Promise<void>;
    protected loadFromStorage(key: string): Promise<{
        item: PQStoredItem;
        signature: Uint8Array;
    } | null>;
    protected deserializeStorageData(data: {
        item: PQStoredItem;
        signature: string;
    }): {
        item: PQStoredItem;
        signature: Uint8Array;
    };
    protected getAllKeys(): Promise<string[]>;
    protected removeFromStorage(key: string): Promise<boolean>;
}
//# sourceMappingURL=pq-secure-storage.d.ts.map