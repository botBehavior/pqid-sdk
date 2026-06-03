export declare const DEFAULT_PBKDF2_ITERATIONS = 600000;
export interface DerivationSalt {
    salt: Uint8Array;
    timestamp: number;
    algorithm: string;
}
export interface StorageKey {
    key: Uint8Array;
    salt: DerivationSalt;
    keyId: string;
    iterations: number;
    algorithm: string;
}
/**
 * Generate a random 256-bit salt for key derivation.
 */
export declare function generateSalt(): Promise<DerivationSalt>;
/**
 * Derive a storage-encryption key from a user PIN using PBKDF2-HMAC-SHA256.
 * Classical KDF — not quantum-resistant.
 */
export declare function deriveStorageKey(userPIN: string, salt?: DerivationSalt, iterations?: number): Promise<StorageKey>;
/**
 * Verify a user PIN against a previously-derived storage key by re-deriving with the
 * stored salt and iteration count and comparing in constant time.
 */
export declare function verifyStorageKey(storageKey: StorageKey, userPIN: string): Promise<boolean>;
/**
 * Rotate a storage key by deriving a fresh key from a new PIN. Returns both keys so the
 * caller can re-encrypt stored data with the new key.
 */
export declare function rotateStorageKey(oldKey: StorageKey, newPIN: string): Promise<{
    oldKey: StorageKey;
    newKey: StorageKey;
}>;
//# sourceMappingURL=pq-key-derivation.d.ts.map