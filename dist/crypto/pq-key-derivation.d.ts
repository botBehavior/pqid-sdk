export interface PQSalt {
    salt: Uint8Array;
    timestamp: number;
    algorithm: string;
}
export interface PQStorageKey {
    key: Uint8Array;
    salt: PQSalt;
    keyId: string;
    algorithm: string;
}
export interface PQStretchedKey {
    key: Uint8Array;
    rounds: number;
    algorithm: string;
}
/**
 * Generate a quantum-resistant salt for key derivation
 */
export declare function generatePQSalt(): Promise<PQSalt>;
/**
 * Derive a quantum-resistant storage key from user PIN using PQ algorithms
 * Uses Argon2 for key stretching and SHAKE-256 for quantum-resistant hashing
 */
export declare function deriveStorageKey(userPIN: string, salt?: PQSalt, iterations?: number): Promise<PQStorageKey>;
/**
 * Stretch a key using quantum-resistant algorithms
 * Provides additional security against quantum attacks
 */
export declare function stretchKey(material: Uint8Array): Promise<PQStretchedKey>;
/**
 * Verify a storage key against a user PIN
 * Supports migration from old iteration counts
 */
export declare function verifyStorageKey(storageKey: PQStorageKey, userPIN: string): Promise<boolean>;
/**
 * Rotate a storage key with quantum-resistant migration
 */
export declare function rotateStorageKey(oldKey: PQStorageKey, newPIN: string): Promise<{
    oldKey: PQStorageKey;
    newKey: PQStorageKey;
    migrationProof: Uint8Array;
}>;
//# sourceMappingURL=pq-key-derivation.d.ts.map