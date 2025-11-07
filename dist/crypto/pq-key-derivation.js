import { bytesToBase64Url } from "./base64.js";
import { wasmApi } from "./wasm-manager.js";
/**
 * Generate a quantum-resistant salt for key derivation
 */
export async function generatePQSalt() {
    // Use quantum-resistant random generation
    const salt = new Uint8Array(32);
    crypto.getRandomValues(salt);
    return {
        salt,
        timestamp: Date.now(),
        algorithm: 'PQ-Salt-v1'
    };
}
/**
 * Derive a quantum-resistant storage key from user PIN using PQ algorithms
 * Uses Argon2 for key stretching and SHAKE-256 for quantum-resistant hashing
 */
export async function deriveStorageKey(userPIN, salt, iterations = 10000) {
    console.log('[SDK] deriveStorageKey called with PIN length:', userPIN.length, 'existing salt:', !!salt, 'iterations:', iterations);
    try {
        const pqSalt = salt || await generatePQSalt();
        console.log('[SDK] Salt prepared, salt length:', pqSalt.salt.length);
        // Convert PIN to bytes
        const pinBytes = new TextEncoder().encode(userPIN);
        console.log('[SDK] PIN converted to bytes, length:', pinBytes.length);
        // Use WASM-based PQ key derivation with configurable iterations
        console.log('[SDK] Calling wasmApi.derive_pq_key with', iterations, 'iterations...');
        const key = await wasmApi.derive_pq_key(pinBytes, pqSalt.salt, iterations);
        console.log('[SDK] WASM derive_pq_key completed, key length:', key.length);
        const result = {
            key,
            salt: pqSalt,
            keyId: bytesToBase64Url(key.slice(0, 16)), // First 16 bytes as key identifier
            algorithm: 'PQ-KDF-v1'
        };
        console.log('[SDK] deriveStorageKey completed successfully');
        return result;
    }
    catch (error) {
        console.error('[SDK] deriveStorageKey failed:', error);
        console.error('[SDK] Error details:', {
            message: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined,
            type: typeof error
        });
        throw error;
    }
}
/**
 * Stretch a key using quantum-resistant algorithms
 * Provides additional security against quantum attacks
 */
export async function stretchKey(material) {
    // Use multiple rounds of SHA-256 for quantum resistance
    const rounds = 10000;
    let stretched = material;
    for (let i = 0; i < rounds; i++) {
        const hashBuffer = await crypto.subtle.digest('SHA-256', stretched);
        stretched = new Uint8Array(hashBuffer);
    }
    return {
        key: stretched,
        rounds,
        algorithm: 'PQ-Stretch-v1'
    };
}
/**
 * Verify a storage key against a user PIN
 * Supports migration from old iteration counts
 */
export async function verifyStorageKey(storageKey, userPIN) {
    try {
        // First try with current iterations (10,000)
        try {
            const rederived = await deriveStorageKey(userPIN, storageKey.salt, 10000);
            if (constantTimeEquals(storageKey.key, rederived.key)) {
                return true;
            }
        }
        catch (error) {
            console.log('[SDK] Current iterations verification failed, trying legacy...');
        }
        // If current iterations fail, try legacy iterations (100,000) for migration
        try {
            const rederived = await deriveStorageKey(userPIN, storageKey.salt, 100000);
            if (constantTimeEquals(storageKey.key, rederived.key)) {
                console.log('[SDK] Legacy key verification successful - migration needed');
                return true;
            }
        }
        catch (error) {
            console.log('[SDK] Legacy iterations verification also failed');
        }
        return false;
    }
    catch (error) {
        console.error('Storage key verification failed:', error);
        return false;
    }
}
/**
 * Constant-time comparison to prevent timing attacks
 */
function constantTimeEquals(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];
    }
    return result === 0;
}
/**
 * Rotate a storage key with quantum-resistant migration
 */
export async function rotateStorageKey(oldKey, newPIN) {
    // Generate new key
    const newKey = await deriveStorageKey(newPIN);
    // Create migration proof (hash of old + new key)
    const migrationData = new Uint8Array(oldKey.key.length + newKey.key.length);
    migrationData.set(oldKey.key);
    migrationData.set(newKey.key, oldKey.key.length);
    const migrationProof = new Uint8Array(await crypto.subtle.digest('SHA-256', migrationData));
    return {
        oldKey,
        newKey,
        migrationProof
    };
}
