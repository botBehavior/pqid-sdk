import { bytesToBase64Url } from "./base64.js";
import { cryptoApi } from "./wasm-manager.js";
// Local at-rest key derivation.
//
// HONESTY NOTE: This module derives a storage-encryption key from a user PIN using
// PBKDF2-HMAC-SHA256. PBKDF2 is a CLASSICAL key-derivation function. It is NOT
// "quantum-resistant" and has nothing to do with the post-quantum ML-DSA signing core.
// It exists only to protect locally-stored secrets at rest behind a user PIN.
// OWASP-recommended floor for PBKDF2-HMAC-SHA256 (2023+). Raised from the previous
// insecure default of 10,000.
export const DEFAULT_PBKDF2_ITERATIONS = 600000;
/**
 * Generate a random 256-bit salt for key derivation.
 */
export async function generateSalt() {
    const salt = new Uint8Array(32);
    crypto.getRandomValues(salt);
    return {
        salt,
        timestamp: Date.now(),
        algorithm: "PBKDF2-HMAC-SHA256"
    };
}
/**
 * Derive a storage-encryption key from a user PIN using PBKDF2-HMAC-SHA256.
 * Classical KDF — not quantum-resistant.
 */
export async function deriveStorageKey(userPIN, salt, iterations = DEFAULT_PBKDF2_ITERATIONS) {
    const derivationSalt = salt || (await generateSalt());
    const pinBytes = new TextEncoder().encode(userPIN);
    const key = await cryptoApi.derive_key(pinBytes, derivationSalt.salt, iterations);
    return {
        key,
        salt: derivationSalt,
        keyId: bytesToBase64Url(key.slice(0, 16)), // First 16 bytes as key identifier
        iterations,
        algorithm: "PBKDF2-HMAC-SHA256"
    };
}
/**
 * Verify a user PIN against a previously-derived storage key by re-deriving with the
 * stored salt and iteration count and comparing in constant time.
 */
export async function verifyStorageKey(storageKey, userPIN) {
    var _a;
    try {
        const rederived = await deriveStorageKey(userPIN, storageKey.salt, (_a = storageKey.iterations) !== null && _a !== void 0 ? _a : DEFAULT_PBKDF2_ITERATIONS);
        return constantTimeEquals(storageKey.key, rederived.key);
    }
    catch (error) {
        console.error("Storage key verification failed:", error);
        return false;
    }
}
/**
 * Constant-time comparison to prevent timing attacks.
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
 * Rotate a storage key by deriving a fresh key from a new PIN. Returns both keys so the
 * caller can re-encrypt stored data with the new key.
 */
export async function rotateStorageKey(oldKey, newPIN) {
    const newKey = await deriveStorageKey(newPIN);
    return { oldKey, newKey };
}
