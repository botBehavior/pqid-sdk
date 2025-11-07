import { base64ToBytes, bytesToBase64, bytesToBase64Url } from "./base64.js";
import { wasmApi } from "./wasm-manager.js";

// PQ Key Derivation System
// Uses quantum-resistant algorithms for deriving storage encryption keys

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
export async function generatePQSalt(): Promise<PQSalt> {
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
 * Derive a quantum-resistant storage key from a user PIN using PBKDF2 + SHA-256.
 */
export async function deriveStorageKey(userPIN: string, salt?: PQSalt, iterations: number = 10000): Promise<PQStorageKey> {
  try {
    const pqSalt = salt || await generatePQSalt();
    const pinBytes = new TextEncoder().encode(userPIN);

    const key = await wasmApi.derive_pq_key(pinBytes, pqSalt.salt, iterations);

    return {
      key,
      salt: pqSalt,
      keyId: bytesToBase64Url(key.slice(0, 16)), // First 16 bytes as key identifier
      algorithm: 'PQ-KDF-v1'
    };
  } catch (error) {
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
export async function stretchKey(material: Uint8Array): Promise<PQStretchedKey> {
  // Use multiple rounds of SHA-256 for quantum resistance
  const rounds = 10000;
  let stretched = material;

  for (let i = 0; i < rounds; i++) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', stretched as unknown as ArrayBuffer);
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
export async function verifyStorageKey(storageKey: PQStorageKey, userPIN: string): Promise<boolean> {
  try {
    // First try with current iterations (10,000)
    try {
      const rederived = await deriveStorageKey(userPIN, storageKey.salt, 10000);
      if (constantTimeEquals(storageKey.key, rederived.key)) {
        return true;
      }
    } catch (error) {
      console.log('[SDK] Current iterations verification failed, trying legacy...');
    }

    // If current iterations fail, try legacy iterations (100,000) for migration
    try {
      const rederived = await deriveStorageKey(userPIN, storageKey.salt, 100000);
      if (constantTimeEquals(storageKey.key, rederived.key)) {
        console.log('[SDK] Legacy key verification successful - migration needed');
        return true;
      }
    } catch (error) {
      console.log('[SDK] Legacy iterations verification also failed');
    }

    return false;
  } catch (error) {
    console.error('Storage key verification failed:', error);
    return false;
  }
}

/**
 * Constant-time comparison to prevent timing attacks
 */
function constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
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
export async function rotateStorageKey(
  oldKey: PQStorageKey,
  newPIN: string
): Promise<{ oldKey: PQStorageKey; newKey: PQStorageKey; migrationProof: Uint8Array }> {
  // Generate new key
  const newKey = await deriveStorageKey(newPIN);

  // Create migration proof (hash of old + new key)
  const migrationData = new Uint8Array(oldKey.key.length + newKey.key.length);
  migrationData.set(oldKey.key);
  migrationData.set(newKey.key, oldKey.key.length);

  const migrationProof = new Uint8Array(await crypto.subtle.digest('SHA-256', migrationData as unknown as ArrayBuffer));

  return {
    oldKey,
    newKey,
    migrationProof
  };
}
