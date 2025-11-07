import { wasmApi } from "./wasm-manager.js";
const PQ_AES_GCM_IV_LENGTH = 12; // 96-bit nonce per NIST recommendations
/**
 * Generate a quantum-resistant initialization vector
 */
async function generatePQIV() {
    const iv = new Uint8Array(PQ_AES_GCM_IV_LENGTH);
    crypto.getRandomValues(iv);
    return iv;
}
/**
 * Encrypt data using quantum-resistant AES-GCM with PQ-derived key
 */
export async function pqEncrypt(data, key) {
    const iv = await generatePQIV();
    // Use WASM-based PQ encryption (with automatic initialization)
    const ciphertextWithIv = await wasmApi.pq_encrypt(data, key.key, iv);
    // Create integrity hash (data + key salt for quantum resistance)
    const integrityInput = new Uint8Array(data.length + key.salt.salt.length);
    integrityInput.set(data);
    integrityInput.set(key.salt.salt, data.length);
    const integrityHash = new Uint8Array(await crypto.subtle.digest('SHA-256', integrityInput));
    return {
        ciphertext: new Uint8Array(ciphertextWithIv.slice(iv.length)), // Remove IV prefix
        iv,
        salt: key.salt.salt,
        algorithm: 'PQ-AES-GCM-v1',
        keyId: key.keyId,
        integrityHash,
        timestamp: Date.now()
    };
}
/**
 * Decrypt data with quantum-resistant integrity verification
 */
export async function pqDecrypt(encrypted, key) {
    try {
        // Verify key matches
        if (encrypted.keyId !== key.keyId) {
            throw new Error('Key ID mismatch');
        }
        // Use WASM-based PQ decryption
        // Reconstruct ciphertext with IV prefix as expected by WASM function
        const ciphertextWithIv = new Uint8Array(encrypted.ciphertext.length + encrypted.iv.length);
        ciphertextWithIv.set(encrypted.iv);
        ciphertextWithIv.set(encrypted.ciphertext, encrypted.iv.length);
        const decryptedData = await wasmApi.pq_decrypt(ciphertextWithIv, key.key);
        // Verify integrity (reconstruct original integrity input)
        const integrityInput = new Uint8Array(decryptedData.length + encrypted.salt.length);
        integrityInput.set(decryptedData);
        integrityInput.set(encrypted.salt, decryptedData.length);
        const computedHash = new Uint8Array(await crypto.subtle.digest('SHA-256', integrityInput));
        // Constant-time comparison for integrity verification
        const integrityVerified = constantTimeEquals(computedHash, encrypted.integrityHash);
        return {
            data: decryptedData,
            verified: integrityVerified,
            timestamp: encrypted.timestamp
        };
    }
    catch (error) {
        console.error('PQ decryption failed:', error);
        return {
            data: new Uint8Array(0),
            verified: false,
            timestamp: encrypted.timestamp
        };
    }
}
/**
 * Encrypt multiple private keys with quantum-resistant protection
 */
export async function encryptPrivateKeys(keys, storageKey) {
    const encryptedKeys = [];
    for (const keyPair of keys) {
        // Create key data structure
        const keyData = {
            id: keyPair.id,
            algorithm: 'DilithiumSignature2025',
            key: Array.from(keyPair.key)
        };
        const jsonData = JSON.stringify(keyData);
        const dataBytes = new TextEncoder().encode(jsonData);
        const encrypted = await pqEncrypt(dataBytes, storageKey);
        encryptedKeys.push(encrypted);
    }
    return {
        encryptedKeys,
        keyCount: keys.length,
        algorithm: 'PQ-Key-Encryption-v1'
    };
}
/**
 * Decrypt private keys with integrity verification
 */
export async function decryptPrivateKeys(encryptedKeys, storageKey) {
    const decryptedKeys = [];
    for (const encrypted of encryptedKeys.encryptedKeys) {
        const decrypted = await pqDecrypt(encrypted, storageKey);
        if (decrypted.verified && decrypted.data.length > 0) {
            try {
                const jsonStr = new TextDecoder().decode(decrypted.data);
                const keyData = JSON.parse(jsonStr);
                decryptedKeys.push({
                    id: keyData.id,
                    key: new Uint8Array(keyData.key),
                    verified: true
                });
            }
            catch (error) {
                console.error('Failed to parse decrypted key data:', error);
                decryptedKeys.push({
                    id: 'unknown',
                    key: new Uint8Array(0),
                    verified: false
                });
            }
        }
        else {
            decryptedKeys.push({
                id: 'unknown',
                key: new Uint8Array(0),
                verified: false
            });
        }
    }
    return decryptedKeys;
}
/**
 * Encrypt credentials with quantum-resistant protection
 */
export async function encryptCredentials(credentials, storageKey) {
    const encryptedCredentials = [];
    for (const credential of credentials) {
        const jsonData = JSON.stringify(credential);
        const dataBytes = new TextEncoder().encode(jsonData);
        const encrypted = await pqEncrypt(dataBytes, storageKey);
        encryptedCredentials.push(encrypted);
    }
    return {
        encryptedCredentials,
        credentialCount: credentials.length,
        algorithm: 'PQ-Credential-Encryption-v1'
    };
}
/**
 * Decrypt credentials with integrity verification
 */
export async function decryptCredentials(encryptedCredentials, storageKey) {
    const decryptedCredentials = [];
    for (const encrypted of encryptedCredentials.encryptedCredentials) {
        const decrypted = await pqDecrypt(encrypted, storageKey);
        if (decrypted.verified && decrypted.data.length > 0) {
            try {
                const jsonStr = new TextDecoder().decode(decrypted.data);
                const credentialData = JSON.parse(jsonStr);
                decryptedCredentials.push({
                    id: credentialData.id,
                    data: credentialData.data,
                    verified: true
                });
            }
            catch (error) {
                console.error('Failed to parse decrypted credential data:', error);
                decryptedCredentials.push({
                    id: 'unknown',
                    data: null,
                    verified: false
                });
            }
        }
        else {
            decryptedCredentials.push({
                id: 'unknown',
                data: null,
                verified: false
            });
        }
    }
    return decryptedCredentials;
}
/**
 * Constant-time comparison for cryptographic operations
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
