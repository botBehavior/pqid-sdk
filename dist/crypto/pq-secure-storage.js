import { pqEncrypt, pqDecrypt } from "./pq-encryption.js";
// PQ Secure Storage Abstraction
// Provides quantum-resistant storage replacing vulnerable Chrome localStorage
// Helper function to convert serializable data back to PQEncryptedData
function deserializeEncryptedData(serializable) {
    return {
        ciphertext: new Uint8Array(atob(serializable.ciphertext).split('').map(c => c.charCodeAt(0))),
        iv: new Uint8Array(atob(serializable.iv).split('').map(c => c.charCodeAt(0))),
        salt: new Uint8Array(atob(serializable.salt).split('').map(c => c.charCodeAt(0))),
        algorithm: serializable.algorithm,
        keyId: serializable.keyId,
        integrityHash: new Uint8Array(atob(serializable.integrityHash).split('').map(c => c.charCodeAt(0))),
        timestamp: serializable.timestamp
    };
}
/**
 * Quantum-resistant secure storage abstraction
 * Replaces vulnerable Chrome localStorage with encrypted, integrity-protected storage
 */
export class PQSecureStorage {
    constructor(storageKey, options = {}) {
        this.cache = new Map();
        this.storageKey = storageKey;
        this.options = {
            namespace: options.namespace || 'pqid',
            compression: options.compression || false,
            integrity: options.integrity !== false // Default to true
        };
    }
    /**
     * Securely store data with quantum-resistant encryption
     */
    async secureStore(key, data) {
        const fullKey = this.getFullKey(key);
        const timestamp = Date.now();
        // Encrypt the data
        const encryptedData = await pqEncrypt(data, this.storageKey);
        // Create checksum for additional integrity
        const checksumInput = new Uint8Array(data.length + 8);
        checksumInput.set(data);
        new DataView(checksumInput.buffer).setBigUint64(data.length, BigInt(timestamp), true);
        const checksumBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', checksumInput));
        // Convert checksum to base64 for JSON serialization
        const checksumB64 = btoa(String.fromCharCode(...checksumBytes));
        // Convert encrypted data to serializable format
        const serializableData = {
            ciphertext: btoa(String.fromCharCode(...encryptedData.ciphertext)),
            iv: btoa(String.fromCharCode(...encryptedData.iv)),
            salt: btoa(String.fromCharCode(...encryptedData.salt)),
            algorithm: encryptedData.algorithm,
            keyId: encryptedData.keyId,
            integrityHash: btoa(String.fromCharCode(...encryptedData.integrityHash)),
            timestamp: encryptedData.timestamp
        };
        // Create stored item
        const storedItem = {
            key: fullKey,
            data: serializableData,
            metadata: {
                created: timestamp,
                modified: timestamp,
                version: 'PQ-Storage-v1',
                checksum: checksumB64
            }
        };
        // Get signature and convert to base64 for storage
        const signature = await this.signStorageItem(storedItem);
        const signatureB64 = btoa(String.fromCharCode(...signature));
        // Store in Chrome localStorage (encrypted)
        const storageData = {
            item: storedItem,
            signature: signatureB64
        };
        // Update cache
        this.cache.set(fullKey, storedItem);
        // Persist to storage
        await this.persistToStorage(fullKey, storageData);
    }
    /**
     * Retrieve and verify data from secure storage
     */
    async secureRetrieve(key) {
        const fullKey = this.getFullKey(key);
        // Check cache first
        const cached = this.cache.get(fullKey);
        if (cached) {
            return this.decryptAndVerify(cached);
        }
        // Load from storage
        const rawStorageData = await this.loadFromStorage(fullKey);
        if (!rawStorageData) {
            return null;
        }
        // The rawStorageData has signature as string, convert to proper format
        const storageData = typeof rawStorageData.signature === 'string'
            ? this.deserializeStorageData(rawStorageData)
            : rawStorageData;
        // Verify storage signature
        const signatureValid = await this.verifyStorageSignature(storageData.item, storageData.signature);
        if (!signatureValid) {
            console.error('Storage signature verification failed for key:', key);
            return null;
        }
        // Cache the item
        this.cache.set(fullKey, storageData.item);
        return this.decryptAndVerify(storageData.item);
    }
    /**
     * Check data integrity without decrypting
     */
    async verifyDataIntegrity(key) {
        const fullKey = this.getFullKey(key);
        const storageData = await this.loadFromStorage(fullKey);
        if (!storageData) {
            return false;
        }
        // Verify storage signature
        const signatureValid = await this.verifyStorageSignature(storageData.item, storageData.signature);
        if (!signatureValid) {
            return false;
        }
        // Deserialize and decrypt data
        const encryptedData = deserializeEncryptedData(storageData.item.data);
        const decrypted = await pqDecrypt(encryptedData, this.storageKey);
        return decrypted.verified;
    }
    /**
     * Secure deletion with quantum-resistant wiping
     */
    async secureDelete(key) {
        const fullKey = this.getFullKey(key);
        // Remove from cache
        this.cache.delete(fullKey);
        // Secure wipe from storage
        try {
            // Overwrite with random data before deletion (quantum-resistant wiping)
            const randomData = new Uint8Array(1024);
            crypto.getRandomValues(randomData);
            await this.persistToStorage(fullKey, randomData);
            // Delete the key using platform-specific storage
            return await this.removeFromStorage(fullKey);
        }
        catch (error) {
            console.error('Secure deletion failed:', error);
            return false;
        }
    }
    /**
     * Get storage statistics
     */
    async getStorageStats() {
        const allKeys = await this.getAllKeys();
        let totalSize = 0;
        let encryptedItems = 0;
        let lastModified = 0;
        for (const key of allKeys) {
            const item = await this.loadFromStorage(key);
            if (item) {
                const size = JSON.stringify(item).length;
                totalSize += size;
                encryptedItems++;
                lastModified = Math.max(lastModified, item.item.metadata.modified);
            }
        }
        return {
            totalItems: allKeys.length,
            totalSize,
            encryptedItems,
            lastModified
        };
    }
    /**
     * Update storage key (for key rotation)
     */
    async updateStorageKey(newKey) {
        // Re-encrypt all cached items with new key
        const reencryptedItems = [];
        for (const [key, item] of this.cache.entries()) {
            // Decrypt with old key
            const encryptedData = deserializeEncryptedData(item.data);
            const decrypted = await pqDecrypt(encryptedData, this.storageKey);
            if (decrypted.verified) {
                // Re-encrypt with new key
                const reencrypted = await pqEncrypt(decrypted.data, newKey);
                // Convert to serializable format
                const serializableReencrypted = {
                    ciphertext: btoa(String.fromCharCode(...reencrypted.ciphertext)),
                    iv: btoa(String.fromCharCode(...reencrypted.iv)),
                    salt: btoa(String.fromCharCode(...reencrypted.salt)),
                    algorithm: reencrypted.algorithm,
                    keyId: reencrypted.keyId,
                    integrityHash: btoa(String.fromCharCode(...reencrypted.integrityHash)),
                    timestamp: reencrypted.timestamp
                };
                // Update item
                const updatedItem = {
                    ...item,
                    data: serializableReencrypted,
                    metadata: {
                        ...item.metadata,
                        modified: Date.now()
                    }
                };
                const reencryptedSignature = await this.signStorageItem(updatedItem);
                const reencryptedSignatureB64 = btoa(String.fromCharCode(...reencryptedSignature));
                reencryptedItems.push({
                    key,
                    data: {
                        item: updatedItem,
                        signature: reencryptedSignatureB64
                    }
                });
            }
        }
        // Persist all re-encrypted items
        for (const { key, data } of reencryptedItems) {
            await this.persistToStorage(key, data);
        }
        // Update storage key
        this.storageKey = newKey;
        // Clear cache (will be reloaded on next access)
        this.cache.clear();
    }
    // Private helper methods
    getFullKey(key) {
        return `${this.options.namespace}:${key}`;
    }
    async decryptAndVerify(item) {
        // Convert serializable data back to PQEncryptedData
        const encryptedData = deserializeEncryptedData(item.data);
        const decrypted = await pqDecrypt(encryptedData, this.storageKey);
        // Additional integrity check using stored checksum
        if (this.options.integrity && decrypted.verified) {
            // Reconstruct original checksum input
            const checksumInput = new Uint8Array(decrypted.data.length + 8);
            checksumInput.set(decrypted.data);
            new DataView(checksumInput.buffer).setBigUint64(decrypted.data.length, BigInt(item.metadata.created), true);
            const computedChecksum = new Uint8Array(await crypto.subtle.digest('SHA-256', checksumInput));
            // Convert stored checksum from base64 back to Uint8Array for comparison
            const storedChecksumBytes = new Uint8Array(atob(item.metadata.checksum).split('').map(c => c.charCodeAt(0)));
            const checksumValid = constantTimeEquals(computedChecksum, storedChecksumBytes);
            return {
                data: decrypted.data,
                verified: checksumValid
            };
        }
        return {
            data: decrypted.data,
            verified: decrypted.verified
        };
    }
    async signStorageItem(item) {
        // Create a signature of the item metadata and encrypted data
        const signatureInput = new TextEncoder().encode(JSON.stringify({
            key: item.key,
            metadata: item.metadata,
            dataLength: item.data.ciphertext.length
        }));
        const signature = new Uint8Array(await crypto.subtle.digest('SHA-256', signatureInput));
        return signature;
    }
    async verifyStorageSignature(item, signature) {
        const computedSignature = await this.signStorageItem(item);
        return constantTimeEquals(computedSignature, signature);
    }
    // Storage operations - to be implemented by platform-specific adapters
    async persistToStorage(key, data) {
        throw new Error('persistToStorage must be implemented by platform adapter');
    }
    async loadFromStorage(key) {
        throw new Error('loadFromStorage must be implemented by platform adapter');
    }
    // Helper method to convert loaded storage data
    deserializeStorageData(data) {
        return {
            item: data.item,
            signature: new Uint8Array(atob(data.signature).split('').map(c => c.charCodeAt(0)))
        };
    }
    async getAllKeys() {
        throw new Error('getAllKeys must be implemented by platform adapter');
    }
    async removeFromStorage(key) {
        throw new Error('removeFromStorage must be implemented by platform adapter');
    }
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
