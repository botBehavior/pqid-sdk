import { cryptoApi } from "./wasm-manager.js";
const AES_GCM_IV_LENGTH = 12; // 96-bit nonce per NIST SP 800-38D
function generateIV() {
    const iv = new Uint8Array(AES_GCM_IV_LENGTH);
    crypto.getRandomValues(iv);
    return iv;
}
/**
 * Encrypt data using AES-256-GCM with a PIN-derived storage key.
 * Classical authenticated encryption — not quantum-resistant.
 */
export async function encrypt(data, key) {
    const iv = generateIV();
    const ciphertextWithIv = await cryptoApi.aes_gcm_encrypt(data, key.key, iv);
    return {
        ciphertext: new Uint8Array(ciphertextWithIv.slice(iv.length)), // Remove IV prefix
        iv,
        algorithm: "AES-256-GCM",
        keyId: key.keyId,
        timestamp: Date.now()
    };
}
/**
 * Decrypt data encrypted with {@link encrypt}. The GCM authentication tag is verified
 * during decryption; a tampered ciphertext throws and is reported as not verified.
 */
export async function decrypt(encrypted, key) {
    try {
        if (encrypted.keyId !== key.keyId) {
            throw new Error("Key ID mismatch");
        }
        const ciphertextWithIv = new Uint8Array(encrypted.ciphertext.length + encrypted.iv.length);
        ciphertextWithIv.set(encrypted.iv);
        ciphertextWithIv.set(encrypted.ciphertext, encrypted.iv.length);
        // AES-GCM decryption fails (throws) if the auth tag does not validate.
        const decryptedData = await cryptoApi.aes_gcm_decrypt(ciphertextWithIv, key.key);
        return {
            data: decryptedData,
            verified: true,
            timestamp: encrypted.timestamp
        };
    }
    catch (error) {
        console.error("Decryption failed:", error);
        return {
            data: new Uint8Array(0),
            verified: false,
            timestamp: encrypted.timestamp
        };
    }
}
/**
 * Encrypt multiple private keys at rest.
 */
export async function encryptPrivateKeys(keys, storageKey) {
    const encryptedKeys = [];
    for (const keyPair of keys) {
        const keyData = {
            id: keyPair.id,
            algorithm: "DilithiumSignature2025",
            key: Array.from(keyPair.key)
        };
        const dataBytes = new TextEncoder().encode(JSON.stringify(keyData));
        encryptedKeys.push(await encrypt(dataBytes, storageKey));
    }
    return {
        encryptedKeys,
        keyCount: keys.length,
        algorithm: "AES-256-GCM"
    };
}
/**
 * Decrypt private keys encrypted with {@link encryptPrivateKeys}.
 */
export async function decryptPrivateKeys(encryptedKeys, storageKey) {
    const decryptedKeys = [];
    for (const encrypted of encryptedKeys.encryptedKeys) {
        const decrypted = await decrypt(encrypted, storageKey);
        if (decrypted.verified && decrypted.data.length > 0) {
            try {
                const keyData = JSON.parse(new TextDecoder().decode(decrypted.data));
                decryptedKeys.push({ id: keyData.id, key: new Uint8Array(keyData.key), verified: true });
            }
            catch (error) {
                console.error("Failed to parse decrypted key data:", error);
                decryptedKeys.push({ id: "unknown", key: new Uint8Array(0), verified: false });
            }
        }
        else {
            decryptedKeys.push({ id: "unknown", key: new Uint8Array(0), verified: false });
        }
    }
    return decryptedKeys;
}
/**
 * Encrypt credentials at rest.
 */
export async function encryptCredentials(credentials, storageKey) {
    const encryptedCredentials = [];
    for (const credential of credentials) {
        const dataBytes = new TextEncoder().encode(JSON.stringify(credential));
        encryptedCredentials.push(await encrypt(dataBytes, storageKey));
    }
    return {
        encryptedCredentials,
        credentialCount: credentials.length,
        algorithm: "AES-256-GCM"
    };
}
/**
 * Decrypt credentials encrypted with {@link encryptCredentials}.
 */
export async function decryptCredentials(encryptedCredentials, storageKey) {
    const decryptedCredentials = [];
    for (const encrypted of encryptedCredentials.encryptedCredentials) {
        const decrypted = await decrypt(encrypted, storageKey);
        if (decrypted.verified && decrypted.data.length > 0) {
            try {
                const credentialData = JSON.parse(new TextDecoder().decode(decrypted.data));
                decryptedCredentials.push({ id: credentialData.id, data: credentialData.data, verified: true });
            }
            catch (error) {
                console.error("Failed to parse decrypted credential data:", error);
                decryptedCredentials.push({ id: "unknown", data: null, verified: false });
            }
        }
        else {
            decryptedCredentials.push({ id: "unknown", data: null, verified: false });
        }
    }
    return decryptedCredentials;
}
