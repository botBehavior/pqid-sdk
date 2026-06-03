import { bytesToBase64, base64ToBytes, utf8ToBytes } from "./base64.js";
import * as ed25519 from "./ed25519.js";
import * as dilithium from "./dilithium.js";
// Algorithm abstraction layer
export async function generateKeyPair(algorithm = "DilithiumSignature2025") {
    switch (algorithm) {
        case "DilithiumSignature2025":
            const pqKeys = await dilithium.generateDilithiumKeyPair();
            return {
                algorithm,
                publicKey: pqKeys.publicKey,
                privateKey: pqKeys.privateKey,
                publicKeyBase64: pqKeys.publicKeyBase64,
                privateKeyBase64: pqKeys.privateKeyBase64
            };
        case "Ed25519Signature2020":
        default:
            const edKeys = await ed25519.generateEd25519KeyPair();
            return {
                publicKey: edKeys.publicKey,
                privateKey: edKeys.privateKey,
                publicKeyBase64: edKeys.publicKeyBase64,
                privateKeyBase64: edKeys.privateKeyPkcs8Base64,
                algorithm
            };
    }
}
export async function sign(key, message) {
    switch (key.algorithm) {
        case "DilithiumSignature2025":
            if (key.privateKey instanceof Uint8Array) {
                // Pass Uint8Array directly to dilithium signing
                const dsa = await dilithium.loadMLDSAInterface();
                const messageBytes = utf8ToBytes(message);
                const signature = await dsa.sign(messageBytes, key.privateKey);
                return bytesToBase64(signature);
            }
            else if (typeof key.privateKey === 'string') {
                return dilithium.signDilithium(key.privateKey, message);
            }
            throw new Error("Dilithium private key must be Uint8Array or base64 string");
        case "Ed25519Signature2020":
        default:
            if (key.privateKey instanceof CryptoKey) {
                return ed25519.signEd25519WithKey(key.privateKey, message);
            }
            throw new Error("Ed25519 private key must be CryptoKey");
    }
}
export async function verify(key, message, signature) {
    switch (key.algorithm) {
        case "DilithiumSignature2025":
            if (key.publicKey instanceof Uint8Array) {
                // Pass Uint8Array directly to dilithium verification
                const dsa = await dilithium.loadMLDSAInterface();
                const messageBytes = utf8ToBytes(message);
                const signatureBytes = base64ToBytes(signature);
                return await dsa.verify(signatureBytes, messageBytes, key.publicKey);
            }
            else {
                const pubKeyStr = typeof key.publicKey === 'string' ? key.publicKey :
                    key.publicKey instanceof Uint8Array ? bytesToBase64(key.publicKey) :
                        bytesToBase64(new Uint8Array()); // Should not happen for Dilithium
                return dilithium.verifyDilithium(pubKeyStr, message, signature);
            }
        case "Ed25519Signature2020":
        default:
            const pubKeyStrEd = typeof key.publicKey === 'string' ? key.publicKey : bytesToBase64(key.publicKey);
            return ed25519.verifyEd25519(pubKeyStrEd, message, signature);
    }
}
// Local at-rest key derivation (PBKDF2-HMAC-SHA256). This is a CLASSICAL primitive
// used to derive a storage-encryption key from a user PIN. It is NOT quantum-resistant
// and is unrelated to the ML-DSA signing core.
export { generateSalt, deriveStorageKey, verifyStorageKey, rotateStorageKey } from "./pq-key-derivation.js";
// Local at-rest encryption (AES-256-GCM). CLASSICAL authenticated encryption,
// NOT quantum-resistant. AES-256 retains a meaningful security margin against
// known quantum attacks (Grover), but is not a post-quantum scheme.
export { encrypt, decrypt, encryptPrivateKeys, decryptPrivateKeys, encryptCredentials, decryptCredentials } from "./pq-encryption.js";
// PQ Dilithium Crypto (the real post-quantum signing core: FIPS 204 ML-DSA-65)
export { generateDilithiumKeyPair, signDilithium, verifyDilithium } from "./dilithium.js";
// Re-export base64 utilities for wallet use
export { bytesToBase64Url } from "./base64.js";
// Low-level primitive accessors (noble-based ML-DSA, ML-KEM, AES-GCM, PBKDF2)
export { cryptoApi, ensureCryptoReady, isCryptoReady } from "./wasm-manager.js";
