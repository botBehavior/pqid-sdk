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
// PQ Key Derivation
export { generatePQSalt, deriveStorageKey, stretchKey, verifyStorageKey, rotateStorageKey } from "./pq-key-derivation.js";
// PQ Encryption Layer
export { pqEncrypt, pqDecrypt, encryptPrivateKeys, decryptPrivateKeys, encryptCredentials, decryptCredentials } from "./pq-encryption.js";
// PQ Dilithium Crypto
export { generateDilithiumKeyPair, signDilithium, verifyDilithium } from "./dilithium.js";
// PQ Secure Storage
export { PQSecureStorage } from "./pq-secure-storage.js";
// PQ Session Security
export { createAuthSession, performPQKeyExchange, signAuthResponse, verifyAuthResponse, createTemporalProof, verifyTemporalProof, createSessionAttestation, verifySessionAttestation, isSessionValid, generatePQNonce, createPQChallenge } from "./pq-session-security.js";
// PQ Auth Bundle
export { createPQAuthBundle, verifyPQAuthBundle, extractClaimsFromBundle, getBundleSecurityMetadata } from "./pq-auth-bundle.js";
// PQ Selective Disclosure
export { generateCredentialProof, verifyCredentialProof, generateZKCredentialProof, verifyZKCredentialProof, composeDisclosureBundle, verifyDisclosureBundle, extractClaimsFromBundle as extractClaimsFromDisclosureBundle, determineDisclosureLevel } from "./pq-selective-disclosure.js";
// Re-export base64 utilities for wallet use
export { bytesToBase64Url } from "./base64.js";
// WASM manager for consistent initialization
export { wasmApi, ensureWasmReady, isWasmReady } from "./wasm-manager.js";
