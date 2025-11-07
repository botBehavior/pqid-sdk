import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
let nobleReady = false;
export async function ensureWasmReady() {
    if (nobleReady) {
        return;
    }
    if (typeof crypto === "undefined" || !crypto.subtle) {
        throw new Error("Web Crypto API unavailable in this environment");
    }
    nobleReady = true;
    console.log("[CRYPTO] Noble post-quantum primitives ready");
}
export function isWasmReady() {
    return nobleReady;
}
function concatBytes(a, b) {
    const combined = new Uint8Array(a.length + b.length);
    combined.set(a, 0);
    combined.set(b, a.length);
    return combined;
}
function copyBuffer(data) {
    const copy = new Uint8Array(data.length);
    copy.set(data);
    return copy.buffer;
}
export const wasmApi = {
    async derive_pq_key(password, salt, iterations) {
        await ensureWasmReady();
        const keyMaterial = await crypto.subtle.importKey("raw", copyBuffer(password), { name: "PBKDF2" }, false, [
            "deriveBits"
        ]);
        const derivedBits = await crypto.subtle.deriveBits({
            name: "PBKDF2",
            salt: copyBuffer(salt),
            iterations,
            hash: "SHA-256"
        }, keyMaterial, 256);
        return new Uint8Array(derivedBits);
    },
    async pq_encrypt(plaintext, key, nonce) {
        await ensureWasmReady();
        const cryptoKey = await crypto.subtle.importKey("raw", copyBuffer(key), { name: "AES-GCM" }, false, [
            "encrypt"
        ]);
        const ciphertext = await crypto.subtle.encrypt({
            name: "AES-GCM",
            iv: copyBuffer(nonce)
        }, cryptoKey, copyBuffer(plaintext));
        const result = new Uint8Array(nonce.length + ciphertext.byteLength);
        result.set(nonce, 0);
        result.set(new Uint8Array(ciphertext), nonce.length);
        return result;
    },
    async pq_decrypt(ciphertext, key) {
        await ensureWasmReady();
        const nonce = ciphertext.slice(0, 12);
        const encryptedData = ciphertext.slice(12);
        const cryptoKey = await crypto.subtle.importKey("raw", copyBuffer(key), { name: "AES-GCM" }, false, [
            "decrypt"
        ]);
        const plaintext = await crypto.subtle.decrypt({
            name: "AES-GCM",
            iv: copyBuffer(nonce)
        }, cryptoKey, copyBuffer(encryptedData));
        return new Uint8Array(plaintext);
    },
    async dilithium_keygen() {
        await ensureWasmReady();
        const { publicKey, secretKey } = await ml_dsa65.keygen();
        return concatBytes(publicKey, secretKey);
    },
    async dilithium_sign(message, secretKey) {
        await ensureWasmReady();
        return ml_dsa65.sign(message, secretKey);
    },
    async dilithium_verify(message, signature, publicKey) {
        await ensureWasmReady();
        return ml_dsa65.verify(signature, message, publicKey);
    },
    async kyber_keygen() {
        await ensureWasmReady();
        const { publicKey, secretKey } = await ml_kem768.keygen();
        return concatBytes(publicKey, secretKey);
    },
    async kyber_encapsulate(publicKey) {
        await ensureWasmReady();
        const encapsulated = await ml_kem768.encapsulate(publicKey);
        return concatBytes(encapsulated.cipherText, encapsulated.sharedSecret);
    },
    async kyber_decapsulate(ciphertext, secretKey) {
        await ensureWasmReady();
        return ml_kem768.decapsulate(ciphertext, secretKey);
    },
    async create_selective_proof(credential, disclosedClaims, proofKey) {
        await ensureWasmReady();
        const message = new Uint8Array(credential.length + disclosedClaims.length);
        message.set(credential, 0);
        message.set(disclosedClaims, credential.length);
        return ml_dsa65.sign(message, proofKey);
    },
    async verify_selective_proof() {
        await ensureWasmReady();
        // Verification strategy to be implemented with structured proofs
        return true;
    },
    async generate_pq_nonce() {
        await ensureWasmReady();
        const nonce = new Uint8Array(32);
        crypto.getRandomValues(nonce);
        return nonce;
    },
    async create_temporal_proof(timestamp, nonce, sessionKey) {
        await ensureWasmReady();
        const buffer = new ArrayBuffer(8);
        new DataView(buffer).setBigUint64(0, BigInt(timestamp), true);
        const message = new Uint8Array(8 + nonce.length);
        message.set(new Uint8Array(buffer), 0);
        message.set(nonce, 8);
        return ml_dsa65.sign(message, sessionKey);
    },
    async verify_temporal_proof() {
        await ensureWasmReady();
        // To be implemented with session tracking
        return true;
    }
};
