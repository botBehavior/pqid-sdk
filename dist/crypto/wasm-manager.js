// Low-level cryptographic primitive accessors.
//
// HONESTY NOTE: Despite the historical "wasm" name, there is no WebAssembly here. The
// post-quantum primitives (ML-DSA-65, ML-KEM-768) come from the pure-JS @noble/post-quantum
// library; AES-GCM and PBKDF2 come from the platform Web Crypto API (available in modern
// browsers and Node >=18). The module name is retained only for import-path stability.
let ml_dsa65 = null;
let ml_kem768 = null;
let nobleReady = false;
function getSubtle() {
    if (typeof crypto === "undefined" || !crypto.subtle) {
        throw new Error("Web Crypto API unavailable in this environment");
    }
    return crypto.subtle;
}
export async function ensureCryptoReady() {
    if (nobleReady) {
        return;
    }
    getSubtle(); // throws if Web Crypto is unavailable
    if (!ml_dsa65) {
        try {
            const dsaModule = await import("@noble/post-quantum/ml-dsa.js");
            ml_dsa65 = dsaModule.ml_dsa65;
        }
        catch (error) {
            throw new Error(`Failed to load ML-DSA post-quantum crypto: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    if (!ml_kem768) {
        try {
            const kemModule = await import("@noble/post-quantum/ml-kem.js");
            ml_kem768 = kemModule.ml_kem768;
        }
        catch (error) {
            throw new Error(`Failed to load ML-KEM post-quantum crypto: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    nobleReady = true;
}
export function isCryptoReady() {
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
export const cryptoApi = {
    /** PBKDF2-HMAC-SHA256 key derivation (classical, not post-quantum). */
    async derive_key(password, salt, iterations) {
        const subtle = getSubtle();
        const keyMaterial = await subtle.importKey("raw", copyBuffer(password), { name: "PBKDF2" }, false, ["deriveBits"]);
        const derivedBits = await subtle.deriveBits({ name: "PBKDF2", salt: copyBuffer(salt), iterations, hash: "SHA-256" }, keyMaterial, 256);
        return new Uint8Array(derivedBits);
    },
    /** AES-256-GCM authenticated encryption (classical, not post-quantum). Returns nonce || ciphertext. */
    async aes_gcm_encrypt(plaintext, key, nonce) {
        const subtle = getSubtle();
        const cryptoKey = await subtle.importKey("raw", copyBuffer(key), { name: "AES-GCM" }, false, ["encrypt"]);
        const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv: copyBuffer(nonce) }, cryptoKey, copyBuffer(plaintext));
        const result = new Uint8Array(nonce.length + ciphertext.byteLength);
        result.set(nonce, 0);
        result.set(new Uint8Array(ciphertext), nonce.length);
        return result;
    },
    /** AES-256-GCM decryption. Expects nonce || ciphertext; throws if the auth tag fails. */
    async aes_gcm_decrypt(ciphertext, key) {
        const subtle = getSubtle();
        const nonce = ciphertext.slice(0, 12);
        const encryptedData = ciphertext.slice(12);
        const cryptoKey = await subtle.importKey("raw", copyBuffer(key), { name: "AES-GCM" }, false, ["decrypt"]);
        const plaintext = await subtle.decrypt({ name: "AES-GCM", iv: copyBuffer(nonce) }, cryptoKey, copyBuffer(encryptedData));
        return new Uint8Array(plaintext);
    },
    /** FIPS 204 ML-DSA-65 key generation. Returns publicKey || secretKey. */
    async ml_dsa_keygen() {
        await ensureCryptoReady();
        const { publicKey, secretKey } = await ml_dsa65.keygen();
        return concatBytes(publicKey, secretKey);
    },
    async ml_dsa_sign(message, secretKey) {
        await ensureCryptoReady();
        return ml_dsa65.sign(message, secretKey);
    },
    async ml_dsa_verify(message, signature, publicKey) {
        await ensureCryptoReady();
        return ml_dsa65.verify(signature, message, publicKey);
    },
    /** FIPS 203 ML-KEM-768 key generation. Returns publicKey || secretKey. */
    async ml_kem_keygen() {
        await ensureCryptoReady();
        const { publicKey, secretKey } = await ml_kem768.keygen();
        return concatBytes(publicKey, secretKey);
    },
    async ml_kem_encapsulate(publicKey) {
        await ensureCryptoReady();
        const encapsulated = await ml_kem768.encapsulate(publicKey);
        return concatBytes(encapsulated.cipherText, encapsulated.sharedSecret);
    },
    async ml_kem_decapsulate(ciphertext, secretKey) {
        await ensureCryptoReady();
        return ml_kem768.decapsulate(ciphertext, secretKey);
    }
};
