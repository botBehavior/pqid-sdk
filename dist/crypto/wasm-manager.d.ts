export declare function ensureCryptoReady(): Promise<void>;
export declare function isCryptoReady(): boolean;
export declare const cryptoApi: {
    /** PBKDF2-HMAC-SHA256 key derivation (classical, not post-quantum). */
    derive_key(password: Uint8Array, salt: Uint8Array, iterations: number): Promise<Uint8Array>;
    /** AES-256-GCM authenticated encryption (classical, not post-quantum). Returns nonce || ciphertext. */
    aes_gcm_encrypt(plaintext: Uint8Array, key: Uint8Array, nonce: Uint8Array): Promise<Uint8Array>;
    /** AES-256-GCM decryption. Expects nonce || ciphertext; throws if the auth tag fails. */
    aes_gcm_decrypt(ciphertext: Uint8Array, key: Uint8Array): Promise<Uint8Array>;
    /** FIPS 204 ML-DSA-65 key generation. Returns publicKey || secretKey. */
    ml_dsa_keygen(): Promise<Uint8Array>;
    ml_dsa_sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array>;
    ml_dsa_verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
    /** FIPS 203 ML-KEM-768 key generation. Returns publicKey || secretKey. */
    ml_kem_keygen(): Promise<Uint8Array>;
    ml_kem_encapsulate(publicKey: Uint8Array): Promise<Uint8Array>;
    ml_kem_decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array>;
};
//# sourceMappingURL=wasm-manager.d.ts.map