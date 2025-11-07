export declare function ensureWasmReady(): Promise<void>;
export declare function isWasmReady(): boolean;
export declare const wasmApi: {
    derive_pq_key(password: Uint8Array, salt: Uint8Array, iterations: number): Promise<Uint8Array>;
    pq_encrypt(plaintext: Uint8Array, key: Uint8Array, nonce: Uint8Array): Promise<Uint8Array>;
    pq_decrypt(ciphertext: Uint8Array, key: Uint8Array): Promise<Uint8Array>;
    dilithium_keygen(): Promise<Uint8Array>;
    dilithium_sign(message: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array>;
    dilithium_verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
    kyber_keygen(): Promise<Uint8Array>;
    kyber_encapsulate(publicKey: Uint8Array): Promise<Uint8Array>;
    kyber_decapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array>;
    create_selective_proof(credential: Uint8Array, disclosedClaims: Uint8Array, proofKey: Uint8Array): Promise<Uint8Array>;
    verify_selective_proof(proof: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
    generate_pq_nonce(): Promise<Uint8Array>;
    create_temporal_proof(timestamp: number, nonce: Uint8Array, sessionKey: Uint8Array): Promise<Uint8Array>;
    verify_temporal_proof(proof: Uint8Array, maxAgeSeconds: number): Promise<boolean>;
};
//# sourceMappingURL=wasm-manager.d.ts.map