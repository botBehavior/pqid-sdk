export declare function generateEd25519KeyPair(): Promise<{
    publicKey: CryptoKey;
    privateKey: CryptoKey;
    publicKeyBase64: string;
    privateKeyPkcs8Base64: string;
}>;
export declare function importEd25519PrivateKey(privateKeyPkcs8Base64: string): Promise<CryptoKey>;
export declare function importEd25519PublicKey(rawPublicKeyBase64: string): Promise<CryptoKey>;
export declare function signEd25519WithKey(privateKey: CryptoKey, message: string): Promise<string>;
export declare function signEd25519(privateKeyPkcs8Base64: string, message: string): Promise<string>;
export declare function verifyEd25519(rawPublicKeyBase64: string, message: string, signatureBase64: string): Promise<boolean>;
export declare function verifyEd25519WithKey(publicKey: CryptoKey, message: string, signatureBase64: string): Promise<boolean>;
//# sourceMappingURL=ed25519.d.ts.map