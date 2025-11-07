export declare function loadMLDSAInterface(): Promise<{
    keygen: () => Promise<{
        publicKey: Uint8Array<ArrayBufferLike>;
        secretKey: Uint8Array<ArrayBufferLike>;
    }>;
    sign: (message: Uint8Array, secretKey: Uint8Array) => Promise<Uint8Array<ArrayBufferLike>>;
    verify: (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => Promise<boolean>;
}>;
export interface DilithiumKeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
    publicKeyBase64: string;
    privateKeyBase64: string;
}
export declare function generateDilithiumKeyPair(): Promise<DilithiumKeyPair>;
export declare function signDilithium(privateKeyBase64: string, message: string): Promise<string>;
export declare function verifyDilithium(publicKeyBase64: string, message: string, signatureBase64: string): Promise<boolean>;
//# sourceMappingURL=dilithium.d.ts.map