export declare function loadMLDSAInterface(): Promise<{
    keygen: () => Promise<{
        publicKey: any;
        secretKey: any;
    }>;
    sign: (message: Uint8Array, secretKey: Uint8Array) => Promise<any>;
    verify: (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => Promise<any>;
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