import { AuthResponseBundle, RequestedClaim, DIDDocument } from "../types.js";
export interface RequestAuthOptions {
    requested_claims: RequestedClaim[];
    challenge?: string;
    audience?: string;
    purpose?: string;
}
export declare function getWalletState(): Promise<{
    did: string;
    publicKeyBase64Url: string;
    verificationMethodId: string;
}>;
export declare function signAssertionPayload(fields: {
    challenge: string;
    audience: string;
    timestamp: string;
    spec_version: string;
}): Promise<string>;
export declare function getDidDocument(): Promise<DIDDocument>;
export declare function getWalletDid(): Promise<string>;
export declare function getWalletPublicKeyBase64Url(): Promise<string>;
export declare function getWalletVerificationMethodId(): Promise<string>;
export declare const PQID_AUTH_SPEC_VERSION = "pqid-auth-0.1.2";
export declare function getAuthBundle(opts: RequestAuthOptions): Promise<AuthResponseBundle>;
//# sourceMappingURL=wallet.d.ts.map