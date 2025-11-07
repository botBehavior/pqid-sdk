import { ClaimType, Credential } from "../types.js";
export declare const DEV_ISSUER_DID = "did:pqid-issuer:dev";
export declare function getDevIssuerPublicKey(): Promise<string>;
export declare const DEV_ISSUER_PUBLIC_KEY_PROMISE: Promise<string>;
export declare function issueCredential(subjectDid: string, claim_type: ClaimType, value: boolean | string | number): Promise<Credential>;
export declare function getIssuerPublicKey(did: string): Promise<string | undefined>;
export declare function getIssuerPublicKeySync(did: string): string | undefined;
export declare function checkCredentialExpiry(credential: Pick<Credential, "validUntil">, now?: Date): {
    ok: boolean;
    reason?: string;
};
//# sourceMappingURL=devIssuer.d.ts.map