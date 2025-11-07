import { Credential, CredentialVerificationResult } from "../types.js";
interface VerifyCredentialsOptions {
    trustedIssuers: string[];
    expectedSubjectDid: string;
    now?: Date;
}
export declare function verifyCredentials(credentials: Credential[], opts: VerifyCredentialsOptions): Promise<CredentialVerificationResult>;
export {};
//# sourceMappingURL=verifyCredentials.d.ts.map