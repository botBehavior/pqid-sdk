import { AuthAssertion, Credential } from "../types.js";
export declare const ASSERTION_SPEC_VERSION = "pqid-auth-0.1.2";
export declare function canonicalizeAssertionPayload(assertion: Pick<AuthAssertion, "challenge" | "audience" | "timestamp" | "spec_version">): string;
export declare function canonicalizeCredentialPayload(payload: Pick<Credential, "id" | "issuer" | "subject" | "claim_type" | "claim_value" | "issuanceDate" | "validUntil">): string;
export { canonicalizeAssertionPayload as canonicalizeAssertion };
//# sourceMappingURL=canonicalize.d.ts.map