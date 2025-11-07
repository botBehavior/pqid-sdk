import { PQSessionKeys } from "./pq-session-security.js";
export interface PQAuthBundle {
    did: string;
    claims: Record<string, any>;
    credentials: any[];
    sessionKeys: {
        sessionId: string;
        publicKey: string;
        algorithm: string;
        expires: number;
    };
    temporalProof: {
        timestamp: number;
        challenge: string;
        signature: string;
        sessionId: string;
    };
    sessionAttestation: {
        sessionId: string;
        publicKey: string;
        signature: string;
        algorithm: string;
        timestamp: number;
    };
    integrityProof: {
        dataHash: string;
        signature: string;
        algorithm: string;
    };
    metadata: {
        specVersion: string;
        created: number;
        expires: number;
        relyingParty: string;
    };
}
export interface PQBundleVerification {
    valid: boolean;
    errors: string[];
    warnings: string[];
    sessionValid: boolean;
    temporalValid: boolean;
    integrityValid: boolean;
}
/**
 * Create enhanced PQ authentication bundle with quantum-resistant protections
 */
export declare function createPQAuthBundle(did: string, claims: Record<string, any>, credentials: any[], relyingParty: string): Promise<{
    bundle: PQAuthBundle;
    sessionKeys: PQSessionKeys;
}>;
/**
 * Verify PQ authentication bundle comprehensively
 */
export declare function verifyPQAuthBundle(bundle: PQAuthBundle, expectedRelyingParty?: string): Promise<PQBundleVerification>;
/**
 * Extract claims from verified bundle
 */
export declare function extractClaimsFromBundle(bundle: PQAuthBundle): Record<string, any>;
/**
 * Get bundle security metadata
 */
export declare function getBundleSecurityMetadata(bundle: PQAuthBundle): {
    sessionId: string;
    expires: number;
    algorithm: string;
    created: number;
};
//# sourceMappingURL=pq-auth-bundle.d.ts.map