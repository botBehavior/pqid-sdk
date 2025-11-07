export interface PQCredentialProof {
    credentialId: string;
    claimType: string;
    claimValue: any;
    issuerDid: string;
    proof: {
        signature: string;
        algorithm: string;
        challenge: string;
        timestamp: number;
    };
    metadata: {
        revealed: boolean;
        proofType: string;
    };
}
export interface PQDisclosureProof {
    credentialId: string;
    claimType: string;
    proofValue: string;
    issuerPublicKey: string;
    challenge: string;
    metadata: {
        disclosureLevel: 'minimal' | 'standard' | 'full';
        algorithm: string;
    };
}
export interface PQDisclosureBundle {
    proofs: PQDisclosureProof[];
    bundleProof: {
        signature: string;
        algorithm: string;
        timestamp: number;
    };
    metadata: {
        sessionId: string;
        relyingParty: string;
        created: number;
    };
}
/**
 * Generate PQ proof of credential ownership without revealing full credential
 */
export declare function generateCredentialProof(credential: any, challenge: string, privateKey: Uint8Array): Promise<PQCredentialProof>;
/**
 * Verify credential proof
 */
export declare function verifyCredentialProof(proof: PQCredentialProof, issuerPublicKey: Uint8Array): Promise<boolean>;
/**
 * Create zero-knowledge proof of credential (placeholder for future ZK implementation)
 */
export declare function generateZKCredentialProof(credential: any, challenge: string): Promise<PQDisclosureProof>;
/**
 * Verify ZK proof (placeholder)
 */
export declare function verifyZKCredentialProof(proof: PQDisclosureProof): Promise<boolean>;
/**
 * Compose multiple credential proofs into a disclosure bundle
 */
export declare function composeDisclosureBundle(proofs: PQCredentialProof[], sessionId: string, relyingParty: string, privateKey: Uint8Array): Promise<PQDisclosureBundle>;
/**
 * Verify disclosure bundle
 */
export declare function verifyDisclosureBundle(bundle: PQDisclosureBundle, publicKey: Uint8Array): Promise<{
    valid: boolean;
    errors: string[];
}>;
/**
 * Extract claims from verified disclosure bundle
 */
export declare function extractClaimsFromBundle(bundle: PQDisclosureBundle): Record<string, any>;
/**
 * Determine optimal disclosure level based on privacy requirements
 */
export declare function determineDisclosureLevel(claimType: string, privacyLevel?: 'high' | 'medium' | 'low'): 'minimal' | 'standard' | 'full';
//# sourceMappingURL=pq-selective-disclosure.d.ts.map