export interface PQSessionKeys {
    sessionId: string;
    publicKey: Uint8Array;
    privateKey: Uint8Array;
    algorithm: string;
    created: number;
    expires: number;
}
export interface PQSharedSecret {
    secret: Uint8Array;
    sessionId: string;
    algorithm: string;
}
export interface PQTemporalProof {
    timestamp: number;
    challenge: string;
    signature: string;
    sessionId: string;
}
export interface PQSessionAttestation {
    sessionId: string;
    publicKey: Uint8Array;
    signature: string;
    algorithm: string;
    timestamp: number;
}
/**
 * Generate fresh PQ session keys for each authentication request
 * This prevents replay attacks and provides forward secrecy
 */
export declare function createAuthSession(): Promise<PQSessionKeys>;
/**
 * Perform quantum-resistant key exchange with relying party
 * Simplified key exchange using PQ signatures for authentication
 */
export declare function performPQKeyExchange(sessionKeys: PQSessionKeys, challenge: string): Promise<PQSharedSecret>;
/**
 * Sign authentication response with fresh session keys
 */
export declare function signAuthResponse(response: any, sessionKeys: PQSessionKeys): Promise<string>;
/**
 * Verify authentication response signature
 */
export declare function verifyAuthResponse(response: any, signature: string, sessionPublicKey: Uint8Array): Promise<boolean>;
/**
 * Create temporal proof to prevent replay attacks
 */
export declare function createTemporalProof(challenge: string, sessionKeys: PQSessionKeys): Promise<PQTemporalProof>;
/**
 * Verify temporal proof and check for replay attacks
 */
export declare function verifyTemporalProof(proof: PQTemporalProof, sessionPublicKey: Uint8Array, maxAge?: number): Promise<boolean>;
/**
 * Create session attestation for additional security
 */
export declare function createSessionAttestation(sessionKeys: PQSessionKeys): Promise<PQSessionAttestation>;
/**
 * Verify session attestation
 */
export declare function verifySessionAttestation(attestation: PQSessionAttestation): Promise<boolean>;
/**
 * Check if session keys are still valid
 */
export declare function isSessionValid(sessionKeys: PQSessionKeys): boolean;
/**
 * Generate quantum-resistant nonce for challenges
 */
export declare function generatePQNonce(): Promise<string>;
/**
 * Create challenge with quantum-resistant properties
 */
export declare function createPQChallenge(relyingParty: string, sessionId: string): Promise<string>;
//# sourceMappingURL=pq-session-security.d.ts.map