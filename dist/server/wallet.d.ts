/**
 * Server-side wallet utilities for development and testing
 *
 * These functions allow web developers to create PQID wallets and auth bundles
 * without requiring a browser environment or Chrome extension.
 */
import type { AuthResponseBundle, Credential } from '../types.js';
export interface ServerWalletState {
    did: string;
    keyPair: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
        algorithm: string;
    };
    credentials: Credential[];
}
/**
 * Create a development wallet server-side
 * Useful for testing PQID integration without browser dependencies
 */
export declare function createDevelopmentWallet(opts?: {
    did?: string;
    credentials?: Array<{
        type: string;
        value: string;
        purpose?: string;
    }>;
}): Promise<ServerWalletState>;
/**
 * Create a test auth bundle server-side
 * Allows developers to test server verification without browser dependencies
 */
export declare function createTestAuthBundle(wallet: ServerWalletState, requestedClaims: Array<{
    type: string;
    purpose?: string;
}>, opts?: {
    challenge?: string;
    audience?: string;
}): Promise<AuthResponseBundle>;
//# sourceMappingURL=wallet.d.ts.map