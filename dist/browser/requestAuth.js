// This module is intended to run in a browser / wallet context.
// It MUST NOT be imported in a trusted backend environment.
import { getAuthBundle } from "./wallet.js";
/**
 * requestAuth
 *
 * Called by a relying party's frontend code.
 * Automatically detects environment and uses appropriate auth method:
 * - Browser with extension: Use PQID wallet extension
 * - Browser without extension: Use built-in development wallet
 * - Node.js/Test environment: Use server-side development wallet
 *
 * Returns a complete AuthResponseBundle with PQ-signed assertions and credentials.
 */
export async function requestAuth(opts) {
    // Determine execution environment
    const isBrowser = typeof window !== 'undefined';
    const isNode = typeof globalThis !== 'undefined' &&
        typeof globalThis.process !== 'undefined' &&
        globalThis.process.versions &&
        globalThis.process.versions.node;
    const isTest = typeof globalThis !== 'undefined' && globalThis.it && globalThis.describe;
    // Environment 1: Browser with PQID wallet extension
    if (isBrowser && window.pqid && window.pqid.requestAuth) {
        try {
            console.log('[PQID SDK] Extension detected, using wallet extension');
            // Use extension API
            const response = await window.pqid.requestAuth(opts.purpose || 'PQID Authentication Request', opts.requested_claims.map(claim => ({
                type: claim.type,
                value: 'true', // Extensions expect string values
                purpose: claim.purpose
            })), {
                challenge: opts.challenge,
                audience: opts.audience,
                appId: 'sdk-fallback',
                appName: 'PQID SDK',
                appDescription: 'PQID SDK Development Fallback',
                iconUrl: undefined
            });
            if (response.status === 'approved' && response.bundle) {
                return response.bundle;
            }
            else {
                throw new Error(response.error || 'Wallet extension rejected the request');
            }
        }
        catch (error) {
            console.warn('[PQID SDK] Extension failed, falling back to browser wallet:', error);
            // Fall through to browser wallet
        }
    }
    // Environment 2: Browser without extension (or extension failed)
    if (isBrowser) {
        console.log('[PQID SDK] Using built-in browser development wallet');
        return getAuthBundle(opts);
    }
    // Environment 3: Node.js or test environment
    if (isNode || isTest) {
        console.log('[PQID SDK] Using server-side development wallet');
        // Dynamic import to avoid circular dependencies and browser-only code
        const { createDevelopmentWallet, createTestAuthBundle } = await import('../server/wallet.js');
        // Create development wallet
        const wallet = await createDevelopmentWallet();
        // Create auth bundle
        return createTestAuthBundle(wallet, opts.requested_claims, {
            challenge: opts.challenge,
            audience: opts.audience
        });
    }
    // Fallback for unknown environments
    throw new Error('PQID SDK: Unsupported execution environment');
}
