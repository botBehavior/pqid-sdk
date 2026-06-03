/**
 * Server-side wallet utilities for development and testing
 *
 * These functions allow web developers to create PQID wallets and auth bundles
 * without requiring a browser environment or Chrome extension.
 */
import { generateKeyPair, sign } from '../crypto/index.js';
import { base64ToBase64Url } from '../crypto/base64.js';
import { issueCredential } from '../issuer/devIssuer.js';
import { canonicalizeAssertionPayload, ASSERTION_SPEC_VERSION } from '../utils/canonicalize.js';
/**
 * Create a development wallet server-side
 * Useful for testing PQID integration without browser dependencies
 */
export async function createDevelopmentWallet(opts) {
    // Generate PQ key pair
    const keyPair = await generateKeyPair('DilithiumSignature2025');
    // Create DID from the FULL public key (base64url), matching the browser wallet
    // (`did:pqid:<publicKeyBase64Url>`) and what verifyAssertion expects: it derives the
    // verification key from the DID's last segment. The previous `did:pqid:dev-<16 chars>`
    // form truncated the key, so server-wallet bundles always failed verification with
    // "did document key mismatch".
    const did = (opts === null || opts === void 0 ? void 0 : opts.did) || `did:pqid:${base64ToBase64Url(keyPair.publicKeyBase64)}`;
    // Generate default credentials
    const credentials = [];
    if (opts === null || opts === void 0 ? void 0 : opts.credentials) {
        for (const cred of opts.credentials) {
            const credential = await issueCredential(did, cred.type, cred.value);
            credentials.push(credential);
        }
    }
    else {
        // Default development credentials
        const defaultCreds = [
            { type: 'age_over_18', value: true },
            { type: 'good_standing', value: true }
        ];
        for (const cred of defaultCreds) {
            const credential = await issueCredential(did, cred.type, cred.value);
            credentials.push(credential);
        }
    }
    // Decode base64 keys to Uint8Arrays
    const publicKeyBytes = Uint8Array.from(atob(keyPair.publicKeyBase64), c => c.charCodeAt(0));
    const privateKeyBytes = Uint8Array.from(atob(keyPair.privateKeyBase64), c => c.charCodeAt(0));
    return {
        did,
        keyPair: {
            publicKey: publicKeyBytes,
            privateKey: privateKeyBytes,
            algorithm: keyPair.algorithm
        },
        credentials
    };
}
/**
 * Create a test auth bundle server-side
 * Allows developers to test server verification without browser dependencies
 */
export async function createTestAuthBundle(wallet, requestedClaims, opts) {
    const challenge = (opts === null || opts === void 0 ? void 0 : opts.challenge) || crypto.randomUUID();
    const audience = (opts === null || opts === void 0 ? void 0 : opts.audience) || 'https://test.example.com';
    // Create assertion
    const assertion = {
        challenge,
        audience,
        timestamp: new Date().toISOString(),
        spec_version: ASSERTION_SPEC_VERSION
    };
    // Sign assertion
    const canonical = canonicalizeAssertionPayload(assertion);
    const assertion_signatureBase64 = await sign({
        privateKey: wallet.keyPair.privateKey,
        algorithm: 'DilithiumSignature2025'
    }, canonical);
    // Find matching credentials
    const credentials = [];
    for (const claim of requestedClaims) {
        const matchingCred = wallet.credentials.find(c => c.claim_type === claim.type);
        if (!matchingCred) {
            throw new Error(`No credential found for claim type: ${claim.type}`);
        }
        credentials.push(matchingCred);
    }
    return {
        did: wallet.did,
        did_document: {
            '@context': ['https://www.w3.org/ns/did/v1'],
            id: wallet.did,
            verificationMethod: [{
                    id: `${wallet.did}#key-1`,
                    type: 'DilithiumKey2025',
                    controller: wallet.did,
                    publicKeyBase64: btoa(String.fromCharCode(...wallet.keyPair.publicKey))
                }],
            authentication: [`${wallet.did}#key-1`]
        },
        assertion,
        assertion_signatureBase64,
        credentials
    };
}
// NOTE: A `createMockAuthBundle` helper was removed during the revive cleanup. It produced
// bundles with placeholder, unverifiable signatures (`'mock-signature-N'`, `'MockPublicKey123'`)
// and a non-key DID. Such a bundle can never pass `verifyAssertion`/`verifyCredentials`, so it
// was misleading "security theater" rather than a useful test fixture. Use
// `createTestAuthBundle` (which signs with a real ML-DSA-65 key) for tests instead.
