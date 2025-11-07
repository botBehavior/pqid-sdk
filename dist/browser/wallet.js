// This module is intended to run in a browser / wallet context.
// It MUST NOT be imported in a trusted backend environment.
import { base64ToBase64Url } from "../crypto/base64.js";
import { generateKeyPair, sign } from "../crypto/index.js";
import { ASSERTION_SPEC_VERSION, canonicalizeAssertionPayload } from "../utils/canonicalize.js";
import { issueCredential } from "../issuer/devIssuer.js";
const DEFAULT_CLAIM_VALUES = {
    // Legacy demo credentials
    age_over_18: true,
    good_standing: true,
    account_age_days_over_30: 60,
    // OAuth-based credentials
    email_verified: true,
    google_account_age_over_365: true,
    github_account_age_over_180: true,
    apple_user: true,
    human_user: true
};
function getDefaultClaimValue(type) {
    var _a;
    return (_a = DEFAULT_CLAIM_VALUES[type]) !== null && _a !== void 0 ? _a : true;
}
let walletStatePromise = null;
async function createWalletState() {
    // Use PQ crypto by default, fallback to Ed25519 for compatibility
    const keyPair = await generateKeyPair("DilithiumSignature2025");
    const publicKeyBase64Url = base64ToBase64Url(keyPair.publicKeyBase64);
    // Update DID generation to support PQ
    const did = `did:pqid:${publicKeyBase64Url}`;
    const verificationMethodId = `${did}#key-1`;
    // Determine key type based on algorithm
    const keyType = keyPair.algorithm === "DilithiumSignature2025"
        ? "DilithiumKey2025"
        : "Ed25519VerificationKey2020";
    const didDocument = {
        id: did,
        "@context": ["https://www.w3.org/ns/did/v1"],
        verificationMethod: [
            {
                id: verificationMethodId,
                type: keyType,
                controller: did,
                publicKeyBase64: keyPair.publicKeyBase64
            }
        ],
        authentication: [verificationMethodId]
    };
    return {
        did,
        didDocument,
        verificationMethodId,
        keyPair,
        publicKeyBase64: keyPair.publicKeyBase64,
        publicKeyBase64Url
    };
}
async function getInternalWalletState() {
    if (!walletStatePromise) {
        walletStatePromise = createWalletState();
    }
    return walletStatePromise;
}
export async function getWalletState() {
    const state = await getInternalWalletState();
    return {
        did: state.did,
        publicKeyBase64Url: state.publicKeyBase64Url,
        verificationMethodId: state.verificationMethodId
    };
}
export async function signAssertionPayload(fields) {
    const state = await getInternalWalletState();
    const canonical = canonicalizeAssertionPayload(fields);
    return sign({ privateKey: state.keyPair.privateKey, algorithm: state.keyPair.algorithm }, canonical);
}
export async function getDidDocument() {
    const state = await getInternalWalletState();
    return state.didDocument;
}
export async function getWalletDid() {
    const state = await getInternalWalletState();
    return state.did;
}
export async function getWalletPublicKeyBase64Url() {
    const state = await getInternalWalletState();
    return state.publicKeyBase64Url;
}
export async function getWalletVerificationMethodId() {
    const state = await getInternalWalletState();
    return state.verificationMethodId;
}
export const PQID_AUTH_SPEC_VERSION = ASSERTION_SPEC_VERSION;
export async function getAuthBundle(opts) {
    var _a, _b;
    const now = new Date().toISOString();
    const { did } = await getInternalWalletState();
    const did_document = await getDidDocument();
    const challenge = opts.challenge ||
        (typeof crypto !== "undefined" && "randomUUID" in crypto
            ? crypto.randomUUID()
            : `nonce-${Math.random().toString(36).slice(2)}`);
    const audience = (_a = opts.audience) !== null && _a !== void 0 ? _a : window.location.origin;
    const assertion = {
        challenge,
        audience,
        timestamp: now,
        spec_version: ASSERTION_SPEC_VERSION
    };
    const assertion_signatureBase64 = await signAssertionPayload(assertion);
    const credentials = [];
    const seenTypes = new Set();
    for (const claim of (_b = opts.requested_claims) !== null && _b !== void 0 ? _b : []) {
        if (seenTypes.has(claim.type)) {
            continue;
        }
        seenTypes.add(claim.type);
        credentials.push(await issueCredential(did, claim.type, getDefaultClaimValue(claim.type)));
    }
    return {
        did,
        did_document,
        assertion,
        assertion_signatureBase64,
        credentials
    };
}
