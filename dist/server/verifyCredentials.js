// This module is intended for server-side verification only.
// Do NOT bundle this into client code.
import { verify } from "../crypto/index.js";
import { checkCredentialExpiry, getIssuerPublicKey } from "../issuer/devIssuer.js";
import { canonicalizeCredentialPayload } from "../utils/canonicalize.js";
export async function verifyCredentials(credentials, opts) {
    var _a, _b, _c, _d, _e;
    const claims = {};
    const errors = [];
    if (!Array.isArray(credentials)) {
        return {
            ok: false,
            claims,
            errors: [{ claim_type: "unknown", reason: "credentials must be an array" }]
        };
    }
    const now = (_a = opts.now) !== null && _a !== void 0 ? _a : new Date();
    for (const credential of credentials) {
        if (!opts.trustedIssuers.includes(credential.issuer)) {
            errors.push({
                claim_type: credential.claim_type,
                reason: `issuer ${credential.issuer} is not trusted`
            });
            continue;
        }
        if (credential.subject !== opts.expectedSubjectDid) {
            errors.push({
                claim_type: credential.claim_type,
                reason: `credential subject ${credential.subject} does not match expected DID ${opts.expectedSubjectDid}`
            });
            continue;
        }
        const issuerKey = await getIssuerPublicKey(credential.issuer);
        if (!issuerKey) {
            errors.push({
                claim_type: credential.claim_type,
                reason: `no public key for issuer ${credential.issuer}`
            });
            continue;
        }
        const expiryCheck = checkCredentialExpiry(credential, now);
        if (!expiryCheck.ok) {
            errors.push({
                claim_type: credential.claim_type,
                reason: (_b = expiryCheck.reason) !== null && _b !== void 0 ? _b : "credential expired"
            });
            continue;
        }
        if (!((_c = credential.proof) === null || _c === void 0 ? void 0 : _c.signatureBase64)) {
            errors.push({
                claim_type: credential.claim_type,
                reason: "missing credential signature"
            });
            continue;
        }
        const canonical = canonicalizeCredentialPayload(credential);
        // Support multiple signature algorithms
        const algorithm = ((_d = credential.proof) === null || _d === void 0 ? void 0 : _d.type) === "DilithiumSignature2025"
            ? "DilithiumSignature2025"
            : ((_e = credential.proof) === null || _e === void 0 ? void 0 : _e.type) === "Ed25519Signature2020"
                ? "Ed25519Signature2020"
                : "Ed25519Signature2020"; // Default for backward compatibility
        const verified = await verify({ publicKey: issuerKey, algorithm }, canonical, credential.proof.signatureBase64);
        if (!verified) {
            errors.push({
                claim_type: credential.claim_type,
                reason: "invalid credential signature"
            });
            continue;
        }
        claims[credential.claim_type] = credential.claim_value;
    }
    return { ok: errors.length === 0, claims, errors };
}
