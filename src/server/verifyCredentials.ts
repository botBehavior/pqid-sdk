// This module is intended for server-side verification only.
// Do NOT bundle this into client code.

import { verifyEd25519 } from "../crypto/ed25519.js";
import {
  checkCredentialExpiry,
  getIssuerPublicKey
} from "../issuer/devIssuer.js";
import {
  ClaimType,
  Credential,
  CredentialVerificationError,
  CredentialVerificationResult
} from "../types.js";
import { canonicalizeCredentialPayload } from "../utils/canonicalize.js";

interface VerifyCredentialsOptions {
  trustedIssuers: string[];
  expectedSubjectDid: string;
  now?: Date;
}

export async function verifyCredentials(
  credentials: Credential[],
  opts: VerifyCredentialsOptions
): Promise<CredentialVerificationResult> {
  const claims: Partial<Record<ClaimType, boolean | string | number>> = {};
  const errors: CredentialVerificationError[] = [];

  if (!Array.isArray(credentials)) {
    return {
      ok: false,
      claims,
      errors: [{ claim_type: "unknown", reason: "credentials must be an array" }]
    };
  }

  const now = opts.now ?? new Date();

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

    const issuerKey = getIssuerPublicKey(credential.issuer);
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
        reason: expiryCheck.reason ?? "credential expired"
      });
      continue;
    }

    if (!credential.proof?.signatureBase64) {
      errors.push({
        claim_type: credential.claim_type,
        reason: "missing credential signature"
      });
      continue;
    }

    const canonical = canonicalizeCredentialPayload(credential);

    const verified = await verifyEd25519(
      issuerKey,
      canonical,
      credential.proof.signatureBase64
    );

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
