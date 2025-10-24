// This module is intended for server-side verification only.
// Do NOT bundle this into client code.

import { verifyEd25519 } from "../crypto/ed25519.js";
import { getIssuerPublicKey } from "../issuer/devIssuer.js";
import {
  ClaimType,
  Credential,
  CredentialVerificationError,
  CredentialVerificationResult
} from "../types.js";
import { canonicalizeCredentialPayload } from "../utils/canonicalize.js";

interface VerifyCredentialsOptions {
  trustedIssuers: string[];
  issuerPublicKeyResolver?: (did: string) => string | undefined;
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

  const resolvePublicKey =
    opts.issuerPublicKeyResolver ?? getIssuerPublicKey;
  const now = opts.now ?? new Date();

  for (const credential of credentials) {
    if (!opts.trustedIssuers.includes(credential.issuer)) {
      errors.push({
        claim_type: credential.claim_type,
        reason: `issuer ${credential.issuer} is not trusted`
      });
      continue;
    }

    const issuerKey = resolvePublicKey(credential.issuer);
    if (!issuerKey) {
      errors.push({
        claim_type: credential.claim_type,
        reason: `no public key for issuer ${credential.issuer}`
      });
      continue;
    }

    const expiryMs = Date.parse(credential.validUntil);
    if (Number.isNaN(expiryMs)) {
      errors.push({
        claim_type: credential.claim_type,
        reason: "credential validUntil is invalid"
      });
      continue;
    }

    if (expiryMs <= now.getTime()) {
      errors.push({
        claim_type: credential.claim_type,
        reason: "credential expired"
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
