import { ClaimType, Credential } from "../types";

/**
 * verifyCredentials
 *
 * v0.1:
 * - Filter credentials to only those from trusted issuers.
 * - Build a claim map like { age_over_18: true, good_standing: true }.
 * - TODO (future): verify each credential's proof.signatureBase64 using issuer public key.
 * - TODO (future): check not expired (validUntil).
 */
export function verifyCredentials(
  credentials: Credential[],
  opts: {
    trustedIssuers: string[];
  }
): {
  ok: boolean;
  claims: Partial<Record<ClaimType, boolean | string | number>>;
} {
  const claims: Partial<Record<ClaimType, boolean | string | number>> = {};

  if (!Array.isArray(credentials)) {
    return { ok: false, claims };
  }

  for (const cred of credentials) {
    if (!opts.trustedIssuers.includes(cred.issuer)) {
      continue;
    }

    // FUTURE:
    // - Validate cred.proof.signatureBase64 using issuer public key
    // - Check cred.validUntil >= now
    // - Check cred.subject is the same DID as bundle.did

    claims[cred.claim_type] = cred.claim_value;
  }

  return { ok: true, claims };
}
