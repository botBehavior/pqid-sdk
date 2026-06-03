// This module is intended for server-side verification only.
// Do NOT bundle this into client code.

import { verifyEd25519 } from "../crypto/ed25519.js";
import { verify, VerificationKey } from "../crypto/index.js";
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
  // Optional map of issuer DID -> public key base64 for custom issuers (e.g. self-issued credentials)
  issuerPublicKeys?: Record<string, string>;
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
    // Check if the issuer is explicitly trusted. The previous "*" wildcard, which trusted
    // ANY issuer, has been removed: it silently disabled the trust check and would accept a
    // credential self-issued by an attacker. Relying parties must enumerate the issuer DIDs
    // they trust.
    const isTrusted = opts.trustedIssuers.includes(credential.issuer);
    if (!isTrusted) {
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

    // Try to get issuer key from custom keys first, then fall back to dev issuer
    let issuerKey = opts.issuerPublicKeys?.[credential.issuer];
    if (!issuerKey) {
      issuerKey = await getIssuerPublicKey(credential.issuer);
    }
    
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

    // Support multiple signature algorithms
    const algorithm = credential.proof?.type === "DilithiumSignature2025"
      ? "DilithiumSignature2025"
      : credential.proof?.type === "Ed25519Signature2020"
      ? "Ed25519Signature2020"
      : "Ed25519Signature2020"; // Default for backward compatibility

    const verified = await verify(
      { publicKey: issuerKey, algorithm },
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
