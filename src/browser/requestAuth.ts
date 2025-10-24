// This module is intended to run in a browser / wallet context.
// It MUST NOT be imported in a trusted backend environment.

import { issueCredential } from "../issuer/devIssuer.js";
import {
  AuthResponseBundle,
  Credential,
  RequestedClaim,
  ClaimType
} from "../types.js";
import { ASSERTION_SPEC_VERSION } from "../utils/canonicalize.js";
import { getDidDocument, getWalletDid, signAssertion } from "./wallet.js";

const DEFAULT_CLAIM_VALUES: Record<ClaimType, boolean | string | number> = {
  age_over_18: true,
  good_standing: true,
  account_age_days_over_30: 60
};

function getDefaultClaimValue(type: ClaimType): boolean | string | number {
  return DEFAULT_CLAIM_VALUES[type] ?? true;
}

/**
 * requestAuth
 *
 * Called by a relying party's frontend code.
 * Eventually this will talk to the PQID wallet extension via window.pqid.requestAuth(...)
 * and ask the user to approve sharing certain claims.
 *
 * For v0.1.1 this provisions a development Ed25519 wallet key pair, issues
 * credentials from the dev issuer, and returns a signed AuthResponseBundle.
 */
export async function requestAuth(opts: {
  requested_claims: RequestedClaim[];
  challenge?: string;
  audience?: string;
}): Promise<AuthResponseBundle> {
  const now = new Date().toISOString();
  const did = await getWalletDid();
  const did_document = await getDidDocument();

  const challenge =
    opts.challenge ||
    (typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : `nonce-${Math.random().toString(36).slice(2)}`);
  const audience = opts.audience ?? window.location.origin;

  const assertion = {
    challenge,
    audience,
    timestamp: now,
    spec_version: ASSERTION_SPEC_VERSION
  };

  const signatureBase64 = await signAssertion(challenge, audience, now);

  const requestedTypes = new Set(
    (opts.requested_claims || []).map((claim) => claim.type)
  );

  const credentials: Credential[] = [];

  for (const type of requestedTypes) {
    credentials.push(
      await issueCredential(did, type, getDefaultClaimValue(type))
    );
  }

  return {
    did,
    did_document,
    assertion,
    assertion_signatureBase64: signatureBase64,
    credentials
  };
}
