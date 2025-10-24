import { AuthAssertion, Credential } from "../types.js";

export const ASSERTION_SPEC_VERSION = "pqid-auth-0.1.2";

function encode(value: unknown): string {
  return encodeURIComponent(String(value));
}

function canonicalizePairs(pairs: [string, unknown][]): string {
  // Canonical ordering must remain stable forever to keep signatures verifiable across versions.
  return pairs
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${encode(value)}`)
    .join("&");
}

export function canonicalizeAssertion(
  assertion: Pick<AuthAssertion, "challenge" | "audience" | "timestamp" | "spec_version">
): string {
  return canonicalizePairs([
    ["challenge", assertion.challenge],
    ["audience", assertion.audience],
    ["timestamp", assertion.timestamp],
    ["spec_version", assertion.spec_version]
  ]);
}

export function canonicalizeCredentialPayload(
  payload: Pick<
    Credential,
    "id" | "issuer" | "subject" | "claim_type" | "claim_value" | "issuanceDate" | "validUntil"
  >
): string {
  return canonicalizePairs([
    ["claim_type", payload.claim_type],
    ["claim_value", payload.claim_value],
    ["id", payload.id],
    ["issuanceDate", payload.issuanceDate],
    ["issuer", payload.issuer],
    ["subject", payload.subject],
    ["validUntil", payload.validUntil]
  ]);
}
