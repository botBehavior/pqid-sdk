import { AuthAssertion, Credential } from "../types.js";

export const ASSERTION_SPEC_VERSION = "pqid-auth-0.1.1";

function encode(value: unknown): string {
  return encodeURIComponent(String(value));
}

export function canonicalizeAssertion(
  assertion: Pick<AuthAssertion, "challenge" | "audience" | "timestamp" | "spec_version">
): string {
  return [
    ["challenge", assertion.challenge],
    ["audience", assertion.audience],
    ["timestamp", assertion.timestamp],
    ["spec_version", assertion.spec_version]
  ]
    .map(([key, value]) => `${key}=${encode(value)}`)
    .join("&");
}

export function canonicalizeCredentialPayload(
  payload: Pick<
    Credential,
    "id" | "issuer" | "subject" | "claim_type" | "claim_value" | "issuanceDate" | "validUntil"
  >
): string {
  return [
    ["id", payload.id],
    ["issuer", payload.issuer],
    ["subject", payload.subject],
    ["claim_type", payload.claim_type],
    ["claim_value", payload.claim_value],
    ["issuanceDate", payload.issuanceDate],
    ["validUntil", payload.validUntil]
  ]
    .map(([key, value]) => `${key}=${encode(value)}`)
    .join("&");
}
