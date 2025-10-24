import { AuthResponseBundle } from "../types";

/**
 * verifyAssertion
 *
 * v0.1:
 * - Check presence of required fields.
 * - Ensure assertion and did exist.
 * - TODO (future): verify Dilithium signature using did_document.
 */
export function verifyAssertion(bundle: AuthResponseBundle): boolean {
  if (!bundle) return false;
  if (!bundle.did) return false;
  if (!bundle.did_document) return false;
  if (!bundle.assertion) return false;
  if (!bundle.assertion.challenge) return false;
  if (!bundle.assertion_signatureBase64) return false;

  // Future: check bundle.assertion_signatureBase64 using did_document.verificationMethod
  // Future: confirm bundle.assertion.audience matches our service origin
  // Future: confirm timestamp freshness

  return true;
}
