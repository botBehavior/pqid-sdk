// This module is intended for server-side verification only.
// Do NOT bundle this into client code.

import { verifyEd25519 } from "../crypto/ed25519.js";
import {
  AssertionVerificationResult,
  AuthResponseBundle,
  DIDVerificationMethod
} from "../types.js";
import { ASSERTION_SPEC_VERSION, canonicalizeAssertion } from "../utils/canonicalize.js";

const FRESHNESS_WINDOW_MS = 2 * 60 * 1000;

function pickAuthenticationMethod(bundle: AuthResponseBundle) {
  const didDocument = bundle.did_document;
  if (!didDocument) {
    return undefined;
  }

  const preferredId = didDocument.authentication?.[0];
  if (preferredId) {
    return didDocument.verificationMethod.find(
      (method: DIDVerificationMethod) => method.id === preferredId
    );
  }

  return didDocument.verificationMethod[0];
}

export async function verifyAssertion(
  bundle: AuthResponseBundle
): Promise<AssertionVerificationResult> {
  if (!bundle) {
    return { ok: false, error: "missing bundle" };
  }

  if (!bundle.did) {
    return { ok: false, error: "missing did" };
  }

  if (!bundle.did_document) {
    return { ok: false, error: "missing did document" };
  }

  const assertion = bundle.assertion;
  if (!assertion) {
    return { ok: false, error: "missing assertion" };
  }

  if (!assertion.challenge || !assertion.audience) {
    return { ok: false, error: "invalid assertion fields" };
  }

  if (assertion.spec_version !== ASSERTION_SPEC_VERSION) {
    return { ok: false, error: "unsupported assertion version" };
  }

  const timestampMs = Date.parse(assertion.timestamp);
  if (Number.isNaN(timestampMs)) {
    return { ok: false, error: "invalid assertion timestamp" };
  }

  const nowMs = Date.now();
  if (Math.abs(nowMs - timestampMs) > FRESHNESS_WINDOW_MS) {
    return { ok: false, error: "stale assertion" };
  }

  if (bundle.did_document.id !== bundle.did) {
    return { ok: false, error: "did mismatch" };
  }

  if (!bundle.assertion_signatureBase64) {
    return { ok: false, error: "missing assertion signature" };
  }

  const verificationMethod = pickAuthenticationMethod(bundle);
  if (!verificationMethod) {
    return { ok: false, error: "missing verification method" };
  }

  if (verificationMethod.type !== "Ed25519VerificationKey2020") {
    return { ok: false, error: "unsupported verification method" };
  }

  const canonical = canonicalizeAssertion(assertion);
  const verified = await verifyEd25519(
    verificationMethod.publicKeyBase64,
    canonical,
    bundle.assertion_signatureBase64
  );

  if (!verified) {
    return { ok: false, error: "invalid assertion signature" };
  }

  return { ok: true, did: bundle.did };
}
