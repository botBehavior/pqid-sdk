// This module is intended for server-side verification only.
// Do NOT bundle this into client code.

import { base64UrlToBase64 } from "../crypto/base64.js";
import { verifyEd25519 } from "../crypto/ed25519.js";
import { verify, VerificationKey } from "../crypto/index.js";
import {
  AssertionVerificationResult,
  AuthResponseBundle,
  DIDVerificationMethod
} from "../types.js";
import {
  ASSERTION_SPEC_VERSION,
  canonicalizeAssertionPayload
} from "../utils/canonicalize.js";

const FRESHNESS_WINDOW_MS = 2 * 60 * 1000;

function pickAuthenticationMethod(bundle: AuthResponseBundle) {
  const didDocument = bundle.did_document;
  if (!didDocument) {
    return undefined;
  }

  const verificationMethods = didDocument.verificationMethod;
  if (!Array.isArray(verificationMethods) || verificationMethods.length === 0) {
    return undefined;
  }

  const preferredId = didDocument.authentication?.[0];
  if (preferredId) {
    return verificationMethods.find((method: DIDVerificationMethod) => method.id === preferredId);
  }

  return verificationMethods[0];
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

  // Support multiple algorithm types
  const algorithm = verificationMethod.type === "DilithiumKey2025"
    ? "DilithiumSignature2025"
    : verificationMethod.type === "Ed25519VerificationKey2020"
    ? "Ed25519Signature2020"
    : null;

  if (!algorithm) {
    return { ok: false, error: "unsupported verification method" };
  }

  const didKeySegment = bundle.did.split(":").pop();
  if (!didKeySegment) {
    return { ok: false, error: "invalid did" };
  }

  const publicKeyBase64 = base64UrlToBase64(didKeySegment);

  if (verificationMethod.publicKeyBase64 !== publicKeyBase64) {
    return { ok: false, error: "did document key mismatch" };
  }

  const canonical = canonicalizeAssertionPayload(assertion);
  const verified = await verify(
    { publicKey: publicKeyBase64, algorithm },
    canonical,
    bundle.assertion_signatureBase64
  );

  if (!verified) {
    return { ok: false, error: "invalid assertion signature" };
  }

  return { ok: true, did: bundle.did };
}
