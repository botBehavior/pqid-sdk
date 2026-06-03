import { base64ToBase64Url } from "../crypto/base64.js";
import { signEd25519 } from "../crypto/ed25519.js";
import { generateKeyPair, sign } from "../crypto/index.js";
import { ClaimType, Credential, SignatureAlgorithm } from "../types.js";
import { canonicalizeCredentialPayload } from "../utils/canonicalize.js";

const DAY_IN_MS = 24 * 60 * 60 * 1000;

/**
 * Development issuer keys - now using PQ crypto for demonstration
 * These are for development only and must never be used in production.
 */
const DEV_ISSUER_ALGORITHM: SignatureAlgorithm = "DilithiumSignature2025";

// Generate PQ keypair for development issuer (cached)
let DEV_ISSUER_KEY_PAIR: any = null;

async function getDevIssuerKeyPair() {
  if (!DEV_ISSUER_KEY_PAIR) {
    DEV_ISSUER_KEY_PAIR = await generateKeyPair(DEV_ISSUER_ALGORITHM);
  }
  return DEV_ISSUER_KEY_PAIR;
}

export const DEV_ISSUER_DID = "did:pqid-issuer:dev";

// Lazy-loaded public key for backward compatibility
let DEV_ISSUER_PUBLIC_KEY: string | null = null;
export async function getDevIssuerPublicKey(): Promise<string> {
  if (!DEV_ISSUER_PUBLIC_KEY) {
    const keyPair = await getDevIssuerKeyPair();
    DEV_ISSUER_PUBLIC_KEY = keyPair.publicKeyBase64; // Return base64, not base64Url
  }
  return DEV_ISSUER_PUBLIC_KEY!;
}

// Backward compatibility - synchronous getter (returns promise now)
export const DEV_ISSUER_PUBLIC_KEY_PROMISE = getDevIssuerPublicKey();

const DEV_VERIFICATION_METHOD_ID = `${DEV_ISSUER_DID}#signing-key-1`;

function toBaseCredential(
  subjectDid: string,
  claim_type: ClaimType,
  value: boolean | string | number
): Credential {
  const issuanceDate = new Date().toISOString();
  const validUntil = new Date(Date.now() + DAY_IN_MS).toISOString();

  return {
    id: typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : `cred-${Math.random().toString(36).slice(2)}`,
    issuer: DEV_ISSUER_DID,
    subject: subjectDid,
    claim_type,
    claim_value: value,
    issuanceDate,
    validUntil,
    proof: {
      type: "Ed25519Signature2020",
      created: issuanceDate,
      verificationMethod: DEV_VERIFICATION_METHOD_ID,
      signatureBase64: ""
    }
  };
}

export async function issueCredential(
  subjectDid: string,
  claim_type: ClaimType,
  value: boolean | string | number
): Promise<Credential> {
  const credential = toBaseCredential(subjectDid, claim_type, value);
  const keyPair = await getDevIssuerKeyPair();

  credential.proof = {
    type: DEV_ISSUER_ALGORITHM,
    created: credential.issuanceDate,
    verificationMethod: DEV_VERIFICATION_METHOD_ID,
    signatureBase64: ""
  };

  const payload = canonicalizeCredentialPayload(credential);
  const signatureBase64 = await sign(
    { privateKey: keyPair.privateKey, algorithm: DEV_ISSUER_ALGORITHM },
    payload
  );

  credential.proof.signatureBase64 = signatureBase64;
  return credential;
}

export async function getIssuerPublicKey(did: string): Promise<string | undefined> {
  if (did === DEV_ISSUER_DID) {
    return await getDevIssuerPublicKey();
  }

  return undefined;
}

// Backward compatibility - sync version (may return undefined if not loaded yet)
export function getIssuerPublicKeySync(did: string): string | undefined {
  if (did === DEV_ISSUER_DID) {
    return DEV_ISSUER_PUBLIC_KEY || undefined;
  }

  return undefined;
}

export function checkCredentialExpiry(
  credential: Pick<Credential, "validUntil">,
  now: Date = new Date()
): { ok: boolean; reason?: string } {
  const expiryMs = Date.parse(credential.validUntil);

  if (Number.isNaN(expiryMs)) {
    return { ok: false, reason: "credential validUntil is invalid" };
  }

  if (expiryMs <= now.getTime()) {
    return { ok: false, reason: "credential expired" };
  }

  return { ok: true };
}
