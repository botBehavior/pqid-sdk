import { base64ToBase64Url } from "../crypto/base64.js";
import { signEd25519 } from "../crypto/ed25519.js";
import { ClaimType, Credential } from "../types.js";
import { canonicalizeCredentialPayload } from "../utils/canonicalize.js";

const DAY_IN_MS = 24 * 60 * 60 * 1000;

const DEV_ISSUER_PRIVATE_KEY_PKCS8_BASE64 =
  "MC4CAQAwBQYDK2VwBCIEIC7AD2uBGyI6eSVtaElV4okuwgFIrOlM08fr4fdsj03u";
const DEV_ISSUER_PUBLIC_KEY_BASE64 =
  "vFFiszaHlrH9+ebEtu32moOdc0lhMn97g2tuVMFgvcM=";

export const DEV_ISSUER_DID = "did:pqid-issuer:dev";
export const DEV_ISSUER_PUBLIC_KEY = base64ToBase64Url(
  DEV_ISSUER_PUBLIC_KEY_BASE64
);

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
  const payload = canonicalizeCredentialPayload(credential);
  const signatureBase64 = await signEd25519(
    DEV_ISSUER_PRIVATE_KEY_PKCS8_BASE64,
    payload
  );

  credential.proof.signatureBase64 = signatureBase64;
  return credential;
}

export function getIssuerPublicKey(did: string): string | undefined {
  if (did === DEV_ISSUER_DID) {
    return DEV_ISSUER_PUBLIC_KEY_BASE64;
  }

  return undefined;
}
