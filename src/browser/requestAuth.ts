import { AuthResponseBundle, Credential, RequestedClaim } from "../types";

/**
 * requestAuth
 *
 * Called by a relying party's frontend code.
 * Eventually this will talk to the PQID wallet extension via window.pqid.requestAuth(...)
 * and ask the user to approve sharing certain claims.
 *
 * For v0.1 this returns a stubbed AuthResponseBundle that matches the spec.
 */
export async function requestAuth(opts: {
  requested_claims: RequestedClaim[];
}): Promise<AuthResponseBundle> {
  const now = new Date().toISOString();

  const did = "did:pq:example123";

  const did_document = {
    id: did,
    "@context": ["https://www.w3.org/ns/did/v1"],
    verificationMethod: [],
    authentication: []
  };

  const assertion = {
    challenge: "stub-nonce",
    audience: window.location.origin,
    timestamp: now
  };

  const credentials: Credential[] = [
    {
      id: "urn:uuid:cred-1",
      issuer: "did:pq:issuer.local",
      subject: did,
      claim_type: "age_over_18",
      claim_value: true,
      issuanceDate: now,
      proof: {
        type: "DilithiumSignature2025",
        created: now,
        verificationMethod: "did:pq:issuer.local#sign",
        signatureBase64: "stub-issuer-sig"
      }
    }
  ];

  return {
    did,
    did_document,
    assertion,
    assertion_signatureBase64: "stub-user-sig",
    credentials
  };
}
