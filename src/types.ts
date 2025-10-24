export type ClaimType =
  | "age_over_18"
  | "good_standing"
  | "account_age_days_over_30";

export interface DIDVerificationMethod {
  id: string;
  type: "DilithiumKey2025" | "KyberKey2025";
  controller: string;
  publicKeyBase64: string;
}

export interface DIDDocument {
  id: string;
  "@context": string[];
  verificationMethod: DIDVerificationMethod[];
  authentication: string[];
  service?: {
    id: string;
    type: string;
    serviceEndpoint: string;
  }[];
  proof?: {
    type: "DilithiumSignature2025";
    created: string;
    verificationMethod: string;
    signatureBase64: string;
  };
}

export interface CredentialProof {
  type: "DilithiumSignature2025";
  created: string;
  verificationMethod: string;
  signatureBase64: string;
}

export interface Credential {
  id: string;
  issuer: string;
  subject: string;
  claim_type: ClaimType;
  claim_value: boolean | string | number;
  issuanceDate: string;
  validUntil?: string;
  proof: CredentialProof;
}

export interface RequestedClaim {
  type: ClaimType;
  purpose?: string;
}

export interface AuthChallenge {
  nonce: string;
  audience: string;
  requested_claims: RequestedClaim[];
  timestamp: string;
}

export interface AuthAssertion {
  challenge: string;
  audience: string;
  timestamp: string;
}

export interface AuthResponseBundle {
  did: string;
  did_document: DIDDocument;
  assertion: AuthAssertion;
  assertion_signatureBase64: string;
  credentials: Credential[];
}
