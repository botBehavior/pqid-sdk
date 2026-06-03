export type ClaimType =
  // Legacy demo credentials
  | "age_over_18"
  | "good_standing"
  | "account_age_days_over_30"
  // OAuth-based credentials
  | "email_verified"
  | "google_account_age_over_365"
  | "github_account_age_over_180"
  | "apple_user"
  | "human_user";

export type SignatureAlgorithm =
  | "DilithiumSignature2025"
  | "Ed25519Signature2020";

export interface DIDVerificationMethod {
  id: string;
  type: "DilithiumKey2025" | "KyberKey2025" | "Ed25519VerificationKey2020";
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
    type: SignatureAlgorithm;
    created: string;
    verificationMethod: string;
    signatureBase64: string;
  };
}

export interface CredentialProof {
  type: SignatureAlgorithm;
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
  validUntil: string;
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
  spec_version: string;
}

export interface AuthResponseBundle {
  did: string;
  did_document: DIDDocument;
  assertion: AuthAssertion;
  assertion_signatureBase64: string;
  credentials: Credential[];
  crypto_algorithm?: SignatureAlgorithm; // Algorithm used for signing
}

export interface AssertionVerificationResult {
  ok: boolean;
  did?: string;
  error?: string;
}

export interface CredentialVerificationError {
  claim_type: ClaimType | string;
  reason: string;
}

export interface CredentialVerificationResult {
  ok: boolean;
  claims: Partial<Record<ClaimType, boolean | string | number>>;
  errors: CredentialVerificationError[];
}

export type AssertionCheckResult = AssertionVerificationResult;
export interface CryptoKeyPair {
  algorithm: SignatureAlgorithm;
  publicKey: Uint8Array | CryptoKey;
  privateKey: Uint8Array | CryptoKey;
  publicKeyBase64: string;
  privateKeyBase64?: string;
}

export type VerifiedClaimsResult = CredentialVerificationResult;
