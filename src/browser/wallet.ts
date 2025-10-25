// This module is intended to run in a browser / wallet context.
// It MUST NOT be imported in a trusted backend environment.

import { base64ToBase64Url } from "../crypto/base64.js";
import {
  generateEd25519KeyPair,
  signEd25519WithKey
} from "../crypto/ed25519.js";
import { generateKeyPair, sign, KeyPair } from "../crypto/index.js";
import {
  AuthAssertion,
  AuthResponseBundle,
  ClaimType,
  Credential,
  RequestedClaim,
  DIDDocument,
  SignatureAlgorithm
} from "../types.js";
import {
  ASSERTION_SPEC_VERSION,
  canonicalizeAssertionPayload
} from "../utils/canonicalize.js";
import { issueCredential } from "../issuer/devIssuer.js";

export interface RequestAuthOptions {
  requested_claims: RequestedClaim[];
  challenge?: string;
  audience?: string;
}

const DEFAULT_CLAIM_VALUES: Record<ClaimType, boolean | string | number> = {
  // Legacy demo credentials
  age_over_18: true,
  good_standing: true,
  account_age_days_over_30: 60,
  // OAuth-based credentials
  email_verified: true,
  google_account_age_over_365: true,
  github_account_age_over_180: true,
  apple_user: true,
  human_user: true
};

function getDefaultClaimValue(type: ClaimType): boolean | string | number {
  return DEFAULT_CLAIM_VALUES[type] ?? true;
}

interface InternalWalletState {
  did: string;
  didDocument: DIDDocument;
  verificationMethodId: string;
  keyPair: KeyPair; // Updated to use abstracted KeyPair
  publicKeyBase64: string;
  publicKeyBase64Url: string;
}

let walletStatePromise: Promise<InternalWalletState> | null = null;

async function createWalletState(): Promise<InternalWalletState> {
  // Use PQ crypto by default, fallback to Ed25519 for compatibility
  const keyPair = await generateKeyPair("DilithiumSignature2025");
  const publicKeyBase64Url = base64ToBase64Url(keyPair.publicKeyBase64);

  // Update DID generation to support PQ
  const did = `did:pqid:${publicKeyBase64Url}`;
  const verificationMethodId = `${did}#key-1`;

  // Determine key type based on algorithm
  const keyType = keyPair.algorithm === "DilithiumSignature2025"
    ? "DilithiumKey2025"
    : "Ed25519VerificationKey2020";

  const didDocument: DIDDocument = {
    id: did,
    "@context": ["https://www.w3.org/ns/did/v1"],
    verificationMethod: [
      {
        id: verificationMethodId,
        type: keyType,
        controller: did,
        publicKeyBase64: keyPair.publicKeyBase64
      }
    ],
    authentication: [verificationMethodId]
  };

  return {
    did,
    didDocument,
    verificationMethodId,
    keyPair,
    publicKeyBase64: keyPair.publicKeyBase64,
    publicKeyBase64Url
  };
}

async function getInternalWalletState(): Promise<InternalWalletState> {
  if (!walletStatePromise) {
    walletStatePromise = createWalletState();
  }
  return walletStatePromise;
}

export async function getWalletState(): Promise<{
  did: string;
  publicKeyBase64Url: string;
  verificationMethodId: string;
}> {
  const state = await getInternalWalletState();
  return {
    did: state.did,
    publicKeyBase64Url: state.publicKeyBase64Url,
    verificationMethodId: state.verificationMethodId
  };
}

export async function signAssertionPayload(fields: {
  challenge: string;
  audience: string;
  timestamp: string;
  spec_version: string;
}): Promise<string> {
  const state = await getInternalWalletState();
  const canonical = canonicalizeAssertionPayload(fields);
  return sign({ privateKey: state.keyPair.privateKey, algorithm: state.keyPair.algorithm }, canonical);
}

export async function getDidDocument(): Promise<DIDDocument> {
  const state = await getInternalWalletState();
  return state.didDocument;
}

export async function getWalletDid(): Promise<string> {
  const state = await getInternalWalletState();
  return state.did;
}

export async function getWalletPublicKeyBase64Url(): Promise<string> {
  const state = await getInternalWalletState();
  return state.publicKeyBase64Url;
}

export async function getWalletVerificationMethodId(): Promise<string> {
  const state = await getInternalWalletState();
  return state.verificationMethodId;
}

export const PQID_AUTH_SPEC_VERSION = ASSERTION_SPEC_VERSION;

export async function getAuthBundle(
  opts: RequestAuthOptions
): Promise<AuthResponseBundle> {
  const now = new Date().toISOString();
  const { did } = await getInternalWalletState();
  const did_document = await getDidDocument();

  const challenge =
    opts.challenge ||
    (typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : `nonce-${Math.random().toString(36).slice(2)}`);
  const audience = opts.audience ?? window.location.origin;

  const assertion: AuthAssertion = {
    challenge,
    audience,
    timestamp: now,
    spec_version: ASSERTION_SPEC_VERSION
  };

  const assertion_signatureBase64 = await signAssertionPayload(assertion);

  const credentials: Credential[] = [];
  const seenTypes = new Set<ClaimType>();
  for (const claim of opts.requested_claims ?? []) {
    if (seenTypes.has(claim.type)) {
      continue;
    }
    seenTypes.add(claim.type);
    credentials.push(
      await issueCredential(did, claim.type, getDefaultClaimValue(claim.type))
    );
  }

  return {
    did,
    did_document,
    assertion,
    assertion_signatureBase64,
    credentials
  };
}
