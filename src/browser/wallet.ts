// This module is intended to run in a browser / wallet context.
// It MUST NOT be imported in a trusted backend environment.

import { base64ToBase64Url } from "../crypto/base64.js";
import {
  generateEd25519KeyPair,
  signEd25519WithKey
} from "../crypto/ed25519.js";
import {
  AuthAssertion,
  AuthResponseBundle,
  ClaimType,
  Credential,
  RequestedClaim,
  DIDDocument
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
  age_over_18: true,
  good_standing: true,
  account_age_days_over_30: 60
};

function getDefaultClaimValue(type: ClaimType): boolean | string | number {
  return DEFAULT_CLAIM_VALUES[type] ?? true;
}

interface InternalWalletState {
  did: string;
  didDocument: DIDDocument;
  verificationMethodId: string;
  privateKey: CryptoKey;
  publicKeyBase64: string;
  publicKeyBase64Url: string;
}

let walletStatePromise: Promise<InternalWalletState> | null = null;

async function createWalletState(): Promise<InternalWalletState> {
  const { privateKey, publicKey, publicKeyBase64 } = await generateEd25519KeyPair();
  const publicKeyBase64Url = base64ToBase64Url(publicKeyBase64);
  const did = `did:pqid-dev:${publicKeyBase64Url}`;
  const verificationMethodId = `${did}#key-1`;

  const didDocument: DIDDocument = {
    id: did,
    "@context": ["https://www.w3.org/ns/did/v1"],
    verificationMethod: [
      {
        id: verificationMethodId,
        type: "Ed25519VerificationKey2020",
        controller: did,
        publicKeyBase64
      }
    ],
    authentication: [verificationMethodId]
  };

  return {
    did,
    didDocument,
    verificationMethodId,
    privateKey,
    publicKeyBase64,
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
  return signEd25519WithKey(state.privateKey, canonical);
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
