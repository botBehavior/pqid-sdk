// This module is intended to run in a browser / wallet context.
// It MUST NOT be imported in a trusted backend environment.

import { base64ToBase64Url } from "../crypto/base64.js";
import {
  generateEd25519KeyPair,
  signEd25519WithKey
} from "../crypto/ed25519.js";
import { AuthAssertion, DIDDocument } from "../types.js";
import { ASSERTION_SPEC_VERSION, canonicalizeAssertion } from "../utils/canonicalize.js";

interface WalletState {
  did: string;
  didDocument: DIDDocument;
  verificationMethodId: string;
  privateKey: CryptoKey;
  publicKeyBase64: string;
  publicKeyBase64Url: string;
}

let walletStatePromise: Promise<WalletState> | null = null;

async function createWalletState(): Promise<WalletState> {
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

async function getWalletState(): Promise<WalletState> {
  if (!walletStatePromise) {
    walletStatePromise = createWalletState();
  }
  return walletStatePromise;
}

export async function signAssertion(
  challenge: string,
  audience: string,
  timestamp: string
): Promise<string> {
  const state = await getWalletState();
  const assertionPayload: AuthAssertion = {
    challenge,
    audience,
    timestamp,
    spec_version: ASSERTION_SPEC_VERSION
  };
  const canonical = canonicalizeAssertion(assertionPayload);
  return signEd25519WithKey(state.privateKey, canonical);
}

export async function getDidDocument(): Promise<DIDDocument> {
  const state = await getWalletState();
  return state.didDocument;
}

export async function getWalletDid(): Promise<string> {
  const state = await getWalletState();
  return state.did;
}

export async function getWalletPublicKeyBase64Url(): Promise<string> {
  const state = await getWalletState();
  return state.publicKeyBase64Url;
}

export async function getWalletVerificationMethodId(): Promise<string> {
  const state = await getWalletState();
  return state.verificationMethodId;
}
