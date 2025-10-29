import { bytesToBase64, base64ToBytes } from "./base64.js";
import { generateKeyPair, sign, verify } from "./index.js";

// PQ Session Security - Quantum-resistant session key exchange and authentication

export interface PQSessionKeys {
  sessionId: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  algorithm: string;
  created: number;
  expires: number;
}

export interface PQSharedSecret {
  secret: Uint8Array;
  sessionId: string;
  algorithm: string;
}

export interface PQTemporalProof {
  timestamp: number;
  challenge: string;
  signature: string;
  sessionId: string;
}

export interface PQSessionAttestation {
  sessionId: string;
  publicKey: Uint8Array;
  signature: string;
  algorithm: string;
  timestamp: number;
}

/**
 * Generate fresh PQ session keys for each authentication request
 * This prevents replay attacks and provides forward secrecy
 */
export async function createAuthSession(): Promise<PQSessionKeys> {
  const sessionId = crypto.getRandomValues(new Uint8Array(16));
  const sessionIdBase64 = bytesToBase64(sessionId);

  // Generate fresh Dilithium keypair for this session
  const keyPair = await generateKeyPair("DilithiumSignature2025");

  const now = Date.now();
  const expires = now + (5 * 60 * 1000); // 5 minute session

  return {
    sessionId: sessionIdBase64,
    publicKey: keyPair.publicKey as Uint8Array,
    privateKey: keyPair.privateKey as Uint8Array,
    algorithm: 'PQ-Session-v1',
    created: now,
    expires
  };
}

/**
 * Perform quantum-resistant key exchange with relying party
 * Simplified key exchange using PQ signatures for authentication
 */
export async function performPQKeyExchange(
  sessionKeys: PQSessionKeys,
  challenge: string
): Promise<PQSharedSecret> {
  // Create a shared secret based on session key and challenge
  // In a full implementation, this would use Kyber for actual key exchange
  const challengeBytes = new TextEncoder().encode(challenge);
  const combined = new Uint8Array(sessionKeys.privateKey.length + challengeBytes.length);
  combined.set(sessionKeys.privateKey);
  combined.set(challengeBytes, sessionKeys.privateKey.length);

  // Hash to create shared secret (simplified - production would use Kyber)
  const secret = new Uint8Array(
    await crypto.subtle.digest('SHA-256', combined as unknown as ArrayBuffer)
  );

  return {
    secret,
    sessionId: sessionKeys.sessionId,
    algorithm: 'PQ-KeyExchange-v1'
  };
}

/**
 * Sign authentication response with fresh session keys
 */
export async function signAuthResponse(
  response: any,
  sessionKeys: PQSessionKeys
): Promise<string> {
  const responseJson = JSON.stringify(response);
  const responseBytes = new TextEncoder().encode(responseJson);

  // Sign with session private key
  const signature = await sign(
    {
      privateKey: sessionKeys.privateKey,
      algorithm: "DilithiumSignature2025"
    },
    responseJson
  );

  return signature;
}

/**
 * Verify authentication response signature
 */
export async function verifyAuthResponse(
  response: any,
  signature: string,
  sessionPublicKey: Uint8Array
): Promise<boolean> {
  try {
    const responseJson = JSON.stringify(response);

    return await verify(
      {
        publicKey: sessionPublicKey,
        algorithm: "DilithiumSignature2025"
      },
      responseJson,
      signature
    );
  } catch (error) {
    console.error('Auth response verification failed:', error);
    return false;
  }
}

/**
 * Create temporal proof to prevent replay attacks
 */
export async function createTemporalProof(
  challenge: string,
  sessionKeys: PQSessionKeys
): Promise<PQTemporalProof> {
  const timestamp = Date.now();
  const timestampStr = timestamp.toString();

  // Create proof data: challenge + timestamp + sessionId
  const proofData = `${challenge}:${timestampStr}:${sessionKeys.sessionId}`;
  const signature = await sign(
    {
      privateKey: sessionKeys.privateKey,
      algorithm: "DilithiumSignature2025"
    },
    proofData
  );

  return {
    timestamp,
    challenge,
    signature,
    sessionId: sessionKeys.sessionId
  };
}

/**
 * Verify temporal proof and check for replay attacks
 */
export async function verifyTemporalProof(
  proof: PQTemporalProof,
  sessionPublicKey: Uint8Array,
  maxAge: number = 300000 // 5 minutes
): Promise<boolean> {
  try {
    // Check timestamp is not too old
    const now = Date.now();
    if (now - proof.timestamp > maxAge) {
      console.error('Temporal proof expired');
      return false;
    }

    // Recreate proof data
    const proofData = `${proof.challenge}:${proof.timestamp.toString()}:${proof.sessionId}`;

    // Verify signature
    return await verify(
      {
        publicKey: sessionPublicKey,
        algorithm: "DilithiumSignature2025"
      },
      proofData,
      proof.signature
    );
  } catch (error) {
    console.error('Temporal proof verification failed:', error);
    return false;
  }
}

/**
 * Create session attestation for additional security
 */
export async function createSessionAttestation(
  sessionKeys: PQSessionKeys
): Promise<PQSessionAttestation> {
  const timestamp = Date.now();
  const attestationData = `${sessionKeys.sessionId}:${timestamp}:${bytesToBase64(sessionKeys.publicKey)}`;

  const signature = await sign(
    {
      privateKey: sessionKeys.privateKey,
      algorithm: "DilithiumSignature2025"
    },
    attestationData
  );

  return {
    sessionId: sessionKeys.sessionId,
    publicKey: sessionKeys.publicKey,
    signature,
    algorithm: 'PQ-Attestation-v1',
    timestamp
  };
}

/**
 * Verify session attestation
 */
export async function verifySessionAttestation(
  attestation: PQSessionAttestation
): Promise<boolean> {
  try {
    // Handle both Uint8Array and base64 string public keys
    const publicKeyBytes = typeof attestation.publicKey === 'string'
      ? new Uint8Array(atob(attestation.publicKey) as unknown as ArrayLike<number>)
      : attestation.publicKey;

    const attestationData = `${attestation.sessionId}:${attestation.timestamp}:${bytesToBase64(publicKeyBytes)}`;

    return await verify(
      {
        publicKey: publicKeyBytes,
        algorithm: "DilithiumSignature2025"
      },
      attestationData,
      attestation.signature
    );
  } catch (error) {
    console.error('Session attestation verification failed:', error);
    return false;
  }
}

/**
 * Check if session keys are still valid
 */
export function isSessionValid(sessionKeys: PQSessionKeys): boolean {
  const now = Date.now();
  return now >= sessionKeys.created && now <= sessionKeys.expires;
}

/**
 * Generate quantum-resistant nonce for challenges
 */
export async function generatePQNonce(): Promise<string> {
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  return bytesToBase64(nonce);
}

/**
 * Create challenge with quantum-resistant properties
 */
export async function createPQChallenge(
  relyingParty: string,
  sessionId: string
): Promise<string> {
  const nonce = await generatePQNonce();
  const timestamp = Date.now();

  // Create challenge: relyingParty + sessionId + nonce + timestamp
  const challengeData = `${relyingParty}:${sessionId}:${nonce}:${timestamp}`;

  return challengeData;
}
