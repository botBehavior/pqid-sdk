import { bytesToBase64 } from "./base64.js";
import {
  PQSessionKeys,
  createAuthSession,
  signAuthResponse,
  verifyAuthResponse,
  createTemporalProof,
  verifyTemporalProof,
  createSessionAttestation,
  verifySessionAttestation,
  createPQChallenge
} from "./pq-session-security.js";

// Enhanced PQ Authentication Bundle with quantum-resistant protections

export interface PQAuthBundle {
  // Core authentication data
  did: string;
  claims: Record<string, any>;
  credentials: any[];

  // PQ Session security
  sessionKeys: {
    sessionId: string;
    publicKey: string; // Base64 encoded
    algorithm: string;
    expires: number;
  };

  // Temporal proof (anti-replay)
  temporalProof: {
    timestamp: number;
    challenge: string;
    signature: string;
    sessionId: string;
  };

  // Session attestation
  sessionAttestation: {
    sessionId: string;
    publicKey: string;
    signature: string;
    algorithm: string;
    timestamp: number;
  };

  // Bundle integrity
  integrityProof: {
    dataHash: string;
    signature: string;
    algorithm: string;
  };

  // Bundle metadata
  metadata: {
    specVersion: string;
    created: number;
    expires: number;
    relyingParty: string;
  };
}

export interface PQBundleVerification {
  valid: boolean;
  errors: string[];
  warnings: string[];
  sessionValid: boolean;
  temporalValid: boolean;
  integrityValid: boolean;
}

/**
 * Create enhanced PQ authentication bundle with quantum-resistant protections
 */
export async function createPQAuthBundle(
  did: string,
  claims: Record<string, any>,
  credentials: any[],
  relyingParty: string
): Promise<{ bundle: PQAuthBundle; sessionKeys: PQSessionKeys }> {
  // Create fresh session keys
  const sessionKeys = await createAuthSession();

  // Generate challenge for this authentication
  const challenge = await createPQChallenge(relyingParty, sessionKeys.sessionId);

  // Create temporal proof
  const temporalProof = await createTemporalProof(challenge, sessionKeys);

  // Create session attestation
  const sessionAttestationRaw = await createSessionAttestation(sessionKeys);
  const sessionAttestation = {
    ...sessionAttestationRaw,
    publicKey: bytesToBase64(sessionAttestationRaw.publicKey)
  };

  // Create bundle data structure
  const bundleData = {
    did,
    claims,
    credentials,
    sessionKeys: {
      sessionId: sessionKeys.sessionId,
      publicKey: bytesToBase64(sessionKeys.publicKey),
      algorithm: sessionKeys.algorithm,
      expires: sessionKeys.expires
    },
    temporalProof,
    sessionAttestation,
    metadata: {
      specVersion: 'pqid-auth-0.2.0',
      created: Date.now(),
      expires: sessionKeys.expires,
      relyingParty
    }
  };

  // Create integrity proof for the entire bundle
  const integrityProof = await createBundleIntegrityProof(bundleData, sessionKeys);

  const bundle: PQAuthBundle = {
    ...bundleData,
    integrityProof
  };

  return { bundle, sessionKeys };
}

/**
 * Create bundle integrity proof using session keys
 */
async function createBundleIntegrityProof(
  bundleData: any,
  sessionKeys: PQSessionKeys
): Promise<{ dataHash: string; signature: string; algorithm: string }> {
  // Create canonical bundle data (exclude integrity proof)
  const canonicalData = {
    did: bundleData.did,
    claims: bundleData.claims,
    credentials: bundleData.credentials,
    sessionKeys: bundleData.sessionKeys,
    temporalProof: bundleData.temporalProof,
    sessionAttestation: bundleData.sessionAttestation,
    metadata: bundleData.metadata
  };

  const dataJson = JSON.stringify(canonicalData, Object.keys(canonicalData).sort());

  // Hash the canonical data
  const dataHashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(dataJson) as unknown as ArrayBuffer);
  const dataHash = bytesToBase64(new Uint8Array(dataHashBuffer));

  // Sign the hash with session key
  const signature = await signAuthResponse({ dataHash }, sessionKeys);

  return {
    dataHash,
    signature,
    algorithm: 'PQ-Integrity-v1'
  };
}

/**
 * Verify PQ authentication bundle comprehensively
 */
export async function verifyPQAuthBundle(
  bundle: PQAuthBundle,
  expectedRelyingParty?: string
): Promise<PQBundleVerification> {
  const errors: string[] = [];
  const warnings: string[] = [];

  let sessionValid = false;
  let temporalValid = false;
  let integrityValid = false;

  try {
    // 1. Verify bundle structure and metadata
    if (!bundle.metadata || bundle.metadata.specVersion !== 'pqid-auth-0.2.0') {
      errors.push('Invalid or missing bundle metadata');
    }

    // 2. Check expiration
    const now = Date.now();
    if (bundle.metadata.expires < now) {
      errors.push('Bundle has expired');
    }

    if (expectedRelyingParty && bundle.metadata.relyingParty !== expectedRelyingParty) {
      errors.push('Relying party mismatch');
    }

    // 3. Verify session validity
    sessionValid = bundle.sessionKeys.expires > now;
    if (!sessionValid) {
      errors.push('Session has expired');
    }

    // 4. Verify temporal proof (anti-replay)
    const sessionPublicKey = new Uint8Array(atob(bundle.sessionKeys.publicKey) as unknown as ArrayLike<number>);
    temporalValid = await verifyTemporalProof(bundle.temporalProof, sessionPublicKey);
    if (!temporalValid) {
      errors.push('Temporal proof verification failed');
    }

    // 5. Verify session attestation
    const attestationForVerification = {
      ...bundle.sessionAttestation,
      publicKey: sessionPublicKey
    };
    const attestationValid = await verifySessionAttestation(attestationForVerification);
    if (!attestationValid) {
      errors.push('Session attestation verification failed');
    }

    // 6. Verify bundle integrity
    integrityValid = await verifyBundleIntegrity(bundle);
    if (!integrityValid) {
      errors.push('Bundle integrity verification failed');
    }

    // 7. Additional security checks
    if (bundle.credentials.length === 0) {
      warnings.push('No credentials provided in bundle');
    }

    if (!bundle.did || !bundle.did.startsWith('did:pqid:')) {
      errors.push('Invalid or missing PQ DID');
    }

    // Check for reasonable timestamp (within last 24 hours)
    const oneDayAgo = now - (24 * 60 * 60 * 1000);
    if (bundle.metadata.created < oneDayAgo) {
      warnings.push('Bundle was created more than 24 hours ago');
    }

  } catch (error) {
    errors.push(`Bundle verification error: ${error instanceof Error ? error.message : String(error)}`);
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    sessionValid,
    temporalValid,
    integrityValid
  };
}

/**
 * Verify bundle integrity proof
 */
async function verifyBundleIntegrity(bundle: PQAuthBundle): Promise<boolean> {
  try {
    // Recreate canonical data
    const canonicalData = {
      did: bundle.did,
      claims: bundle.claims,
      credentials: bundle.credentials,
      sessionKeys: bundle.sessionKeys,
      temporalProof: bundle.temporalProof,
      sessionAttestation: bundle.sessionAttestation,
      metadata: bundle.metadata
    };

    const dataJson = JSON.stringify(canonicalData, Object.keys(canonicalData).sort());

    // Hash the canonical data
    const dataHashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(dataJson) as unknown as ArrayBuffer);
    const computedDataHash = bytesToBase64(new Uint8Array(dataHashBuffer));

    // Verify the hash matches
    if (computedDataHash !== bundle.integrityProof.dataHash) {
      return false;
    }

    // Verify the signature
    const sessionPublicKey = new Uint8Array(atob(bundle.sessionKeys.publicKey) as unknown as ArrayLike<number>);
    return await verifyAuthResponse(
      { dataHash: bundle.integrityProof.dataHash },
      bundle.integrityProof.signature,
      sessionPublicKey
    );
  } catch (error) {
    console.error('Bundle integrity verification failed:', error);
    return false;
  }
}


/**
 * Extract claims from verified bundle
 */
export function extractClaimsFromBundle(bundle: PQAuthBundle): Record<string, any> {
  return bundle.claims || {};
}

/**
 * Get bundle security metadata
 */
export function getBundleSecurityMetadata(bundle: PQAuthBundle): {
  sessionId: string;
  expires: number;
  algorithm: string;
  created: number;
} {
  return {
    sessionId: bundle.sessionKeys.sessionId,
    expires: bundle.sessionKeys.expires,
    algorithm: bundle.sessionKeys.algorithm,
    created: bundle.metadata.created
  };
}
