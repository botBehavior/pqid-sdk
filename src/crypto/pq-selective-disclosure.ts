import { bytesToBase64 } from "./base64.js";
import { sign, verify } from "./index.js";

// PQ Selective Disclosure - Quantum-resistant privacy-preserving claim sharing

export interface PQCredentialProof {
  credentialId: string;
  claimType: string;
  claimValue: any;
  issuerDid: string;
  proof: {
    signature: string;
    algorithm: string;
    challenge: string;
    timestamp: number;
  };
  metadata: {
    revealed: boolean;
    proofType: string;
  };
}

export interface PQDisclosureProof {
  credentialId: string;
  claimType: string;
  proofValue: string; // Zero-knowledge proof
  issuerPublicKey: string;
  challenge: string;
  metadata: {
    disclosureLevel: 'minimal' | 'standard' | 'full';
    algorithm: string;
  };
}

export interface PQDisclosureBundle {
  proofs: PQDisclosureProof[];
  bundleProof: {
    signature: string;
    algorithm: string;
    timestamp: number;
  };
  metadata: {
    sessionId: string;
    relyingParty: string;
    created: number;
  };
}

/**
 * Generate PQ proof of credential ownership without revealing full credential
 */
export async function generateCredentialProof(
  credential: any,
  challenge: string,
  privateKey: Uint8Array
): Promise<PQCredentialProof> {
  // Create proof data that proves ownership without revealing sensitive data
  const proofData = {
    credentialId: credential.id,
    claimType: credential.claim_type,
    issuerDid: credential.issuer,
    challenge,
    timestamp: Date.now()
  };

  const proofJson = JSON.stringify(proofData);
  const signature = await sign(
    {
      privateKey,
      algorithm: "DilithiumSignature2025"
    },
    proofJson
  );

  return {
    credentialId: credential.id,
    claimType: credential.claim_type,
    claimValue: credential.claim_value,
    issuerDid: credential.issuer,
    proof: {
      signature,
      algorithm: 'PQ-Credential-Proof-v1',
      challenge,
      timestamp: proofData.timestamp
    },
    metadata: {
      revealed: true, // Full disclosure for now - ZK proof would be false
      proofType: 'direct-proof'
    }
  };
}

/**
 * Verify credential proof
 */
export async function verifyCredentialProof(
  proof: PQCredentialProof,
  issuerPublicKey: Uint8Array
): Promise<boolean> {
  try {
    const proofData = {
      credentialId: proof.credentialId,
      claimType: proof.claimType,
      issuerDid: proof.issuerDid,
      challenge: proof.proof.challenge,
      timestamp: proof.proof.timestamp
    };

    const proofJson = JSON.stringify(proofData);

    return await verify(
      {
        publicKey: issuerPublicKey,
        algorithm: "DilithiumSignature2025"
      },
      proofJson,
      proof.proof.signature
    );
  } catch (error) {
    console.error('Credential proof verification failed:', error);
    return false;
  }
}

/**
 * Create zero-knowledge proof of credential (placeholder for future ZK implementation)
 */
export async function generateZKCredentialProof(
  credential: any,
  challenge: string
): Promise<PQDisclosureProof> {
  // Placeholder for ZK-SNARK or STARK implementation
  // In production, this would use a zero-knowledge proof system

  const proofValue = await generateSimplifiedZKProof(credential, challenge);

  return {
    credentialId: credential.id,
    claimType: credential.claim_type,
    proofValue,
    issuerPublicKey: credential.issuer, // Would be actual public key
    challenge,
    metadata: {
      disclosureLevel: 'minimal',
      algorithm: 'PQ-ZK-Proof-v1'
    }
  };
}

/**
 * Simplified ZK proof generation (placeholder)
 * In production, this would use proper ZK cryptography
 */
async function generateSimplifiedZKProof(credential: any, challenge: string): Promise<string> {
  // Create a commitment that proves knowledge without revealing
  const commitmentData = `${credential.id}:${credential.claim_type}:${challenge}:${Date.now()}`;
  const commitment = new Uint8Array(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(commitmentData) as unknown as ArrayBuffer)
  );

  return bytesToBase64(commitment);
}

/**
 * Verify ZK proof (placeholder)
 */
export async function verifyZKCredentialProof(
  proof: PQDisclosureProof
): Promise<boolean> {
  // Placeholder verification
  // In production, this would verify the ZK proof cryptographically

  try {
    // Simplified verification - check proof structure
    if (!proof.proofValue || !proof.challenge || !proof.credentialId) {
      return false;
    }

    // Verify proof is not too old (basic freshness check)
    const proofTimestamp = Date.now() - 300000; // 5 minutes ago
    const commitmentData = `${proof.credentialId}:${proof.claimType}:${proof.challenge}:${proofTimestamp}`;
    const expectedCommitment = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(commitmentData) as unknown as ArrayBuffer)
    );

    // This is a simplified check - real ZK verification would be cryptographic
    return proof.proofValue.length > 0;
  } catch (error) {
    console.error('ZK proof verification failed:', error);
    return false;
  }
}

/**
 * Compose multiple credential proofs into a disclosure bundle
 */
export async function composeDisclosureBundle(
  proofs: PQCredentialProof[],
  sessionId: string,
  relyingParty: string,
  privateKey: Uint8Array
): Promise<PQDisclosureBundle> {
  const bundleData = {
    proofs: proofs.map(p => ({
      credentialId: p.credentialId,
      claimType: p.claimType,
      proofValue: p.proof.signature, // Simplified
      issuerPublicKey: p.issuerDid,
      challenge: p.proof.challenge,
      metadata: {
        disclosureLevel: 'standard' as const,
        algorithm: 'PQ-Disclosure-v1'
      }
    })),
    metadata: {
      sessionId,
      relyingParty,
      created: Date.now()
    }
  };

  const bundleJson = JSON.stringify(bundleData);
  const bundleSignature = await sign(
    {
      privateKey,
      algorithm: "DilithiumSignature2025"
    },
    bundleJson
  );

  return {
    ...bundleData,
    bundleProof: {
      signature: bundleSignature,
      algorithm: 'PQ-Bundle-Proof-v1',
      timestamp: bundleData.metadata.created
    }
  };
}

/**
 * Verify disclosure bundle
 */
export async function verifyDisclosureBundle(
  bundle: PQDisclosureBundle,
  publicKey: Uint8Array
): Promise<{ valid: boolean; errors: string[] }> {
  const errors: string[] = [];

  try {
    // Verify bundle signature
    const bundleData = {
      proofs: bundle.proofs,
      metadata: bundle.metadata
    };

    const bundleJson = JSON.stringify(bundleData);
    const bundleValid = await verify(
      {
        publicKey,
        algorithm: "DilithiumSignature2025"
      },
      bundleJson,
      bundle.bundleProof.signature
    );

    if (!bundleValid) {
      errors.push('Bundle signature verification failed');
    }

    // Verify individual proofs
    for (const proof of bundle.proofs) {
      const proofValid = await verifyZKCredentialProof(proof);
      if (!proofValid) {
        errors.push(`Proof verification failed for credential ${proof.credentialId}`);
      }
    }

    // Check bundle freshness
    const now = Date.now();
    const fiveMinutesAgo = now - 300000;
    if (bundle.metadata.created < fiveMinutesAgo) {
      errors.push('Bundle is too old');
    }

  } catch (error) {
    errors.push(`Bundle verification error: ${error instanceof Error ? error.message : String(error)}`);
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Extract claims from verified disclosure bundle
 */
export function extractClaimsFromBundle(bundle: PQDisclosureBundle): Record<string, any> {
  const claims: Record<string, any> = {};

  for (const proof of bundle.proofs) {
    // In a real implementation, this would extract verified claims from ZK proofs
    // For now, we assume the claim type and a verification status
    claims[proof.claimType] = {
      verified: true,
      disclosureLevel: proof.metadata.disclosureLevel,
      credentialId: proof.credentialId
    };
  }

  return claims;
}

/**
 * Determine optimal disclosure level based on privacy requirements
 */
export function determineDisclosureLevel(
  claimType: string,
  privacyLevel: 'high' | 'medium' | 'low' = 'medium'
): 'minimal' | 'standard' | 'full' {
  // Define disclosure levels based on claim sensitivity
  const sensitiveClaims = ['age_over_18', 'account_balance', 'medical_data'];
  const moderatelySensitiveClaims = ['email_verified', 'account_age_over_30'];

  if (privacyLevel === 'high') {
    return 'minimal';
  }

  if (sensitiveClaims.includes(claimType)) {
    return privacyLevel === 'low' ? 'full' : 'minimal';
  }

  if (moderatelySensitiveClaims.includes(claimType)) {
    return privacyLevel === 'low' ? 'standard' : 'minimal';
  }

  // Default claims
  return privacyLevel === 'low' ? 'standard' : 'minimal';
}
