import { base64ToBytes, bytesToBase64, utf8ToBytes } from "./base64.js";

// Dilithium implementation using @noble/post-quantum (FIPS 204 ML-DSA)
// This provides NIST-standard post-quantum digital signatures

// Dynamic import to avoid bundling issues in different environments
let ml_dsa: any = null;

export async function loadMLDSA() {
  if (!ml_dsa) {
    try {
      // Load real @noble/post-quantum Dilithium (NIST FIPS 204 ML-DSA)
      const pq = await import('@noble/post-quantum/ml-dsa.js');
      // Use ml_dsa65 for optimal security/performance balance
      ml_dsa = pq.ml_dsa65;
      console.log('Successfully loaded real Dilithium ML-DSA-65 (NIST FIPS 204)');
    } catch (error) {
      console.error('CRITICAL: Failed to load @noble/post-quantum Dilithium:', error instanceof Error ? error.message : String(error));
      throw new Error('Real post-quantum cryptography unavailable - cannot proceed with insecure fallbacks');
    }
  }
  return ml_dsa;
}

export interface DilithiumKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  publicKeyBase64: string;
  privateKeyBase64: string;
}

// Generate Dilithium keypair using FIPS 204 ML-DSA
export async function generateDilithiumKeyPair(): Promise<DilithiumKeyPair> {
  const dsa = await loadMLDSA();
  const keyPair = await dsa.keygen();

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.secretKey,
    publicKeyBase64: bytesToBase64(keyPair.publicKey),
    privateKeyBase64: bytesToBase64(keyPair.secretKey)
  };
}

// Sign message using Dilithium private key
export async function signDilithium(
  privateKeyBase64: string,
  message: string
): Promise<string> {
  const dsa = await loadMLDSA();
  const privateKey = base64ToBytes(privateKeyBase64);
  const messageBytes = utf8ToBytes(message);

  const signature = await dsa.sign(messageBytes, privateKey);
  return bytesToBase64(signature);
}

// Verify Dilithium signature
export async function verifyDilithium(
  publicKeyBase64: string,
  message: string,
  signatureBase64: string
): Promise<boolean> {
  try {
    const dsa = await loadMLDSA();
    const publicKey = base64ToBytes(publicKeyBase64);
    const messageBytes = utf8ToBytes(message);
    const signature = base64ToBytes(signatureBase64);

    return await dsa.verify(signature, messageBytes, publicKey);
  } catch (error) {
    console.error('Dilithium verification failed:', error);
    return false;
  }
}
