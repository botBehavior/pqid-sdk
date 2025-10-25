#!/usr/bin/env node

// Debug verification issue

import { generateDilithiumKeyPair, signDilithium, verifyDilithium } from './dist/crypto/dilithium.js';

async function debugVerify() {
  console.log('🔍 Debugging Verification Issue\n');

  try {
    const keyPair = await generateDilithiumKeyPair();
    const message = 'Test message for verification';

    console.log('Generated key pair');
    console.log(`Public key length: ${keyPair.publicKey.length}`);
    console.log(`Private key length: ${keyPair.privateKey.length}`);

    console.log('Signing message...');
    const signature = await signDilithium(keyPair.privateKeyBase64, message);
    console.log(`Signature base64 length: ${signature.length}`);

    // Decode signature to check length
    const { base64ToBytes } = await import('./dist/crypto/base64.js');
    const signatureBytes = base64ToBytes(signature);
    console.log(`Signature bytes length: ${signatureBytes.length} (expected: ~3309)`);

    console.log('Verifying signature...');
    const isValid = await verifyDilithium(keyPair.publicKeyBase64, message, signature);
    console.log(`Verification result: ${isValid}`);

    if (!isValid) {
      console.log('Verification failed - checking with direct Dilithium API...');

      // Try direct verification
      const pq = await import('@noble/post-quantum/ml-dsa.js');
      const dsa = pq.ml_dsa65;

      const { utf8ToBytes } = await import('./dist/crypto/base64.js');
      const messageBytes = utf8ToBytes(message);
      const publicKey = base64ToBytes(keyPair.publicKeyBase64);

      console.log(`Direct verify params:`);
      console.log(`  message length: ${messageBytes.length}`);
      console.log(`  signature length: ${signatureBytes.length}`);
      console.log(`  public key length: ${publicKey.length}`);

      const directResult = await dsa.verify(messageBytes, signatureBytes, publicKey);
      console.log(`Direct verification result: ${directResult}`);
    }

  } catch (error) {
    console.error('Debug verify failed:', error);
    console.error('Stack:', error.stack);
  }
}

debugVerify();
