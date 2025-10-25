#!/usr/bin/env node

// Debug script to understand what's happening with PQ crypto

import { generateDilithiumKeyPair } from './dist/crypto/dilithium.js';

async function debugCrypto() {
  console.log('🔍 Debugging PQ Crypto\n');

  try {
    console.log('Generating key pair...');
    const keyPair = await generateDilithiumKeyPair();

    console.log('Key pair generated successfully!');
    console.log(`Public key length: ${keyPair.publicKey.length} bytes`);
    console.log(`Private key length: ${keyPair.privateKey.length} bytes`);
    console.log(`Public key base64 length: ${keyPair.publicKeyBase64.length} chars`);
    console.log(`Private key base64 length: ${keyPair.privateKeyBase64.length} chars`);

    console.log('\nFirst 50 chars of public key base64:');
    console.log(keyPair.publicKeyBase64.substring(0, 50));

    console.log('\nFirst 50 chars of private key base64:');
    console.log(keyPair.privateKeyBase64.substring(0, 50));

    // Check expected lengths
    const expectedPubLength = 1952; // ML-DSA-65 public key
    const expectedPrivLength = 4032; // ML-DSA-65 private key
    const expectedPubBase64Length = Math.ceil(expectedPubLength * 4 / 3);
    const expectedPrivBase64Length = Math.ceil(expectedPrivLength * 4 / 3);

    console.log(`\nExpected public key length: ${expectedPubLength} bytes`);
    console.log(`Expected private key length: ${expectedPrivLength} bytes`);
    console.log(`Expected public base64 length: ~${expectedPubBase64Length} chars`);
    console.log(`Expected private base64 length: ~${expectedPrivBase64Length} chars`);

  } catch (error) {
    console.error('Debug failed:', error);
    console.error('Stack:', error.stack);
  }
}

debugCrypto();
