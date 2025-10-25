#!/usr/bin/env node

// Debug base64 decoding issue

import { generateDilithiumKeyPair } from './dist/crypto/dilithium.js';
import { base64ToBytes } from './dist/crypto/base64.js';

async function debugBase64() {
  console.log('🔍 Debugging Base64 Decoding\n');

  try {
    const keyPair = await generateDilithiumKeyPair();

    console.log(`Original private key length: ${keyPair.privateKey.length} bytes`);
    console.log(`Base64 private key length: ${keyPair.privateKeyBase64.length} chars`);

    // Try to decode the base64
    const decoded = base64ToBytes(keyPair.privateKeyBase64);
    console.log(`Decoded length: ${decoded.length} bytes`);

    // Check if they match
    let matches = true;
    for (let i = 0; i < Math.min(keyPair.privateKey.length, decoded.length); i++) {
      if (keyPair.privateKey[i] !== decoded[i]) {
        matches = false;
        break;
      }
    }

    console.log(`Bytes match: ${matches}`);
    console.log(`Expected length: 4032, got: ${decoded.length}`);

  } catch (error) {
    console.error('Base64 debug failed:', error);
  }
}

debugBase64();
