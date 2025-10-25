#!/usr/bin/env node

// Debug direct sign and verify without base64 conversion

async function debugDirectSignVerify() {
  console.log('🔍 Debugging Direct Sign/Verify\n');

  try {
    const pq = await import('@noble/post-quantum/ml-dsa.js');
    const dsa = pq.ml_dsa65;

    console.log('Generating key pair...');
    const keyPair = await dsa.keygen();
    console.log(`Public key: ${keyPair.publicKey.length} bytes`);
    console.log(`Private key: ${keyPair.secretKey.length} bytes`);

    const message = new TextEncoder().encode('Test message');
    console.log(`Message: ${message.length} bytes`);

    console.log('Signing...');
    const signature = await dsa.sign(message, keyPair.secretKey);
    console.log(`Signature: ${signature.length} bytes`);

    console.log('Verifying...');
    const isValid = await dsa.verify(message, signature, keyPair.publicKey);
    console.log(`Result: ${isValid}`);

    if (!isValid) {
      console.log('FAILED: Even direct verification failed!');
      console.log('Checking if signature is corrupted...');

      // Try signing again with the same key
      const signature2 = await dsa.sign(message, keyPair.secretKey);
      const isValid2 = await dsa.verify(message, signature2, keyPair.publicKey);
      console.log(`Second attempt result: ${isValid2}`);

      // Check if signatures are different (they should be for Dilithium)
      const sig1Hex = Array.from(signature.slice(0, 10)).map(b => b.toString(16).padStart(2, '0')).join('');
      const sig2Hex = Array.from(signature2.slice(0, 10)).map(b => b.toString(16).padStart(2, '0')).join('');
      console.log(`First sig start: ${sig1Hex}`);
      console.log(`Second sig start: ${sig2Hex}`);
      console.log(`Signatures different: ${sig1Hex !== sig2Hex}`);
    }

  } catch (error) {
    console.error('Debug failed:', error);
    console.error('Stack:', error.stack);
  }
}

debugDirectSignVerify();
