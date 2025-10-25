#!/usr/bin/env node

// Debug direct Dilithium usage

async function debugDirectDilithium() {
  console.log('🔍 Debugging Direct Dilithium Usage\n');

  try {
    // Load Dilithium directly
    const pq = await import('@noble/post-quantum/ml-dsa.js');
    const dsa = pq.ml_dsa65;

    console.log('Dilithium loaded successfully');

    // Generate keypair directly
    const keyPair = await dsa.keygen();
    console.log(`Direct keygen - public key length: ${keyPair.publicKey.length}`);
    console.log(`Direct keygen - secret key length: ${keyPair.secretKey.length}`);

    // Try to sign
    const message = new Uint8Array([1, 2, 3, 4, 5]);
    console.log(`Message length: ${message.length}`);

    // Try both orders
    console.log('Trying sign(secretKey, message)...');
    try {
      const signature1 = await dsa.sign(keyPair.secretKey, message);
      console.log(`Success with (secretKey, message): signature length ${signature1.length}`);
    } catch (error1) {
      console.log(`Failed with (secretKey, message):`, error1.message);

      console.log('Trying sign(message, secretKey)...');
      try {
        const signature = await dsa.sign(message, keyPair.secretKey);
        console.log(`Success with (message, secretKey): signature length ${signature.length}`);

        // Try verify
        console.log('Trying verify(message, signature, publicKey)...');
        const isValid = await dsa.verify(message, signature, keyPair.publicKey);
        console.log(`Verify result: ${isValid}`);

        return; // Success, exit

      } catch (error2) {
        console.log(`Failed with (message, secretKey):`, error2.message);
      }
    }
    console.log(`Verification result: ${isValid}`);

  } catch (error) {
    console.error('Direct Dilithium debug failed:', error);
    console.error('Error details:', error.message);
  }
}

debugDirectDilithium();
