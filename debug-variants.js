#!/usr/bin/env node

// Test different Dilithium variants

async function testVariants() {
  console.log('🔍 Testing Dilithium Variants\n');

  try {
    const pq = await import('@noble/post-quantum/ml-dsa.js');

    const variants = ['ml_dsa44', 'ml_dsa65', 'ml_dsa87'];
    const message = new TextEncoder().encode('Test message for PQ crypto');

    for (const variant of variants) {
      if (pq[variant]) {
        console.log(`\nTesting ${variant}:`);
        const dsa = pq[variant];

        const keyPair = await dsa.keygen();
        console.log(`  Key sizes: pub=${keyPair.publicKey.length}, priv=${keyPair.secretKey.length}`);

        const signature = await dsa.sign(message, keyPair.secretKey);
        console.log(`  Signature size: ${signature.length}`);

        const isValid = await dsa.verify(message, signature, keyPair.publicKey);
        console.log(`  Verification: ${isValid}`);
      } else {
        console.log(`${variant}: not available`);
      }
    }

  } catch (error) {
    console.error('Variant test failed:', error);
  }
}

testVariants();
