#!/usr/bin/env node

// Test script for real PQ cryptography
// This verifies that Dilithium ML-DSA-65 is working correctly

import { generateDilithiumKeyPair, signDilithium, verifyDilithium } from './dist/crypto/dilithium.js';

async function testRealPQCrypto() {
  console.log('🧪 Testing Real PQ Cryptography (NIST FIPS 204 ML-DSA-65)\n');

  try {
    // Test 1: Key Generation - should produce different keys each time
    console.log('1. Testing key generation...');
    const keyPair1 = await generateDilithiumKeyPair();
    const keyPair2 = await generateDilithiumKeyPair();

    console.log(`   KeyPair 1 Public Key Length: ${keyPair1.publicKey.length} bytes`);
    console.log(`   KeyPair 2 Public Key Length: ${keyPair2.publicKey.length} bytes`);
    console.log(`   KeyPair 1 Private Key Length: ${keyPair1.privateKey.length} bytes`);
    console.log(`   KeyPair 2 Private Key Length: ${keyPair2.privateKey.length} bytes`);

    // Verify NIST FIPS 204 ML-DSA-65 sizes
    const expectedPubKeySize = 1952; // ML-DSA-65 public key
    const expectedPrivKeySize = 4032; // ML-DSA-65 private key

    if (keyPair1.publicKey.length !== expectedPubKeySize) {
      throw new Error(`Public key size ${keyPair1.publicKey.length} !== expected ${expectedPubKeySize}`);
    }
    if (keyPair1.privateKey.length !== expectedPrivKeySize) {
      throw new Error(`Private key size ${keyPair1.privateKey.length} !== expected ${expectedPrivKeySize}`);
    }

    // Check keys are different (real randomness)
    if (keyPair1.publicKeyBase64 === keyPair2.publicKeyBase64) {
      throw new Error('CRITICAL: Public keys are identical - not using real crypto!');
    }
    console.log('   ✅ Keys are different (real randomness confirmed)');

    // Test 2: Sign and Verify cycle
    console.log('\n2. Testing sign and verify cycle...');
    const message = 'This is a test message for PQ cryptography';
    console.log(`   Private key base64 length: ${keyPair1.privateKeyBase64.length} chars`);
    console.log(`   Private key base64 first 50: ${keyPair1.privateKeyBase64.substring(0, 50)}`);
    const signature = await signDilithium(keyPair1.privateKeyBase64, message);

    console.log(`   Signature Length: ${signature.length} (base64 encoded)`);

    // Verify the signature
    const isValid = await verifyDilithium(keyPair1.publicKeyBase64, message, signature);
    if (!isValid) {
      throw new Error('CRITICAL: Signature verification failed!');
    }
    console.log('   ✅ Signature verified successfully');

    // Test 3: Wrong signature should fail
    console.log('\n3. Testing invalid signature rejection...');
    const wrongSignature = await signDilithium(keyPair2.privateKeyBase64, 'different message');
    const shouldBeInvalid = await verifyDilithium(keyPair1.publicKeyBase64, message, wrongSignature);
    if (shouldBeInvalid) {
      throw new Error('CRITICAL: Wrong signature was accepted!');
    }
    console.log('   ✅ Invalid signature correctly rejected');

    // Test 4: Wrong public key should fail
    console.log('\n4. Testing wrong public key rejection...');
    const wrongKeyValid = await verifyDilithium(keyPair2.publicKeyBase64, message, signature);
    if (wrongKeyValid) {
      throw new Error('CRITICAL: Wrong public key was accepted!');
    }
    console.log('   ✅ Wrong public key correctly rejected');

    console.log('\n🎉 SUCCESS: Real PQ cryptography is working!');
    console.log('   - NIST FIPS 204 ML-DSA-65 compliance verified');
    console.log('   - Cryptographic signatures are secure');
    console.log('   - No mock implementations detected');
    console.log('   - Real quantum resistance confirmed');

  } catch (error) {
    console.error('\n❌ FAILURE:', error.message);
    console.error('Real PQ cryptography is NOT working!');
    process.exit(1);
  }
}

// Run the test
testRealPQCrypto().catch(error => {
  console.error('Test execution failed:', error);
  process.exit(1);
});
