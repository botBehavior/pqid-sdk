import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { base64ToBytes, bytesToBase64, utf8ToBytes } from "./base64.js";
let nobleDSA = ml_dsa65;
function loadMLDSA() {
    if (!nobleDSA) {
        throw new Error("Dilithium ML-DSA module unavailable");
    }
    return nobleDSA;
}
export async function loadMLDSAInterface() {
    const dsa = loadMLDSA();
    return {
        keygen: async () => {
            const keypair = await dsa.keygen();
            return {
                publicKey: keypair.publicKey,
                secretKey: keypair.secretKey
            };
        },
        sign: async (message, secretKey) => {
            return await dsa.sign(message, secretKey);
        },
        verify: async (signature, message, publicKey) => {
            return await dsa.verify(signature, message, publicKey);
        }
    };
}
// Generate Dilithium keypair using FIPS 204 ML-DSA
export async function generateDilithiumKeyPair() {
    const dsa = await loadMLDSAInterface();
    const keyPair = await dsa.keygen();
    return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.secretKey,
        publicKeyBase64: bytesToBase64(keyPair.publicKey),
        privateKeyBase64: bytesToBase64(keyPair.secretKey)
    };
}
// Sign message using Dilithium private key
export async function signDilithium(privateKeyBase64, message) {
    const dsa = await loadMLDSAInterface();
    const privateKey = base64ToBytes(privateKeyBase64);
    const messageBytes = utf8ToBytes(message);
    const signature = await dsa.sign(messageBytes, privateKey);
    return bytesToBase64(signature);
}
// Verify Dilithium signature
export async function verifyDilithium(publicKeyBase64, message, signatureBase64) {
    try {
        const dsa = await loadMLDSAInterface();
        const publicKey = base64ToBytes(publicKeyBase64);
        const messageBytes = utf8ToBytes(message);
        const signature = base64ToBytes(signatureBase64);
        return await dsa.verify(signature, messageBytes, publicKey);
    }
    catch (error) {
        console.error('Dilithium verification failed:', error);
        return false;
    }
}
