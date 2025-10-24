import { base64ToBytes, bytesToBase64, utf8ToBytes } from "./base64.js";

function getSubtleCrypto(): SubtleCrypto {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    return crypto.subtle;
  }

  throw new Error("WebCrypto subtle API is not available in this environment");
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer;
}

export async function generateEd25519KeyPair(): Promise<{
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeyBase64: string;
  privateKeyPkcs8Base64: string;
}> {
  const subtle = getSubtleCrypto();
  const keyPair = (await subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;

  const publicKeyRaw = new Uint8Array(await subtle.exportKey("raw", keyPair.publicKey));
  const privateKeyPkcs8 = new Uint8Array(
    await subtle.exportKey("pkcs8", keyPair.privateKey)
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicKeyBase64: bytesToBase64(publicKeyRaw),
    privateKeyPkcs8Base64: bytesToBase64(privateKeyPkcs8)
  };
}

export async function importEd25519PrivateKey(
  privateKeyPkcs8Base64: string
): Promise<CryptoKey> {
  const subtle = getSubtleCrypto();
  const keyBytes = base64ToBytes(privateKeyPkcs8Base64);
  return subtle.importKey(
    "pkcs8",
    toArrayBuffer(keyBytes),
    { name: "Ed25519" },
    true,
    ["sign"]
  );
}

export async function importEd25519PublicKey(
  rawPublicKeyBase64: string
): Promise<CryptoKey> {
  const subtle = getSubtleCrypto();
  const keyBytes = base64ToBytes(rawPublicKeyBase64);
  return subtle.importKey(
    "raw",
    toArrayBuffer(keyBytes),
    { name: "Ed25519" },
    true,
    ["verify"]
  );
}

export async function signEd25519WithKey(
  privateKey: CryptoKey,
  message: string
): Promise<string> {
  const subtle = getSubtleCrypto();
  const messageBytes = utf8ToBytes(message);
  const signature = await subtle.sign(
    "Ed25519",
    privateKey,
    toArrayBuffer(messageBytes)
  );
  return bytesToBase64(new Uint8Array(signature));
}

export async function signEd25519(
  privateKeyPkcs8Base64: string,
  message: string
): Promise<string> {
  const privateKey = await importEd25519PrivateKey(privateKeyPkcs8Base64);
  return signEd25519WithKey(privateKey, message);
}

export async function verifyEd25519(
  rawPublicKeyBase64: string,
  message: string,
  signatureBase64: string
): Promise<boolean> {
  const publicKey = await importEd25519PublicKey(rawPublicKeyBase64);
  return verifyEd25519WithKey(publicKey, message, signatureBase64);
}

export async function verifyEd25519WithKey(
  publicKey: CryptoKey,
  message: string,
  signatureBase64: string
): Promise<boolean> {
  const subtle = getSubtleCrypto();
  const signatureBytes = base64ToBytes(signatureBase64);
  const messageBytes = utf8ToBytes(message);
  return subtle.verify(
    "Ed25519",
    publicKey,
    toArrayBuffer(signatureBytes),
    toArrayBuffer(messageBytes)
  );
}
