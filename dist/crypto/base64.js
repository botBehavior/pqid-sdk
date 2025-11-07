// All helpers in this module produce unpadded base64url output when applicable to
// keep signatures deterministic across browser and server runtimes.
function hasBuffer() {
    return typeof Buffer !== "undefined";
}
export function bytesToBase64(bytes) {
    if (hasBuffer()) {
        return Buffer.from(bytes).toString("base64");
    }
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
export function base64ToBytes(base64) {
    if (hasBuffer()) {
        return new Uint8Array(Buffer.from(base64, "base64"));
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
export function base64ToBase64Url(base64) {
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}
export function base64UrlToBase64(base64Url) {
    let base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const pad = base64.length % 4;
    if (pad) {
        base64 += "=".repeat(4 - pad);
    }
    return base64;
}
export function bytesToBase64Url(bytes) {
    return base64ToBase64Url(bytesToBase64(bytes));
}
export function base64UrlToBytes(base64Url) {
    return base64ToBytes(base64UrlToBase64(base64Url));
}
export function utf8ToBytes(input) {
    return new TextEncoder().encode(input);
}
export function bytesToUtf8(bytes) {
    return new TextDecoder().decode(bytes);
}
