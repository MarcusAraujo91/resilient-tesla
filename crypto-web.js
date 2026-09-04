/**
 * Web Cryptographic Engine (Browser & Isomorphic Node testing)
 * File: crypto-web.js
 */

const HEADER_HEX_LENGTH = 56;
const DEFAULT_MASTER_KEY = "hermes-default-zero-plaintext-master-key-2026";

function bufToHex(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

function hexToBuf(hex) {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex string length");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

async function deriveClientKey(secret = DEFAULT_MASTER_KEY) {
  const enc = new TextEncoder();
  const rawHash = await globalThis.crypto.subtle.digest("SHA-256", enc.encode(secret));
  return await globalThis.crypto.subtle.importKey(
    "raw",
    rawHash,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptPayloadClient(data, secret = DEFAULT_MASTER_KEY) {
  const plaintext = typeof data === "string" ? data : JSON.stringify(data);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveClientKey(secret);

  const enc = new TextEncoder();
  const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    key,
    enc.encode(plaintext)
  );

  const totalLen = encryptedBuffer.byteLength;
  const cipherBytes = new Uint8Array(encryptedBuffer, 0, totalLen - 16);
  const tagBytes = new Uint8Array(encryptedBuffer, totalLen - 16, 16);

  return bufToHex(iv) + bufToHex(tagBytes) + bufToHex(cipherBytes);
}

async function decryptPayloadClient(hexPayload, secret = DEFAULT_MASTER_KEY) {
  if (typeof hexPayload !== "string" || hexPayload.length < HEADER_HEX_LENGTH) {
    throw new Error("Invalid ciphertext packet format: minimum 56 hex chars required");
  }

  const iv = hexToBuf(hexPayload.slice(0, 24));
  const tag = hexToBuf(hexPayload.slice(24, 56));
  const ciphertext = hexToBuf(hexPayload.slice(56));

  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  const key = await deriveClientKey(secret);
  const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    key,
    combined
  );

  const decryptedStr = new TextDecoder().decode(decryptedBuffer);
  try {
    return JSON.parse(decryptedStr);
  } catch {
    return decryptedStr;
  }
}

function timingSafeEqClientSync(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const maxLen = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < maxLen; i++) {
    const charA = i < a.length ? a.charCodeAt(i) : 0;
    const charB = i < b.length ? b.charCodeAt(i) : 0;
    diff |= charA ^ charB;
  }
  return diff === 0;
}

async function timingSafeEqClient(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const enc = new TextEncoder();
  const hashA = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", enc.encode(a)));
  const hashB = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", enc.encode(b)));
  let diff = a.length ^ b.length;
  for (let i = 0; i < hashA.length; i++) {
    diff |= hashA[i] ^ hashB[i];
  }
  return diff === 0;
}

async function envelopeFormPayload(formData, secret = DEFAULT_MASTER_KEY) {
  const encrypted = await encryptPayloadClient(formData, secret);
  return { data: { encrypted } };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    bufToHex,
    hexToBuf,
    deriveClientKey,
    encryptPayloadClient,
    decryptPayloadClient,
    timingSafeEqClientSync,
    timingSafeEqClient,
    envelopeFormPayload,
    encryptClientPayload: encryptPayloadClient,
    decryptClientPayload: decryptPayloadClient,
  };
}
