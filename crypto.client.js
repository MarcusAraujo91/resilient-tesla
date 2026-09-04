/**
 * Client-side cryptographic engine using native Web Crypto API (globalThis.crypto.subtle).
 */

const HEADER_HEX_LENGTH = 56;

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

async function deriveClientKey(secret) {
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

async function encryptClientPayload(payload, secret) {
  const plaintext = typeof payload === "string" ? payload : JSON.stringify(payload);
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

async function decryptClientPayload(hexPacket, secret) {
  if (typeof hexPacket !== "string" || hexPacket.length < HEADER_HEX_LENGTH) {
    throw new Error("Invalid ciphertext packet format: minimum 56 hex chars required");
  }

  const iv = hexToBuf(hexPacket.slice(0, 24));
  const tag = hexToBuf(hexPacket.slice(24, 56));
  const ciphertext = hexToBuf(hexPacket.slice(56));

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

async function envelopeFormPayload(formData, secret) {
  const encrypted = await encryptClientPayload(formData, secret);
  return { data: { encrypted } };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    bufToHex,
    hexToBuf,
    deriveClientKey,
    encryptClientPayload,
    decryptClientPayload,
    envelopeFormPayload,
  };
}
