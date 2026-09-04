const crypto = require("node:crypto");

const HEADER_HEX_LENGTH = 56;
const DEFAULT_TTL_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const DEFAULT_MASTER_KEY = "hermes-default-zero-plaintext-master-key-2026";

function getMasterKey(secret) {
  return secret || process.env.APP_MASTER_KEY || process.env.SITE_PASSWORD || DEFAULT_MASTER_KEY;
}

function deriveKey(secret) {
  return crypto.createHash("sha256").update(getMasterKey(secret), "utf8").digest();
}

/**
 * PILAR 3: Comparador em tempo constante com proteção contra vazamento de tamanho de buffer
 */
function timingSafeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function encryptPayload(payload, secret) {
  const plaintext = typeof payload === "string" ? payload : JSON.stringify(payload);
  const key = deriveKey(secret);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return iv.toString("hex") + tag.toString("hex") + ciphertext.toString("hex");
}

function decryptPayload(hexPacket, secret) {
  if (typeof hexPacket !== "string" || hexPacket.length < HEADER_HEX_LENGTH) {
    throw new Error("Invalid ciphertext packet format: minimum 56 hex chars required");
  }

  const key = deriveKey(secret);
  const iv = Buffer.from(hexPacket.slice(0, 24), "hex");
  const tag = Buffer.from(hexPacket.slice(24, 56), "hex");
  const ciphertext = Buffer.from(hexPacket.slice(56), "hex");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  const decryptedStr = decipher.update(ciphertext, undefined, "utf8") + decipher.final("utf8");
  try {
    return JSON.parse(decryptedStr);
  } catch {
    return decryptedStr;
  }
}

function unpackEncryptedOrPlain(input, secret) {
  if (!input) return input;
  if (typeof input === "object" && "encrypted" in input && typeof input.encrypted === "string") {
    return decryptPayload(input.encrypted, secret);
  }
  if (typeof input === "string" && input.length >= HEADER_HEX_LENGTH && /^[0-9a-fA-F]+$/.test(input)) {
    try {
      return decryptPayload(input, secret);
    } catch {
      return input;
    }
  }
  return input;
}

// PILAR 2: Tokens com TTL assinados (base64url + hmac_sha256)
function toBase64Url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function fromBase64Url(str) {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) base64 += "=";
  return Buffer.from(base64, "base64");
}

function issueSignedToken(payload, ttlMs = DEFAULT_TTL_MS, secret) {
  const master = getMasterKey(secret);
  const now = Date.now();
  const exp = now + ttlMs;

  const dataContainer = { data: payload, iat: now, exp };
  const jsonStr = JSON.stringify(dataContainer);
  const encodedPayload = toBase64Url(Buffer.from(jsonStr, "utf8"));

  const signature = crypto.createHmac("sha256", master).update(encodedPayload).digest("hex");
  return `${encodedPayload}.${signature}`;
}

function verifySignedToken(token, secret) {
  if (typeof token !== "string" || !token.includes(".")) {
    return { valid: false, reason: "Formato de token inválido" };
  }

  const parts = token.split(".");
  if (parts.length !== 2) return { valid: false, reason: "Token malformado" };

  const [encodedPayload, signature] = parts;
  const master = getMasterKey(secret);
  const expectedSignature = crypto.createHmac("sha256", master).update(encodedPayload).digest("hex");

  if (!timingSafeEq(signature, expectedSignature)) {
    return { valid: false, reason: "Assinatura criptográfica inválida" };
  }

  try {
    const rawJson = fromBase64Url(encodedPayload).toString("utf8");
    const container = JSON.parse(rawJson);
    if (Date.now() > container.exp) {
      return { valid: false, expired: true, reason: "Token expirado" };
    }
    return { valid: true, data: container.data };
  } catch (err) {
    return { valid: false, reason: err.message };
  }
}

// PILAR 2: One-Time Tokens (OTT) de Queima Única
const ottStore = new Map();

function issueOneTimeToken(payload, ttlMs = DEFAULT_TTL_MS, secret) {
  const master = getMasterKey(secret);
  const now = Date.now();
  const exp = now + ttlMs;
  const id = crypto.randomBytes(16).toString("hex");

  const message = `ott_${id}_${exp}`;
  const hmac = crypto.createHmac("sha256", master).update(message).digest("hex");
  const token = `${message}_${hmac}`;

  ottStore.set(id, { payload, exp, consumed: false });
  return { token, ottId: id, exp };
}

function consumeOneTimeToken(token, secret) {
  if (typeof token !== "string" || !token.startsWith("ott_")) {
    return { valid: false, reason: "Token OTT malformado" };
  }

  const parts = token.split("_");
  if (parts.length !== 4) return { valid: false, reason: "Estrutura do OTT inválida" };

  const [, id, expStr, hmac] = parts;
  const exp = parseInt(expStr, 10);
  const master = getMasterKey(secret);

  const message = `ott_${id}_${exp}`;
  const expectedHmac = crypto.createHmac("sha256", master).update(message).digest("hex");

  if (!timingSafeEq(hmac, expectedHmac)) {
    return { valid: false, reason: "Assinatura HMAC do OTT inválida" };
  }

  const now = Date.now();
  if (now > exp) {
    ottStore.delete(id);
    return { valid: false, expired: true, reason: "OTT expirado" };
  }

  const record = ottStore.get(id);
  if (!record || record.consumed) {
    return { valid: false, consumed: true, reason: "Token já foi consumido" };
  }

  record.consumed = true;
  ottStore.set(id, record);
  return { valid: true, data: record.payload };
}

// PILAR 4: Anti-Brute Force Guard
const bruteForceStore = new Map();

class BruteForceGuard {
  static getStatus(id) {
    const record = bruteForceStore.get(id);
    if (!record) return { locked: false, remainingMs: 0, attempts: 0 };
    const now = Date.now();
    if (record.lockedUntil > now) {
      return { locked: true, remainingMs: record.lockedUntil - now, attempts: record.count };
    }
    if (record.lockedUntil > 0 && record.lockedUntil <= now) {
      bruteForceStore.delete(id);
      return { locked: false, remainingMs: 0, attempts: 0 };
    }
    return { locked: false, remainingMs: 0, attempts: record.count };
  }

  static recordFailure(id) {
    const now = Date.now();
    let record = bruteForceStore.get(id);
    if (!record) {
      record = { count: 1, lastFailure: now, lockedUntil: 0 };
    } else {
      record.count += 1;
      record.lastFailure = now;
    }

    if (record.count >= MAX_ATTEMPTS) {
      record.lockedUntil = now + LOCKOUT_MS;
      bruteForceStore.set(id, record);
      return { locked: true, remainingMs: LOCKOUT_MS, attempts: record.count };
    }

    bruteForceStore.set(id, record);
    return { locked: false, remainingMs: 0, attempts: record.count };
  }

  static recordSuccess(id) {
    bruteForceStore.delete(id);
  }
}

module.exports = {
  getMasterKey,
  deriveKey,
  timingSafeEq,
  encryptPayload,
  decryptPayload,
  unpackEncryptedOrPlain,
  issueSignedToken,
  verifySignedToken,
  issueOneTimeToken,
  consumeOneTimeToken,
  BruteForceGuard,
};
