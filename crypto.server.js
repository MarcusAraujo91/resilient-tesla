const crypto = require("node:crypto");

const HEADER_HEX_LENGTH = 56;
const DEFAULT_TTL_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

function deriveKey(secret) {
  const master = secret || process.env.APP_MASTER_KEY || "hermes-default-zero-plaintext-master-key-2026";
  return crypto.createHash("sha256").update(master, "utf8").digest();
}

function timingSafeEq(a, b) {
  const bufA = typeof a === "string" ? Buffer.from(a, "utf8") : a;
  const bufB = typeof b === "string" ? Buffer.from(b, "utf8") : b;

  const hashA = crypto.createHash("sha256").update(bufA).digest();
  const hashB = crypto.createHash("sha256").update(bufB).digest();
  const hashesMatch = crypto.timingSafeEqual(hashA, hashB);

  let lenDiff = bufA.length ^ bufB.length;
  for (let i = 0; i < Math.min(bufA.length, bufB.length); i++) {
    lenDiff |= bufA[i] ^ bufB[i];
  }

  return hashesMatch && lenDiff === 0;
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

const consumedOttStore = new Map();

function issueEphemeralToken(data, ttlMs = DEFAULT_TTL_MS, options) {
  const now = Date.now();
  const exp = now + ttlMs;
  const nonce = crypto.randomBytes(8).toString("hex");
  const jti = options?.jti || crypto.randomBytes(16).toString("hex");

  const payload = {
    data,
    iat: now,
    exp,
    nonce,
    jti,
  };

  const token = encryptPayload(payload, options?.secret);
  return { token, exp, jti };
}

function verifyEphemeralToken(tokenHex, options) {
  let payload;
  try {
    payload = decryptPayload(tokenHex, options?.secret);
  } catch (err) {
    return { valid: false, status: "invalid", reason: err.message };
  }

  const now = Date.now();
  if (now > payload.exp) {
    return { valid: false, status: "expired", reason: "Token has expired" };
  }

  if (payload.jti) {
    if (consumedOttStore.has(payload.jti)) {
      return { valid: false, status: "consumed", reason: "Token has already been consumed" };
    }
    if (options?.autoConsumeOtt) {
      consumedOttStore.set(payload.jti, payload.exp);
    }
  }

  return {
    valid: true,
    status: "valid",
    data: payload.data,
    exp: payload.exp,
    jti: payload.jti,
  };
}

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
  deriveKey,
  timingSafeEq,
  encryptPayload,
  decryptPayload,
  issueEphemeralToken,
  verifyEphemeralToken,
  BruteForceGuard,
};
