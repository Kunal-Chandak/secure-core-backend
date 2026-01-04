import crypto from "crypto";

/**
 * Derive a key using PBKDF2
 * @param {string} code - Room code
 * @param {Buffer} salt - Salt
 * @param {number} iterations - Number of iterations (default: 100000)
 * @param {number} keyLength - Desired key length in bytes (default: 32)
 * @returns {Buffer} Derived key
 */
export function pbkdf2(code, salt, iterations = 100000, keyLength = 32) {
  return crypto.pbkdf2Sync(code, salt, iterations, keyLength, 'sha256');
}

/**
 * Derive a key using HKDF (HMAC-based Key Derivation Function)
 * @param {Buffer} inputKey - Input key material
 * @param {Buffer} salt - Salt (can be empty)
 * @param {string} info - Context information
 * @param {number} length - Desired output key length in bytes
 * @returns {Buffer} Derived key
 */
export function hkdf(inputKey, salt, info, length = 32) {
  // HKDF-Extract
  const prk = crypto.createHmac("sha256", salt).update(inputKey).digest();

  // HKDF-Expand
  const infoBuffer = Buffer.from(info, "utf8");
  const n = Math.ceil(length / 32); // SHA-256 output is 32 bytes
  const t = [];
  let t_prev = Buffer.alloc(0);

  for (let i = 1; i <= n; i++) {
    const counter = Buffer.from([i]);
    const input = Buffer.concat([t_prev, infoBuffer, counter]);
    t_prev = crypto.createHmac("sha256", prk).update(input).digest();
    t.push(t_prev);
  }

  return Buffer.concat(t).slice(0, length);
}