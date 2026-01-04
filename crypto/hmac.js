import crypto from "crypto";

/**
 * Generate HMAC-SHA256 for a message using a secret key
 * @param {Buffer | string} key - Secret key
 * @param {Buffer | string} message - Message to authenticate
 * @returns {string} Hex HMAC
 */
export function generateHMAC(key, message) {
  return crypto
    .createHmac("sha256", key)
    .update(message)
    .digest("hex");
}

/**
 * Verify HMAC-SHA256
 * @param {Buffer | string} key - Secret key
 * @param {Buffer | string} message - Original message
 * @param {string} hmac - HMAC to verify
 * @returns {boolean} true if valid
 */
export function verifyHmac(key, message, hmac) {
  const computed = generateHMAC(key, message);
  // Use timingSafeEqual to prevent timing attacks
  const a = Buffer.from(computed, "hex");
  const b = Buffer.from(hmac, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
