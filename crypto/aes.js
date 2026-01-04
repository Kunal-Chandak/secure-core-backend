import crypto from "crypto";

/**
 * Encrypt data using AES-256-GCM
 * @param {Buffer} key - 32-byte key
 * @param {Buffer} plaintext - Data to encrypt
 * @param {Buffer} iv - 12-byte IV
 * @returns {Object} {ciphertext, authTag}
 */
export function encryptAESGCM(key, plaintext, iv) {
  const cipher = crypto.createCipherGCM("aes-256-gcm", key);
  cipher.setIV(iv);

  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  return { ciphertext, authTag };
}

/**
 * Decrypt data using AES-256-GCM
 * @param {Buffer} key - 32-byte key
 * @param {Buffer} ciphertext - Encrypted data
 * @param {Buffer} iv - 12-byte IV
 * @param {Buffer} authTag - Authentication tag
 * @returns {Buffer} Decrypted plaintext
 */
export function decryptAESGCM(key, ciphertext, iv, authTag) {
  const decipher = crypto.createDecipherGCM("aes-256-gcm", key);
  decipher.setIV(iv);
  decipher.setAuthTag(authTag);

  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);

  return plaintext;
}

/**
 * Generate a random 12-byte IV for AES-GCM
 * @returns {Buffer} 12-byte IV
 */
export function generateIV() {
  return crypto.randomBytes(12);
}

/**
 * Generate a random 32-byte key for AES-256
 * @returns {Buffer} 32-byte key
 */
export function generateAESKey() {
  return crypto.randomBytes(32);
}