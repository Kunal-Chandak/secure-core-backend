import crypto from "crypto";

/**
 * SHA-256 hash utility
 * Used for:
 * - roomHash
 * - fileHash
 *
 * @param {string} input
 * @returns {string} hex-encoded SHA-256 hash
 */
export function sha256(input) {
  if (typeof input !== "string") {
    throw new Error("sha256 input must be a string");
  }

  return crypto
    .createHash("sha256")
    .update(input, "utf8")
    .digest("hex");
}
