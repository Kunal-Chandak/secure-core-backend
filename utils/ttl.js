/**
 * Convert expiry to seconds
 * Accepts number (seconds), string like '10m', '1h', '1d'
 * @param {number|string} expiry
 * @returns {number} seconds
 */
export function parseExpiry(expiry) {
  if (typeof expiry === "number") return expiry;

  const match = /^(\d+)([smhd])$/.exec(expiry);
  if (!match) throw new Error("Invalid expiry format");

  const value = parseInt(match[1]);
  const unit = match[2];

  switch (unit) {
    case "s":
      return value;
    case "m":
      return value * 60;
    case "h":
      return value * 3600;
    case "d":
      return value * 86400;
    default:
      throw new Error("Unknown time unit");
  }
}
