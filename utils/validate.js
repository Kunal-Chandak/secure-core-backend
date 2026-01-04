import redis from "../redis/client.js";

/**
 * Check if a Redis key exists and has TTL > 0
 * @param {string} key - Redis key
 * @returns {Promise<boolean>} true if exists and not expired
 */
export async function isKeyValid(key) {
  const exists = await redis.exists(key);
  if (!exists) return false;

  const ttl = await redis.ttl(key);
  return ttl > 0;
}
