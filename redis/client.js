import Redis from "ioredis";
import dotenv from "dotenv";

dotenv.config();

const redis = new Redis(process.env.REDIS_URL, {
  tls: {
    rejectUnauthorized: false,
  },
  connectTimeout: 10_000,  
  maxRetriesPerRequest: 3,
  retryStrategy(times) {
    return Math.min(times * 200, 2000);
  },
});


redis.on("connect", () => {
  console.log("Redis connected (Upstash)");
});

redis.on("error", (err) => {
  console.error("Redis error:", err.message);
});

export default redis;
