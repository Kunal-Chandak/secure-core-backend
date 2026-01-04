import redis from "../redis/client.js";
import crypto from "crypto";
import { cleanupRoomFiles } from "./file.controller.js";

/**
 * POST /room/create
 * Stores room metadata with TTL
 */
export async function createRoom(req, res) {
  try {
    const { room_hash, room_code, room_salt, expiry, is_group, creator_id } = req.body;

    if (!room_hash || !room_code || !room_salt || !expiry || typeof is_group !== 'boolean' || !creator_id) {
      return res.status(400).json({
        success: false,
        error: "INVALID_REQUEST",
      });
    }

    if (typeof expiry !== "number" || expiry <= 0) {
      return res.status(400).json({
        success: false,
        error: "INVALID_EXPIRY",
      });
    }

    const redisKey = `room:${room_hash}`;

    const exists = await redis.exists(redisKey);
    if (exists) {
      return res.status(409).json({
        success: false,
        error: "ROOM_ALREADY_EXISTS",
      });
    }

    const payload = {
      room_code,
      room_salt,               
      is_group,
      expiry_timestamp: Date.now() + expiry * 1000,
      creator_id,
      createdAt: Date.now(),
    };

    await redis.set(redisKey, JSON.stringify(payload), 
      "EX", expiry,
    );

    return res.json({
      success: true,
      room_hash,
      room_salt,                      
      expiry,
    });
  } catch (err) {
    console.error("Create room error:", err);
    return res.status(500).json({
      success: false,
      error: "SERVER_ERROR",
    });
  }
}

/**
 * POST /room/join
 * Verifies room existence using hashed code
 */
export async function joinRoom(req, res) {
  try {
    const { code } = req.body;

    if (!code || !/^\d{6}$/.test(code)) {
      return res.status(400).json({
        success: false,
        error: "INVALID_CODE_FORMAT",
      });
    }

    const roomHash = crypto
      .createHash("sha256")
      .update(code)
      .digest("hex");

    const redisKey = `room:${roomHash}`;

    const exists = await redis.exists(redisKey);
    if (!exists) {
      return res.status(404).json({
        success: false,
        error: "ROOM_NOT_FOUND",
      });
    }

    const ttl = await redis.ttl(redisKey);
    if (ttl <= 0) {
      return res.status(410).json({
        success: false,
        error: "ROOM_EXPIRED",
      });
    }

    const raw = await redis.get(redisKey);
    const metadata = JSON.parse(raw);

    return res.json({
      success: true,
      room_hash: roomHash,
      room_code: metadata.room_code,
      room_salt: metadata.room_salt,     // ✅ NOW EXISTS
      expiry_timestamp: metadata.expiry_timestamp,
      createdAt: metadata.createdAt,
    });
  } catch (err) {
    console.error("Join room error:", err);
    return res.status(500).json({
      success: false,
      error: "SERVER_ERROR",
    });
  }
}

/**
 * POST /room/info
 * Gets room metadata
 */
export async function getRoomInfo(req, res) {
  try {
    const { room_hash } = req.body;

    if (!room_hash) {
      return res.status(400).json({
        success: false,
        error: "INVALID_REQUEST",
      });
    }

    const redisKey = `room:${room_hash}`;
    const roomDataStr = await redis.get(redisKey);

    if (!roomDataStr) {
      return res.status(404).json({
        success: false,
        error: "ROOM_NOT_FOUND",
      });
    }

    const roomData = JSON.parse(roomDataStr);
    const ttl = await redis.ttl(redisKey);

    return res.json({
      success: true,
      room_salt: roomData.room_salt,
      is_group: roomData.is_group,
      creator_id: roomData.creator_id,
      expiry_timestamp: roomData.expiry_timestamp,
    });
  } catch (err) {
    console.error("Get room info error:", err);
    return res.status(500).json({
      success: false,
      error: "SERVER_ERROR",
    });
  }
}

/**
 * POST /room/messages
 * Gets all messages for a room
 */
export async function getRoomMessages(req, res) {
  try {
    const { room_hash } = req.body;

    if (!room_hash) {
      return res.status(400).json({
        success: false,
        error: "INVALID_REQUEST",
      });
    }

    const messagesKey = `room:${room_hash}:messages`;
    const messages = await redis.lrange(messagesKey, 0, -1);

    const parsedMessages = messages.map(msg => JSON.parse(msg)).reverse(); // reverse to get chronological order

    return res.json({
      success: true,
      messages: parsedMessages,
    });
  } catch (err) {
    console.error("Get room messages error:", err);
    return res.status(500).json({
      success: false,
      error: "SERVER_ERROR",
    });
  }
}
export async function burnRoom(req, res) {
  try {
    const { room_hash, creator_id } = req.body;

    if (!room_hash || !creator_id) {
      return res.status(400).json({
        success: false,
        error: "INVALID_REQUEST",
      });
    }

    const redisKey = `room:${room_hash}`;
    const roomDataStr = await redis.get(redisKey);

    if (!roomDataStr) {
      return res.status(404).json({
        success: false,
        error: "ROOM_NOT_FOUND",
      });
    }

    const roomData = JSON.parse(roomDataStr);

    if (roomData.creator_id !== creator_id) {
      return res.status(403).json({
        success: false,
        error: "NOT_CREATOR",
      });
    }

    // Delete room and members
    await redis.del(redisKey);
    await redis.del(`room:${room_hash}:members`);
    await redis.del(`room:${room_hash}:messages`);

    // Cleanup uploaded files
    await cleanupRoomFiles(room_hash);

    // Broadcast room burnt to all clients in the room
    const { roomClients } = await import("../index.js");
    const clients = roomClients.get(room_hash);
    if (clients) {
      for (const client of clients) {
        if (client.readyState === 1) {
          client.send(JSON.stringify({ type: "room_burnt" }));
        }
      }
      // Clear the clients
      roomClients.delete(room_hash);
    }

    return res.json({
      success: true,
    });
  } catch (err) {
    console.error("Burn room error:", err);
    return res.status(500).json({
      success: false,
      error: "SERVER_ERROR",
    });
  }
}

/**
 * Periodic cleanup of expired rooms' S3 files
 * Called every 5 minutes to clean up orphaned S3 files
 */
export async function startPeriodicCleanup() {
  const CLEANUP_INTERVAL = 5 * 60 * 1000; // 5 minutes

  setInterval(async () => {
    try {
      console.log("🧹 Starting periodic S3 cleanup...");
      
      // Get all file metadata keys
      const fileKeys = await redis.keys("file:*:*");
      
      if (fileKeys.length === 0) {
        console.log("✅ No files to cleanup");
        return;
      }

      let cleanedCount = 0;

      for (const fileKey of fileKeys) {
        const fileData = await redis.get(fileKey);
        
        // If file metadata doesn't exist in Redis, it has expired
        // We need to clean up the corresponding S3 file
        if (!fileData) {
          // Extract roomHash from key format: file:roomHash:fileId
          const parts = fileKey.split(":");
          if (parts.length >= 3) {
            const roomHash = parts[1];
            
            // Check if room still exists
            const roomKey = `room:${roomHash}`;
            const roomExists = await redis.exists(roomKey);
            
            if (!roomExists) {
              // Room has expired, cleanup all its files
              await cleanupRoomFiles(roomHash);
              cleanedCount++;
            }
          }
        }
      }

      if (cleanedCount > 0) {
        console.log(`✅ Cleaned up S3 files for ${cleanedCount} expired rooms`);
      }
    } catch (error) {
      console.error("Periodic cleanup error:", error);
    }
  }, CLEANUP_INTERVAL);
}

