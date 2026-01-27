import redis from "../redis/client.js";
import crypto from "crypto";
import dotenv from 'dotenv';
import { cleanupRoomFiles, s3Client, BUCKET_NAME } from "./file.controller.js";

dotenv.config();

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
      // Room not found, clean up files
      await cleanupRoomFiles(roomHash);
      return res.status(404).json({
        success: false,
        error: "ROOM_NOT_FOUND",
      });
    }

    const ttl = await redis.ttl(redisKey);
    if (ttl <= 0) {
      // Room expired, clean up files
      await cleanupRoomFiles(roomHash);
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
      // Room expired or not found, clean up files
      await cleanupRoomFiles(room_hash);
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
    const { room_hash, page = 0, limit = 50 } = req.body;

    if (!room_hash) {
      return res.status(400).json({
        success: false,
        error: "INVALID_REQUEST",
      });
    }

    const redisKey = `room:${room_hash}`;
    const roomExists = await redis.exists(redisKey);

    if (!roomExists) {
      // Room expired or not found, clean up files
      await cleanupRoomFiles(room_hash);
      return res.status(404).json({
        success: false,
        error: "ROOM_NOT_FOUND",
      });
    }

    const messagesKey = `room:${room_hash}:messages`;
    const totalMessages = await redis.llen(messagesKey);

    // Calculate start and end indices for pagination
    const start = page * limit;
    const end = start + limit - 1;

    const messages = await redis.lrange(messagesKey, start, end);
    const parsedMessages = messages.map(msg => JSON.parse(msg)).reverse(); // reverse to get chronological order

    return res.json({
      success: true,
      messages: parsedMessages,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: totalMessages,
        hasMore: totalMessages > (page + 1) * limit,
      },
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
  const CLEANUP_INTERVAL = 60 * 60 * 1000; // 1 hr

  setInterval(async () => {
    try {
      console.log("Starting periodic S3 cleanup...");

      // Skip if S3 is not configured
      if (!s3Client || !BUCKET_NAME) {
        console.log("S3 not configured - skipping cleanup");
        return;
      }

      // Import S3 commands dynamically to avoid startup errors
      const { ListObjectsV2Command, DeleteObjectsCommand } = await import("@aws-sdk/client-s3");

      // List all objects in the bucket with prefix 'rooms/'
      const listCommand = new ListObjectsV2Command({
        Bucket: BUCKET_NAME,
        Prefix: 'rooms/',
      });

      const listResponse = await s3Client.send(listCommand);
      const objects = listResponse.Contents || [];

      if (objects.length === 0) {
        console.log("No files to cleanup");
        return;
      }

      // Group objects by roomHash
      const roomFiles = {};
      for (const obj of objects) {
        const key = obj.Key;
        const parts = key.split('/');
        if (parts.length >= 2 && parts[0] === 'rooms') {
          const roomHash = parts[1];
          if (!roomFiles[roomHash]) {
            roomFiles[roomHash] = [];
          }
          roomFiles[roomHash].push(key);
        }
      }

      console.log(`Found room hashes in S3: ${Object.keys(roomFiles).join(', ')}`);

      let cleanedCount = 0;

      for (const roomHash in roomFiles) {
        // Check if room still exists in Redis
        const roomKey = `room:${roomHash}`;
        const roomExists = await redis.exists(roomKey);

        if (!roomExists) {
          console.log(`Deleting files for expired room: ${roomHash}`);
          // Room has expired, delete all its files from S3
          const s3Keys = roomFiles[roomHash].map(key => ({ Key: key }));

          const deleteCommand = new DeleteObjectsCommand({
            Bucket: BUCKET_NAME,
            Delete: {
              Objects: s3Keys,
            },
          });

          await s3Client.send(deleteCommand);
          console.log(`Deleted ${s3Keys.length} files from S3 for room ${roomHash}`);
          cleanedCount++;
        } else {
          console.log(`Room ${roomHash} still exists, skipping cleanup`);
        }
      }

      if (cleanedCount > 0) {
        console.log(`Cleaned up S3 files for ${cleanedCount} expired rooms`);
      }
    } catch (error) {
      console.error("Periodic cleanup error:", error);
    }
  }, CLEANUP_INTERVAL);
}

