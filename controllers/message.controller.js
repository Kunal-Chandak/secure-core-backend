import { isKeyValid } from "../utils/validate.js";
import redis from "../redis/client.js";
import crypto from "crypto";

/**
 * Helper function to decode base64
 */
function base64Decode(str) {
  return Buffer.from(str, 'base64');
}

// Cache for room data to avoid Redis lookups on every message
// { roomHash -> { roomData, expiresAt } }
const roomCache = new Map();
const ROOM_CACHE_TTL = 5000; // 5 seconds

function getCachedRoom(roomHash) {
  const cached = roomCache.get(roomHash);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.roomData;
  }
  roomCache.delete(roomHash);
  return null;
}

function setCachedRoom(roomHash, roomData) {
  roomCache.set(roomHash, {
    roomData,
    expiresAt: Date.now() + ROOM_CACHE_TTL,
  });
}

/**
 * Handle encrypted message (relay-only)
 * Backend NEVER decrypts or verifies crypto
 */
export async function handleMessage(ws, data, wss, roomClients) {
  try {
    // Handle ping messages for heartbeat
    if (data === 'ping' || (typeof data === 'string' && data.trim() === 'ping')) {
      ws.send('pong');
      return;
    }

    // Parse JSON data if it's not a ping
    if (typeof data === 'string') {
      try {
        data = JSON.parse(data);
      } catch (parseError) {
        ws.send(JSON.stringify({ success: false, error: "INVALID_MESSAGE" }));
        return;
      }
    }

    // ═══════════════════════════════════════════════════════════════
    // HANDLE ROOM JOIN (clients send this on initial connection)
    // ═══════════════════════════════════════════════════════════════
    if (data.type === 'join_room') {
      const { roomHash, senderId } = data;

      if (!roomHash || !senderId) {
        ws.send(JSON.stringify({ success: false, error: "INVALID_PAYLOAD" }));
        return;
      }

      // Fast path: check cache first
      let roomData = getCachedRoom(roomHash);
      
      if (!roomData) {
        // Cache miss: fetch from Redis
        const roomKey = `room:${roomHash}`;
        const roomDataStr = await redis.get(roomKey);
        if (!roomDataStr) {
          ws.send(JSON.stringify({ success: false, error: "ROOM_INVALID" }));
          return;
        }
        roomData = JSON.parse(roomDataStr);
        setCachedRoom(roomHash, roomData);
      }

      // Add client to room
      if (!roomClients.has(roomHash)) {
        roomClients.set(roomHash, new Set());
      }
      roomClients.get(roomHash).add(ws);

      // ACK immediately (no detailed logging in hot path)
      ws.send(JSON.stringify({ success: true }));
      return;
    }

    // Handle file messages (images, documents, etc.)
    if (data.type === 'image' || data.type === 'file') {
      const { roomHash, type, imageId, fileId, fileName, senderId } = data;
      const fileIdentifier = imageId || fileId;

      if (!roomHash || !fileIdentifier || !senderId) {
        ws.send(JSON.stringify({ success: false, error: "INVALID_PAYLOAD" }));
        return;
      }

      // Fast path: check cache
      let roomData = getCachedRoom(roomHash);
      if (!roomData) {
        const roomKey = `room:${roomHash}`;
        const roomDataStr = await redis.get(roomKey);
        if (!roomDataStr) {
          ws.send(JSON.stringify({ success: false, error: "ROOM_INVALID" }));
          return;
        }
        roomData = JSON.parse(roomDataStr);
        setCachedRoom(roomHash, roomData);
      }

      // Add client to room if not already
      if (!roomClients.has(roomHash)) {
        roomClients.set(roomHash, new Set());
      }
      roomClients.get(roomHash).add(ws);

      // Broadcast immediately
      const roomClientsSet = roomClients.get(roomHash);
      if (roomClientsSet) {
        const broadcast = JSON.stringify({
          type,
          roomHash,
          imageId,
          fileId,
          fileName,
          senderId,
        });
        roomClientsSet.forEach(client => {
          if (client.readyState === 1) {
            client.send(broadcast);
          }
        });
      }

      // Store asynchronously (fire and forget for latency)
      (async () => {
        const msgId = crypto.randomUUID();
        const messagesKey = `room:${roomHash}:messages`;
        const messageData = {
          msgId,
          type,
          imageId,
          fileId,
          fileName,
          senderId,
          createdAt: Date.now(),
        };
        await redis.lpush(messagesKey, JSON.stringify(messageData));
        const roomTtl = await redis.ttl(`room:${roomHash}`);
        if (roomTtl > 0) {
          await redis.expire(messagesKey, roomTtl);
        }
      })();

      // ACK sender immediately
      ws.send(JSON.stringify({ success: true }));
      return;
    }

    // Handle delete message
    if (data.type === 'delete_message') {
      const { roomHash, messageId, senderId } = data;

      if (!roomHash || !messageId || !senderId) {
        ws.send(JSON.stringify({ success: false, error: "INVALID_PAYLOAD" }));
        return;
      }

      // Fast path: check cache
      let roomData = getCachedRoom(roomHash);
      if (!roomData) {
        const roomKey = `room:${roomHash}`;
        const roomDataStr = await redis.get(roomKey);
        if (!roomDataStr) {
          ws.send(JSON.stringify({ success: false, error: "ROOM_INVALID" }));
          return;
        }
        roomData = JSON.parse(roomDataStr);
        setCachedRoom(roomHash, roomData);
      }

      // Add client to room if not already
      if (!roomClients.has(roomHash)) {
        roomClients.set(roomHash, new Set());
      }
      roomClients.get(roomHash).add(ws);

      // Broadcast delete immediately
      const roomClientsSet = roomClients.get(roomHash);
      if (roomClientsSet) {
        const broadcast = JSON.stringify({
          type: 'delete_message',
          messageId,
          senderId,
        });
        roomClientsSet.forEach(client => {
          if (client.readyState === 1) {
            client.send(broadcast);
          }
        });
      }

      // Store deletion asynchronously (fire and forget)
      (async () => {
        const messagesKey = `room:${roomHash}:messages`;
        const messages = await redis.lrange(messagesKey, 0, -1);
        for (let i = 0; i < messages.length; i++) {
          const msgData = JSON.parse(messages[i]);
          if (msgData.msgId === messageId && msgData.senderId === senderId) {
            msgData.deleted = true;
            await redis.lset(messagesKey, i, JSON.stringify(msgData));
            break;
          }
        }
      })();

      // ACK sender immediately
      ws.send(JSON.stringify({ success: true }));
      return;
    }

    // Handle regular encrypted messages
    const {
      roomHash,
      ciphertext,
      iv,
      authTag,
      hmac,
      senderId,
    } = data;

    // ---- Basic validation (fail fast) ----
    if (!roomHash || !ciphertext || !iv || !authTag || !hmac || !senderId) {
      ws.send(JSON.stringify({ success: false, error: "INVALID_PAYLOAD" }));
      return;
    }

    // ---- Validate cryptographic parameters ----
    try {
      base64Decode(ciphertext);
      base64Decode(iv);
      base64Decode(authTag);
      
      const ivBuf = base64Decode(iv);
      const authTagBuf = base64Decode(authTag);
      const ciphertextBuf = base64Decode(ciphertext);
      
      if (ivBuf.length !== 12 || authTagBuf.length !== 16 || ciphertextBuf.length === 0) {
        throw new Error("Invalid crypto parameters");
      }
      
      base64Decode(hmac);
    } catch (cryptoError) {
      ws.send(JSON.stringify({ success: false, error: "INVALID_CRYPTO_PARAMETERS" }));
      return;
    }

    // ---- Validate room exists (cached) ----
    let roomData = getCachedRoom(roomHash);
    if (!roomData) {
      const roomKey = `room:${roomHash}`;
      const roomDataStr = await redis.get(roomKey);
      if (!roomDataStr) {
        ws.send(JSON.stringify({ success: false, error: "ROOM_INVALID" }));
        return;
      }
      roomData = JSON.parse(roomDataStr);
      setCachedRoom(roomHash, roomData);
    }

    // ---- Quick member check (async fire-and-forget) ----
    const membersKey = `room:${roomHash}:members`;
    (async () => {
      const isNewMember = await redis.sadd(membersKey, senderId);
      if (isNewMember) {
        const roomTtl = await redis.ttl(`room:${roomHash}`);
        if (roomTtl > 0) {
          await redis.expire(membersKey, roomTtl);
        }
      }
    })();

    // Add client to room immediately (critical for broadcast)
    if (!roomClients.has(roomHash)) {
      roomClients.set(roomHash, new Set());
    }
    roomClients.get(roomHash).add(ws);

    // ---- Broadcast encrypted blob IMMEDIATELY to all clients ----
    const msgId = crypto.randomUUID();
    const broadcastPayload = JSON.stringify({
      roomHash,
      msgId,
      ciphertext,
      iv,
      authTag,
      hmac,
      senderId,
    });

    const roomClientsSet = roomClients.get(roomHash);
    if (roomClientsSet) {
      roomClientsSet.forEach(client => {
        if (client.readyState === 1) {
          client.send(broadcastPayload);
        }
      });
    }

    // ---- Store message asynchronously (fire and forget) ----
    (async () => {
      const messagesKey = `room:${roomHash}:messages`;
      const messageData = {
        msgId,
        ciphertext,
        iv,
        authTag,
        hmac,
        senderId,
        createdAt: Date.now(),
      };
      await redis.lpush(messagesKey, JSON.stringify(messageData));
      const roomTtl = await redis.ttl(`room:${roomHash}`);
      if (roomTtl > 0) {
        await redis.expire(messagesKey, roomTtl);
      }
    })();

    // ---- ACK sender immediately (no waiting for storage) ----
    ws.send(JSON.stringify({ success: true, msgId }));

  } catch (err) {
    console.error("Message handler error:", err.message);
    ws.send(JSON.stringify({ success: false, error: "SERVER_ERROR" }));
  }
}
