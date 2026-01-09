import { isKeyValid } from "../utils/validate.js";
import redis from "../redis/client.js";
import crypto from "crypto";

/**
 * Helper function to decode base64
 */
function base64Decode(str) {
  return Buffer.from(str, 'base64');
}

/**
 * Handle encrypted message (relay-only)
 * Backend NEVER decrypts or verifies crypto
 */
export async function handleMessage(ws, data, wss, roomClients) {
  try {
    // Handle ping messages for heartbeat
    if (data === 'ping' || (typeof data === 'string' && data.trim() === 'ping')) {
      console.log('Received ping, sending pong');
      ws.send('pong');
      return;
    }

    // Parse JSON data if it's not a ping
    if (typeof data === 'string') {
      try {
        data = JSON.parse(data);
      } catch (parseError) {
        console.error('Failed to parse message as JSON:', parseError);
        ws.send(JSON.stringify({ success: false, error: "INVALID_MESSAGE" }));
        return;
      }
    }

    console.log('Processing message type:', data.type || 'unknown');

    // Handle file messages (images, documents, etc.)
    if (data.type === 'image' || data.type === 'file') {
      console.log('📎 Processing file message:', data);
      const { roomHash, type, imageId, fileId, fileName, senderId } = data;
      const fileIdentifier = imageId || fileId;

      // Basic validation for file messages
      if (!roomHash || !fileIdentifier || !senderId) {
        console.log('Invalid file payload - missing required fields');
        ws.send(JSON.stringify({ success: false, error: "INVALID_PAYLOAD" }));
        return;
      }

      // Validate room exists
      const roomKey = `room:${roomHash}`;
      const roomDataStr = await redis.get(roomKey);
      if (!roomDataStr) {
        console.log('Room not found for file message');
        ws.send(JSON.stringify({ success: false, error: "ROOM_INVALID" }));
        return;
      }

      // Add client to room if not already
      if (!roomClients.has(roomHash)) {
        roomClients.set(roomHash, new Set());
      }
      roomClients.get(roomHash).add(ws);

      // Broadcast file message to all clients in room
      console.log('Broadcasting file message to room:', roomHash);
      const roomClientsSet = roomClients.get(roomHash);
      if (roomClientsSet) {
        roomClientsSet.forEach(client => {
          if (client.readyState === 1 && client !== ws) {
            client.send(JSON.stringify({
              type: type,
              roomHash,
              imageId: imageId,
              fileId: fileId,
              fileName,
              senderId,
            }));
          }
        });
      }

      // Store file message
      const msgId = crypto.randomUUID();
      const messagesKey = `room:${roomHash}:messages`;
      const messageData = {
        msgId,
        type: type,
        imageId: imageId,
        fileId: fileId,
        fileName,
        senderId,
        createdAt: Date.now(),
      };

      await redis.lpush(messagesKey, JSON.stringify(messageData));
      const roomTtl = await redis.ttl(roomKey);
      if (roomTtl > 0) {
        await redis.expire(messagesKey, roomTtl);
      }

      // ACK sender
      ws.send(JSON.stringify({ success: true, msgId }));
      return;
    }

    // Handle delete message
    if (data.type === 'delete_message') {
      console.log('Processing delete message:', data);
      const { roomHash, messageId, senderId } = data;

      // Basic validation
      if (!roomHash || !messageId || !senderId) {
        console.log('Invalid delete payload - missing required fields');
        ws.send(JSON.stringify({ success: false, error: "INVALID_PAYLOAD" }));
        return;
      }

      // Validate room exists
      const roomKey = `room:${roomHash}`;
      const roomDataStr = await redis.get(roomKey);
      if (!roomDataStr) {
        console.log('Room not found for delete message');
        ws.send(JSON.stringify({ success: false, error: "ROOM_INVALID" }));
        return;
      }

      // Add client to room if not already
      if (!roomClients.has(roomHash)) {
        roomClients.set(roomHash, new Set());
      }
      roomClients.get(roomHash).add(ws);

      // Find and mark the message as deleted
      const messagesKey = `room:${roomHash}:messages`;
      const messages = await redis.lrange(messagesKey, 0, -1);
      
      let messageFound = false;
      for (let i = 0; i < messages.length; i++) {
        const msgData = JSON.parse(messages[i]);
        if (msgData.msgId === messageId && msgData.senderId === senderId) {
          // Mark message as deleted
          msgData.deleted = true;
          await redis.lset(messagesKey, i, JSON.stringify(msgData));
          messageFound = true;
          break;
        }
      }

      if (!messageFound) {
        console.log('Message not found for deletion');
        ws.send(JSON.stringify({ success: false, error: "MESSAGE_NOT_FOUND" }));
        return;
      }

      // Broadcast delete message to all clients in room
      console.log('Broadcasting delete message to room:', roomHash);
      const roomClientsSet = roomClients.get(roomHash);
      if (roomClientsSet) {
        roomClientsSet.forEach(client => {
          if (client.readyState === 1 && client !== ws) {
            client.send(JSON.stringify({
              type: 'delete_message',
              messageId,
              senderId,
            }));
          }
        });
      }

      // ACK sender
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

    // ---- Basic validation ----
    if (
      !roomHash ||
      !ciphertext ||
      !iv ||
      !authTag ||
      !hmac ||
      !senderId
    ) {
      ws.send(JSON.stringify({ success: false, error: "INVALID_PAYLOAD" }));
      return;
    }

    // ---- Validate cryptographic parameters ----
    try {
      // Check if base64 strings are valid
      base64Decode(ciphertext);
      base64Decode(iv);
      base64Decode(authTag);
      
      // Validate lengths (AES-GCM specific)
      if (base64Decode(iv).length !== 12) {
        throw new Error("Invalid IV length");
      }
      if (base64Decode(authTag).length !== 16) {
        throw new Error("Invalid auth tag length");
      }
      if (base64Decode(ciphertext).length === 0) {
        throw new Error("Empty ciphertext");
      }
      
      // Validate HMAC format (should be base64 encoded)
      base64Decode(hmac);
      
      // Validate senderId format (should be UUID-like)
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      if (!uuidRegex.test(senderId)) {
        throw new Error("Invalid sender ID format");
      }
      
    } catch (cryptoError) {
      console.error("Cryptographic validation failed:", cryptoError.message);
      ws.send(JSON.stringify({ success: false, error: "INVALID_CRYPTO_PARAMETERS" }));
      return;
    }

    // ---- Validate room exists ----
    const roomKey = `room:${roomHash}`;
    const roomDataStr = await redis.get(roomKey);
    if (!roomDataStr) {
      ws.send(JSON.stringify({ success: false, error: "ROOM_INVALID" }));
      return;
    }
    const roomData = JSON.parse(roomDataStr);
    const isGroup = roomData.is_group;

    // ---- Check member limit ----
    const membersKey = `room:${roomHash}:members`;
    const isNewMember = await redis.sadd(membersKey, senderId);
    const memberCount = await redis.scard(membersKey);

    const maxMembers = isGroup ? 20 : 2;
    if (memberCount > maxMembers) {
      // Remove the added member if over limit
      await redis.srem(membersKey, senderId);
      ws.send(JSON.stringify({ success: false, error: "ROOM_FULL" }));
      return;
    }

    // Set expiry on members key if new member
    if (isNewMember) {
      const roomTtl = await redis.ttl(roomKey);
      if (roomTtl > 0) {
        await redis.expire(membersKey, roomTtl);
      }
    }

    // Add client to room
    if (!roomClients.has(roomHash)) {
      roomClients.set(roomHash, new Set());
    }
    roomClients.get(roomHash).add(ws);

    // ---- Store encrypted message (optional) ----
    const msgId = crypto.randomUUID();
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
    const roomTtl = await redis.ttl(roomKey);
    if (roomTtl > 0) {
      await redis.expire(messagesKey, roomTtl);
    }

    // ---- Broadcast encrypted blob ----
    const roomClientsSet = roomClients.get(roomHash);
    if (roomClientsSet) {
      roomClientsSet.forEach(client => {
        if (client.readyState === 1 && client !== ws) {
          client.send(JSON.stringify({
            roomHash,
            msgId,
            ciphertext,
            iv,
            authTag,
            hmac,
            senderId,
          }));
        }
      });
    }

    // ---- ACK sender ----
    ws.send(JSON.stringify({ success: true, msgId }));

  } catch (err) {
    console.error("Message send error:", err);
    ws.send(JSON.stringify({ success: false, error: "SERVER_ERROR" }));
  }
}
