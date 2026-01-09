import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectsCommand, HeadBucketCommand } from "@aws-sdk/client-s3";
import { Upload } from "@aws-sdk/lib-storage";
import dotenv from 'dotenv';
import multer from "multer";
import multerS3 from "multer-s3";
import crypto from "crypto";
import { DateTime } from 'luxon';
import { generateHMAC, verifyHmac } from "../crypto/hmac.js";
import { hkdf, pbkdf2 } from "../crypto/hkdf.js";
import redis from "../redis/client.js";

dotenv.config();

// S3 Configuration (optional - will disable file features if not configured)
let s3Client = null;
let BUCKET_NAME = null;
let upload = null;

// Initialize basic multer first
upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024 , // 50MB limit
  },
});

// Initialize S3 synchronously like test-s3.js
if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
  try {
    s3Client = new S3Client({
      region: process.env.AWS_REGION || "us-east-1",
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      },
    });
    BUCKET_NAME = process.env.S3_BUCKET_NAME || "securecore-files";

    // Test the S3 connection synchronously
    s3Client.send(new HeadBucketCommand({ Bucket: BUCKET_NAME }))
      .then(() => {
        console.log("S3 client initialized and bucket accessible");

        // Configure multer S3 synchronously now
        upload = multer({
          storage: multerS3({
            s3: s3Client,
            bucket: BUCKET_NAME,
            key: (req, file, cb) => {
              const { roomHash } = req.body;
              const fileId = crypto.randomUUID();
              const key = `rooms/${roomHash}/files/${fileId}.bin`;
              console.log(`Uploading to S3 key: ${key}`);
              cb(null, key);
            },
            acl: 'private',
          }),
          limits: {
            fileSize: 50 * 1024 * 1024, // 50MB limit
          },
        });
        console.log("Multer S3 storage configured synchronously");
      })
      .catch((bucketError) => {
        console.log("S3 client initialized but bucket access failed");
        console.log("   Error name:", bucketError.name);
        console.log("   Error message:", bucketError.message);
        console.log("   Bucket name:", BUCKET_NAME);
        console.log("   Region:", process.env.AWS_REGION || "us-east-1");
        s3Client = null;
      });
  } catch (error) {
    console.log("⚠️ Failed to initialize S3 client - file features disabled:", error.message);
  }
} else {
  console.log("⚠️ AWS credentials not configured - file features disabled");
}

export { s3Client, BUCKET_NAME };
if (!upload) {
  import("multer").then((multerModule) => {
    const multer = multerModule.default;
    upload = multer({
      storage: multer.memoryStorage(),
      limits: {
        fileSize: 50 * 1024 * 1024, // 50MB limit
      },
    });
  });
}

/**
 * Upload encrypted file
 */
export const uploadImage = async (req, res) => {
  try {
    console.log("Starting image upload...");
    console.log("   Room hash:", req.body.roomHash);
    console.log("   File present:", !!req.file);
    console.log("   S3 client available:", !!s3Client);

    // Check if S3 is configured
    if (!s3Client || !BUCKET_NAME) {
      console.log("S3 not configured");
      return res.status(503).json({
        success: false,
        error: "FILE_STORAGE_NOT_CONFIGURED"
      });
    }

    const { roomHash, hmac, iv, authTag, fileName, fileSize } = req.body;

    if (!req.file || !roomHash || !hmac || !iv || !authTag) {
      console.log("Missing parameters");
      return res.status(400).json({
        success: false,
        error: "MISSING_PARAMETERS"
      });
    }

    // Verify room exists and get room data
    const roomKey = `room:${roomHash}`;
    const roomData = await redis.get(roomKey);

    if (!roomData) {
      return res.status(404).json({
        success: false,
        error: "ROOM_NOT_FOUND"
      });
    }

    const room = JSON.parse(roomData);
    const now = DateTime.now();

    console.log("Room data:", room); // Debug: check room data

    if (now > room.expiry_timestamp) {
      return res.status(410).json({
        success: false,
        error: "ROOM_EXPIRED"
      });
    }

    // Verify HMAC using derived key from room code and salt
    if (!room.room_code) {
      console.log("Room code not found in room data - room was created before code storage was added");
      return res.status(500).json({
        success: false,
        error: "ROOM_CODE_MISSING"
      });
    }
    const derivedKey = pbkdf2(room.room_code, Buffer.from(room.room_salt, 'base64'));

    // Construct message data the same way as frontend: base64(ciphertext) + base64(iv) + base64(authTag)
    const ciphertextBase64 = req.file.buffer.toString('base64');
    const messageData = `${ciphertextBase64}${iv}${authTag}`;
    const isValid = verifyHmac(derivedKey, messageData, hmac);

    if (!isValid) {
      return res.status(403).json({
        success: false,
        error: "INVALID_HMAC"
      });
    }

    // Generate S3 key
    const fileId = crypto.randomUUID();
    const s3Key = `rooms/${roomHash}/files/${fileId}.bin`;

    // Upload to S3 directly
    const uploadCommand = new PutObjectCommand({
      Bucket: BUCKET_NAME,
      Key: s3Key,
      Body: req.file.buffer,
      ACL: 'private',
    });

    await s3Client.send(uploadCommand);
    console.log(`Uploaded to S3 key: ${s3Key}`);

    // Store metadata in Redis with same TTL as room
    const ttl = Math.ceil((room.expiry_timestamp - now) / 1000);
    console.log("🔍 TTL calculation:", { expiryTimestamp: room.expiry_timestamp, now, ttl }); // Debug TTL

    // Validate TTL
    if (ttl <= 0 || ttl > 2147483647) { // Redis max TTL is 2^31 - 1 seconds
      console.log("Invalid TTL:", ttl);
      return res.status(400).json({
        success: false,
        error: "INVALID_ROOM_EXPIRY"
      });
    }

    const fileMetadata = {
      fileId,
      fileName: fileName || "file",
      fileSize: parseInt(fileSize) || req.file.size,
      uploadTimestamp: now,
      s3Key: s3Key,
      iv,
      authTag,
    };

    console.log("Storing metadata:", fileMetadata);

    await redis.set(
      `file:${roomHash}:${fileId}`,
      JSON.stringify(fileMetadata),
      "EX", ttl 
    );

    res.json({
      success: true,
      fileId,
      message: "File uploaded successfully"
    });

  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({
      success: false,
      error: "UPLOAD_FAILED"
    });
  }
};

/**
 * Download encrypted image file
 */
export const downloadFile = async (req, res) => {
  try {
    // Check if S3 is configured
    if (!s3Client || !BUCKET_NAME) {
      return res.status(503).json({
        success: false,
        error: "FILE_STORAGE_NOT_CONFIGURED"
      });
    }

    const { fileId } = req.params;
    const { roomHash } = req.query;

    if (!roomHash) {
      return res.status(400).json({
        success: false,
        error: "MISSING_ROOM_HASH"
      });
    }

    // Verify room exists
    const roomKey = `room:${roomHash}`;
    const roomData = await redis.get(roomKey);

    if (!roomData) {
      return res.status(404).json({
        success: false,
        error: "ROOM_NOT_FOUND"
      });
    }

    // Get file metadata
    const fileKey = `file:${roomHash}:${fileId}`;
    const fileData = await redis.get(fileKey);

    if (!fileData) {
      return res.status(404).json({
        success: false,
        error: "FILE_NOT_FOUND"
      });
    }

    const metadata = JSON.parse(fileData);
    console.log('Download metadata:', metadata);
    console.log('S3 key:', metadata.s3Key);

    if (!metadata.s3Key) {
      return res.status(500).json({
        success: false,
        error: "S3_KEY_MISSING"
      });
    }

    // Stream file from S3
    const command = new GetObjectCommand({
      Bucket: BUCKET_NAME,
      Key: metadata.s3Key,
    });

    const response = await s3Client.send(command);

    if (!response.Body) {
      return res.status(404).json({
        success: false,
        error: "FILE_NOT_FOUND"
      });
    }

    // Set headers
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', metadata.fileSize);
    res.setHeader('X-File-IV', metadata.iv);
    res.setHeader('X-File-AuthTag', metadata.authTag);
    res.setHeader('X-File-FileName', metadata.fileName);

    // Stream the file
    response.Body.pipe(res);

  } catch (error) {
    console.error("Download error:", error);
    res.status(500).json({
      success: false,
      error: "DOWNLOAD_FAILED"
    });
  }
};

/**
 * Clean up room files (called when room expires or is burnt)
 */
export const cleanupRoomFiles = async (roomHash) => {
  try {
    // Skip if S3 is not configured
    if (!s3Client || !BUCKET_NAME) {
      console.log("S3 not configured - skipping file cleanup");
      return;
    }

    // Get all file keys for this room
    const pattern = `file:${roomHash}:*`;
    const keys = await redis.keys(pattern);

    if (keys.length === 0) {
      console.log(`No files to cleanup for room ${roomHash}`);
      return;
    }

    // Collect S3 keys to delete
    const s3Keys = [];
    for (const key of keys) {
      const fileData = await redis.get(key);
      if (fileData) {
        const metadata = JSON.parse(fileData);
        s3Keys.push({ Key: metadata.s3Key });
        console.log(`Queuing S3 deletion: ${metadata.s3Key}`);
      }
    }

    // Delete from S3
    if (s3Keys.length > 0) {
      const deleteCommand = new DeleteObjectsCommand({
        Bucket: BUCKET_NAME,
        Delete: {
          Objects: s3Keys,
        },
      });

      await s3Client.send(deleteCommand);
      console.log(`Deleted ${s3Keys.length} files from S3 for room ${roomHash}`);
    }

    // Delete metadata from Redis
    await redis.del(keys);
    console.log(`Deleted ${keys.length} file metadata entries for room ${roomHash}`);

  } catch (error) {
    console.error("Cleanup error:", error);
  }
};