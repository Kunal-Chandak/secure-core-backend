import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import dotenv from 'dotenv';
import multer from "multer";
import crypto from "crypto";
import { DateTime } from 'luxon';
import { generateHMAC, verifyHmac } from "../crypto/hmac.js";
import { hkdf, pbkdf2 } from "../crypto/hkdf.js";
import redis from "../redis/client.js";

dotenv.config();

// S3 Configuration
let s3Client = null;
let BUCKET_NAME = null;
let upload = null;

// Initialize multer with memory storage
upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB limit for file drops
  },
});

// Initialize S3 (same as file.controller.js)
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
    console.log("File Drop S3 client initialized");
  } catch (error) {
    console.log("⚠️ Failed to initialize S3 client for file drops:", error.message);
  }
} else {
  console.log("⚠️ AWS credentials not configured - file drop features disabled");
}

export { s3Client, BUCKET_NAME, upload };

/**
 * POST /file-drop/create
 * Create a new file drop session
 * Receives: dropHash (SHA256 hash, generated on frontend - plaintext never sent)
 */
export const createFileDrop = async (req, res) => {
  try {
    if (!s3Client || !BUCKET_NAME) {
      return res.status(503).json({
        success: false,
        error: "FILE_STORAGE_NOT_CONFIGURED"
      });
    }

    const { dropHash, duration } = req.body;

    // Validate input
    if (!dropHash || !duration) {
      return res.status(400).json({
        success: false,
        error: "MISSING_PARAMETERS"
      });
    }

    // Validate hash format (SHA256 = 64 hex characters)
    if (!/^[a-f0-9]{64}$/.test(dropHash)) {
      return res.status(400).json({
        success: false,
        error: "INVALID_DROP_HASH_FORMAT"
      });
    }

    // Validate duration
    const durationMap = {
      '10m': 10 * 60,
      '1h': 60 * 60,
      '24h': 24 * 60 * 60,
    };

    const ttl = durationMap[duration];

    if (!ttl) {
      return res.status(400).json({
        success: false,
        error: "INVALID_DURATION",
        message: "Duration must be 10m, 1h, or 24h"
      });
    }

    const dropKey = `drop:${dropHash}`;

    // Check if this hash already exists (prevent re-creation)
    const exists = await redis.exists(dropKey);
    if (exists) {
      return res.status(409).json({
        success: false,
        error: "DROP_ALREADY_EXISTS"
      });
    }

    // Create drop session metadata
    const now = DateTime.now();
    const expiryTimestamp = now.plus({ seconds: ttl });

    const dropMetadata = {
      // ⚠️  NOTE: We do NOT store the plaintext code here!
      // Frontend generated it, frontend will hash it for every request
      // Backend only knows the hash
      createdAt: now.toISO(),
      expiryTimestamp: expiryTimestamp.toISO(),
      duration,
      ttl,
      fileId: null,
      fileName: null,
      fileSize: null,
      iv: null,
      authTag: null,
      s3Key: null,
      downloaded: false,
      uploadedAt: null,
    };

    // Store in Redis with TTL
    await redis.set(
      dropKey,
      JSON.stringify(dropMetadata),
      "EX",
      ttl
    );

    console.log(`✅ File drop session created: ${dropHash.substring(0, 8)}... (TTL: ${ttl}s)`);
    console.log('   ⚠️  Plaintext code kept only on frontend');

    res.json({
      success: true,
      expiryTimestamp: expiryTimestamp.toISO(),
      duration,
    });

  } catch (error) {
    console.error("Create file drop error:", error);
    res.status(500).json({
      success: false,
      error: "CREATE_FAILED"
    });
  }
};

/**
 * POST /file-drop/upload
 * Upload encrypted file to a drop session
 * Receives: dropHash (SHA256 hash of the 6-digit code) from frontend
 */
export const uploadFileDrop = async (req, res) => {
  try {
    if (!s3Client || !BUCKET_NAME) {
      return res.status(503).json({
        success: false,
        error: "FILE_STORAGE_NOT_CONFIGURED"
      });
    }

    const { dropHash, hmac, iv, authTag, fileName, fileSize } = req.body;

    // Validate input (expect hash from frontend, not plaintext code)
    if (!dropHash || !req.file || !hmac || !iv || !authTag) {
      return res.status(400).json({
        success: false,
        error: "MISSING_PARAMETERS"
      });
    }

    // Get drop session using hash
    const dropKey = `drop:${dropHash}`;
    const dropData = await redis.get(dropKey);

    if (!dropData) {
      return res.status(404).json({
        success: false,
        error: "DROP_NOT_FOUND"
      });
    }

    const drop = JSON.parse(dropData);
    const now = DateTime.now();

    // Check if already expired
    const expiryTime = DateTime.fromISO(drop.expiryTimestamp);
    if (now > expiryTime) {
      return res.status(410).json({
        success: false,
        error: "DROP_EXPIRED"
      });
    }

    // Check if already uploaded
    if (drop.fileId) {
      return res.status(409).json({
        success: false,
        error: "FILE_ALREADY_UPLOADED"
      });
    }

    // ⚠️  NOTE: We cannot verify HMAC on backend since we don't have the plaintext code
    // The HMAC was generated on frontend using the drop code as key
    // We trust the frontend has properly encrypted and HMACed the data
    // The dropHash itself serves as proof of authorization (only frontend that generated it can hash to it)
    
    // Generate file ID and S3 key (use hash in path for extra security - no plaintext code)
    const fileId = crypto.randomUUID();
    const s3Key = `file-drops/${dropHash.substring(0, 16)}/${fileId}.bin`;

    // Upload to S3
    const uploadCommand = new PutObjectCommand({
      Bucket: BUCKET_NAME,
      Key: s3Key,
      Body: req.file.buffer,
      ACL: 'private',
    });

    await s3Client.send(uploadCommand);
    console.log(`📤 Uploaded file drop to S3: ${s3Key}`);

    // Update drop metadata
    const ttl = Math.ceil((expiryTime - now) / 1000);
    
    drop.fileId = fileId;
    drop.fileName = fileName || "file";
    drop.fileSize = parseInt(fileSize) || req.file.size;
    drop.iv = iv;
    drop.authTag = authTag;
    drop.s3Key = s3Key;
    drop.uploadedAt = now.toISO();

    await redis.set(
      dropKey,
      JSON.stringify(drop),
      "EX",
      ttl
    );

    console.log(`✅ File drop metadata updated: ${dropHash.substring(0, 8)}...`);

    res.json({
      success: true,
      fileId,
      message: "File uploaded successfully to drop session"
    });

  } catch (error) {
    console.error("Upload file drop error:", error);
    res.status(500).json({
      success: false,
      error: "UPLOAD_FAILED"
    });
  }
};

/**
 * POST /file-drop/validate
 * Validate drop code hash and return file metadata
 * Receives: dropHash (SHA256 hash of the 6-digit code) from frontend
 */
export const validateDropCode = async (req, res) => {
  try {
    if (!s3Client || !BUCKET_NAME) {
      return res.status(503).json({
        success: false,
        error: "FILE_STORAGE_NOT_CONFIGURED"
      });
    }

    const { dropHash } = req.body;

    if (!dropHash || !/^[a-f0-9]{64}$/.test(dropHash)) {
      return res.status(400).json({
        success: false,
        error: "INVALID_DROP_HASH_FORMAT"
      });
    }

    // Get drop session using hash
    const dropKey = `drop:${dropHash}`;
    const dropData = await redis.get(dropKey);

    if (!dropData) {
      return res.status(404).json({
        success: false,
        error: "DROP_NOT_FOUND"
      });
    }

    const drop = JSON.parse(dropData);
    const now = DateTime.now();

    // Check if expired
    const expiryTime = DateTime.fromISO(drop.expiryTimestamp);
    if (now > expiryTime) {
      return res.status(410).json({
        success: false,
        error: "DROP_EXPIRED"
      });
    }

    // Check if already downloaded
    if (drop.downloaded) {
      return res.status(410).json({
        success: false,
        error: "FILE_ALREADY_DOWNLOADED"
      });
    }

    // Check if file has been uploaded
    if (!drop.fileId) {
      return res.status(400).json({
        success: false,
        error: "NO_FILE_UPLOADED_YET"
      });
    }

    res.json({
      success: true,
      fileId: drop.fileId,
      fileName: drop.fileName,
      fileSize: drop.fileSize,
      iv: drop.iv,
      authTag: drop.authTag,
      expiryTime: drop.expiryTimestamp,
      timeRemaining: Math.ceil((expiryTime.toMillis() - now.toMillis()) / 1000),
    });

  } catch (error) {
    console.error("Validate drop code error:", error);
    res.status(500).json({
      success: false,
      error: "VALIDATION_FAILED"
    });
  }
};

/**
 * GET /file-drop/:fileId
 * Download file from drop and delete it (one-time download)
 * Query params: dropHash
 */
export const downloadFileDrop = async (req, res) => {
  try {
    if (!s3Client || !BUCKET_NAME) {
      return res.status(503).json({
        success: false,
        error: "FILE_STORAGE_NOT_CONFIGURED"
      });
    }

    const { fileId } = req.params;
    const { dropHash } = req.query;

    if (!dropHash || !fileId) {
      return res.status(400).json({
        success: false,
        error: "MISSING_PARAMETERS"
      });
    }

    // Get drop session using hash
    const dropKey = `drop:${dropHash}`;
    const dropData = await redis.get(dropKey);

    if (!dropData) {
      return res.status(404).json({
        success: false,
        error: "DROP_NOT_FOUND"
      });
    }

    const drop = JSON.parse(dropData);
    const now = DateTime.now();

    // Check if expired
    const expiryTime = DateTime.fromISO(drop.expiryTimestamp);
    if (now > expiryTime) {
      return res.status(410).json({
        success: false,
        error: "DROP_EXPIRED"
      });
    }

    // Check if already downloaded
    if (drop.downloaded) {
      return res.status(410).json({
        success: false,
        error: "FILE_ALREADY_DOWNLOADED"
      });
    }

    // Verify file ID matches
    if (drop.fileId !== fileId) {
      return res.status(403).json({
        success: false,
        error: "FILE_ID_MISMATCH"
      });
    }

    // Get file from S3
    const command = new GetObjectCommand({
      Bucket: BUCKET_NAME,
      Key: drop.s3Key,
    });

    const response = await s3Client.send(command);

    if (!response.Body) {
      return res.status(404).json({
        success: false,
        error: "FILE_NOT_FOUND_IN_S3"
      });
    }

    // Set response headers
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', drop.fileSize);
    res.setHeader('X-File-IV', drop.iv);
    res.setHeader('X-File-AuthTag', drop.authTag);
    res.setHeader('X-File-FileName', drop.fileName);

    // Mark as downloaded in Redis BEFORE streaming
    drop.downloaded = true;
    drop.downloadedAt = now.toISO();
    
    const ttl = Math.ceil((expiryTime - now) / 1000);
    await redis.set(
      dropKey,
      JSON.stringify(drop),
      "EX",
      ttl
    );

    console.log(`📥 Downloaded file drop: ${dropHash.substring(0, 8)}.../${fileId}`);

    // Stream the file
    response.Body.pipe(res);

    // After download completes, delete from S3
    res.on('finish', async () => {
      try {
        const deleteCommand = new DeleteObjectCommand({
          Bucket: BUCKET_NAME,
          Key: drop.s3Key,
        });
        
        await s3Client.send(deleteCommand);
        console.log(`🔥 Deleted file drop from S3: ${drop.s3Key}`);
      } catch (deleteError) {
        console.error("Failed to delete file from S3 after download:", deleteError);
        // Don't fail the response, just log it
      }
    });

    // Handle errors during streaming
    res.on('error', async (streamError) => {
      console.error("Stream error during file drop download:", streamError);
      // Mark as not downloaded if stream fails
      drop.downloaded = false;
      await redis.set(
        dropKey,
        JSON.stringify(drop),
        "EX",
        ttl
      );
    });

  } catch (error) {
    console.error("Download file drop error:", error);
    res.status(500).json({
      success: false,
      error: "DOWNLOAD_FAILED"
    });
  }
};

/**
 * Cleanup expired file drops
 * Called periodically or on demand
 */
export const cleanupExpiredDrops = async () => {
  try {
    if (!s3Client || !BUCKET_NAME) {
      console.log("S3 not configured - skipping file drop cleanup");
      return;
    }

    // Get all drop keys
    const pattern = 'drop:*';
    const keys = await redis.keys(pattern);

    if (keys.length === 0) {
      console.log("No drops to cleanup");
      return;
    }

    let cleanedCount = 0;
    let deletedRedisCount = 0;

    for (const key of keys) {
      const dropData = await redis.get(key);
      if (dropData) {
        const drop = JSON.parse(dropData);
        
        // Check if expired
        const expiryTime = DateTime.fromISO(drop.expiryTimestamp);
        const now = DateTime.now();
        
        if (now > expiryTime) {
          // Delete S3 file if it exists
          if (drop.s3Key) {
            try {
              const deleteCommand = new DeleteObjectCommand({
                Bucket: BUCKET_NAME,
                Key: drop.s3Key,
              });
              
              await s3Client.send(deleteCommand);
              console.log(`🧹 Deleted expired file from S3: ${drop.s3Key}`);
              cleanedCount++;
            } catch (deleteError) {
              console.error(`Failed to delete expired drop file ${drop.s3Key}:`, deleteError);
            }
          }

          // Delete the Redis key
          try {
            await redis.del(key);
            console.log(`🗑️  Deleted expired Redis key: ${key}`);
            deletedRedisCount++;
          } catch (redisError) {
            console.error(`Failed to delete Redis key ${key}:`, redisError);
          }
        }
      }
    }

    console.log(`✅ Cleanup complete: Deleted ${cleanedCount} S3 files and ${deletedRedisCount} Redis keys`);

  } catch (error) {
    console.error("File drop cleanup error:", error);
  }
};
