import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command } from "@aws-sdk/client-s3";
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
 * Start periodic cleanup of expired file drops
 * Runs every 5 minutes
 */
export const startFileDropCleanup = async () => {
  console.log('Starting file drop cleanup scheduler...');
  
  // Run cleanup immediately on startup
  console.log('Running initial cleanup...');
  await cleanupExpiredDrops();
  
  // Then run every 5 minutes
  const CLEANUP_INTERVAL = 60 * 60 * 1000; // 1 hr
  setInterval(async () => {
    console.log('\nRunning periodic file drop cleanup...');
    await cleanupExpiredDrops();
  }, CLEANUP_INTERVAL);
  
  console.log(`File drop cleanup scheduler started`);
};

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

    let ttl;
    
    if (durationMap[duration]) {
      // Preset durations
      ttl = durationMap[duration];
    } else if (duration.endsWith('m')) {
      // Custom duration in minutes
      const minutes = parseInt(duration);
      if (isNaN(minutes) || minutes < 1 || minutes > 2880) {
        // 2880 minutes = 2 days
        return res.status(400).json({
          success: false,
          error: "INVALID_DURATION",
          message: "Duration must be between 1m and 2880m (1 minute to 2 days)"
        });
      }
      ttl = minutes * 60; // Convert to seconds
    } else {
      return res.status(400).json({
        success: false,
        error: "INVALID_DURATION",
        message: "Duration must be 10m, 1h, 24h, or custom minutes (1m-2880m)"
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
 * Cleanup orphaned file drops in S3
 * Removes S3 files that no longer have corresponding Redis keys
 */
export const cleanupExpiredDrops = async () => {
  try {
    if (!s3Client || !BUCKET_NAME) {
      console.log("S3 not configured - skipping file drop cleanup");
      return;
    }

    // List all file-drop objects in S3
    const listCommand = new ListObjectsV2Command({
      Bucket: BUCKET_NAME,
      Prefix: 'file-drops/',
    });

    const response = await s3Client.send(listCommand);
    const s3Files = response.Contents || [];

    if (s3Files.length === 0) {
      console.log("No file-drop objects to cleanup");
      return;
    }

    console.log(`Found ${s3Files.length} file-drop objects in S3`);

    let deletedCount = 0;
    const filesToDelete = [];

    // Check each S3 file for corresponding Redis key
    for (const s3Object of s3Files) {
      const s3Key = s3Object.Key;
      const pathParts = s3Key.split('/');

      if (pathParts.length < 3 || pathParts[0] !== 'file-drops') {
        continue;
      }

      const dropHashPrefix = pathParts[1];
      let redisKeyExists = false;

      // Search Redis for matching key
      let cursor = '0';
      do {
        try {
          const [newCursor, keys] = await redis.scan(cursor, 'MATCH', `drop:${dropHashPrefix}*`, 'COUNT', 10);
          cursor = newCursor;

          if (keys && keys.length > 0) {
            for (const redisKey of keys) {
              const redisData = await redis.get(redisKey);
              if (redisData) {
                const dropData = JSON.parse(redisData);
                if (dropData.s3Key === s3Key) {
                  redisKeyExists = true;
                  break;
                }
              }
            }
            if (redisKeyExists) break;
          }
        } catch (err) {
          console.error("Redis scan error:", err.message);
          break;
        }
      } while (cursor !== '0' && !redisKeyExists);

      // If no Redis key found, mark for deletion
      if (!redisKeyExists) {
        filesToDelete.push({ Key: s3Key });
        deletedCount++;
      }
    }

    // Delete orphaned files in batch
    if (filesToDelete.length > 0) {
      console.log(`Deleting ${deletedCount} orphaned file-drop objects from S3`);
      
      const deleteCommand = new DeleteObjectCommand({
        Bucket: BUCKET_NAME,
        Delete: {
          Objects: filesToDelete,
        },
      });

      // Delete one by one since S3 API expects single DeleteObjectCommand for batch
      for (const file of filesToDelete) {
        try {
          await s3Client.send(new DeleteObjectCommand({
            Bucket: BUCKET_NAME,
            Key: file.Key,
          }));
        } catch (err) {
          console.error(`Failed to delete ${file.Key}:`, err.message);
        }
      }

      console.log(`Cleaned up ${deletedCount} orphaned file-drop objects from S3`);
    }

  } catch (error) {
    console.error("File drop cleanup error:", error.message);
  }
};
