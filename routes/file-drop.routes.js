import express from "express";
import {
  createFileDrop,
  uploadFileDrop,
  validateDropCode,
  downloadFileDrop,
  upload,
} from "../controllers/file-drop.controller.js";

const router = express.Router();

/**
 * POST /file-drop/create
 * Create a new file drop session
 * Body: { dropHash (SHA256), duration: "10m" | "1h" | "24h" }
 * Note: dropHash is generated on frontend, NEVER send plaintext code to backend!
 * Response: { success: true, expiryTimestamp, duration }
 */
router.post("/create", createFileDrop);

/**
 * POST /file-drop/upload
 * Upload encrypted file to drop session
 * Body: { dropHash (SHA256), hmac, iv, authTag, fileName, fileSize, file }
 * Response: { success: true, fileId, dropCode }
 */
router.post("/upload", upload.single("file"), uploadFileDrop);

/**
 * POST /file-drop/validate
 * Validate drop code and check if file is available
 * Body: { dropHash (SHA256 hash of 6-digit code) }
 * Response: { success: true, fileId, fileName, fileSize, iv, authTag, expiryTime, timeRemaining }
 */
router.post("/validate", validateDropCode);

/**
 * GET /file-drop/:fileId
 * Download file from drop session (one-time only)
 * Query: dropHash (SHA256 hash of 6-digit code)
 * Response: Encrypted file binary + headers (IV, AuthTag, FileName)
 */
router.get("/:fileId", downloadFileDrop);

export default router;
