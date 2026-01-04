import express from "express";
import multer from "multer";
import { uploadImage, downloadFile } from "../controllers/file.controller.js";

const router = express.Router();

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB limit
  },
});

// POST /file/upload - Upload encrypted file
router.post("/upload", upload.single("file"), uploadImage);

// GET /file/:fileId - Download encrypted file
router.get("/:fileId", downloadFile);

export default router;