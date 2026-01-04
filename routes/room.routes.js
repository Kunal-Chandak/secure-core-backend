import express from "express";
import { createRoom, joinRoom, getRoomInfo, burnRoom, getRoomMessages } from "../controllers/room.controller.js";

const router = express.Router();

// POST /room/create
router.post("/create", createRoom);

// POST /room/join
router.post("/join", joinRoom);

// POST /room/info
router.post("/info", getRoomInfo);

// POST /room/messages
router.post("/messages", getRoomMessages);

// POST /room/burn
router.post("/burn", burnRoom);

export default router;
