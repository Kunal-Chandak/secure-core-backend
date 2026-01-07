import express from "express";
import dotenv from "dotenv";
import roomRoutes from "./routes/room.routes.js";
import fileRoutes from "./routes/file.routes.js";
import { WebSocketServer } from "ws";
import { handleMessage } from "./controllers/message.controller.js";
import { startPeriodicCleanup } from "./controllers/room.controller.js";

dotenv.config();

const app = express();
app.use(express.json());

app.use("/room", roomRoutes);
app.use("/file", fileRoutes);

const PORT = process.env.PORT || 3001;
const server = app.listen(PORT, () => {
  console.log(`🚀 SecureCore backend running on port ${PORT}`);
  startPeriodicCleanup(); // Start S3 cleanup job
}, '0.0.0.0');

// ---------------- WebSocket Server ----------------
// Use the same server for WebSocket upgrades
const wss = new WebSocketServer({ 
  server,
  // Add heartbeat settings
  perMessageDeflate: false,
  maxPayload: 1024 * 1024, // 1MB max payload
});

// Map of roomHash to Set of WebSocket clients
const roomClients = new Map();

wss.on("connection", (ws) => {
  console.log("🟢 New WebSocket connection");

  // Set up ping/pong heartbeat
  const pingInterval = setInterval(() => {
    if (ws.readyState === 1) { // OPEN
      ws.ping();
    }
  }, 30000); // Ping every 30 seconds

  // Handle pong responses
  ws.on("pong", () => {
    console.log("Received pong from client");
  });

  // Set connection timeout
  const connectionTimeout = setTimeout(() => {
    console.log("🔴 Connection timeout - closing WebSocket");
    ws.terminate();
  }, 5 * 60 * 1000); // 5 minutes timeout

  ws.on("message", async (rawData) => {
    try {
      const data = JSON.parse(rawData);
      await handleMessage(ws, data, wss, roomClients);
    } catch (err) {
      console.error("WS message parse error:", err);
      ws.send(JSON.stringify({ success: false, error: "INVALID_MESSAGE" }));
    }
  });

  ws.on("close", () => {
    console.log("🔴 WebSocket connection closed");
    clearInterval(pingInterval);
    clearTimeout(connectionTimeout);
    // Remove from all rooms
    for (const [roomHash, clients] of roomClients) {
      clients.delete(ws);
      if (clients.size === 0) {
        roomClients.delete(roomHash);
      }
    }
  });

  ws.on("error", (error) => {
    console.error("🔴 WebSocket error:", error);
    clearInterval(pingInterval);
    clearTimeout(connectionTimeout);
  });
});

export { roomClients };

console.log(`🟢 WebSocket server is now running on the same port as HTTP.`);
