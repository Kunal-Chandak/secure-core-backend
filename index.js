// import express from "express";
// import dotenv from "dotenv";
// import roomRoutes from "./routes/room.routes.js";
// import fileRoutes from "./routes/file.routes.js";
// import { WebSocketServer } from "ws";
// import { handleMessage } from "./controllers/message.controller.js";
// import { startPeriodicCleanup } from "./controllers/room.controller.js";

// dotenv.config();

// const app = express();
// app.use(express.json());

// app.use("/room", roomRoutes);
// app.use("/file", fileRoutes);

// const PORT = process.env.PORT || 3001;
// app.listen(PORT, () => {
//   console.log(`🚀 SecureCore backend running on port ${PORT}`);
//   startPeriodicCleanup(); // Start S3 cleanup job
// }, '0.0.0.0');

// // ---------------- WebSocket Server ----------------
// const WS_PORT = process.env.WS_PORT || 8081;
// const wss = new WebSocketServer({ port: WS_PORT });

// // Map of roomHash to Set of WebSocket clients
// const roomClients = new Map();

// wss.on("connection", (ws) => {
//   console.log("🟢 New WebSocket connection");

//   ws.on("message", async (rawData) => {
//     try {
//       const data = JSON.parse(rawData);
//       await handleMessage(ws, data, wss, roomClients);
//     } catch (err) {
//       console.error("WS message parse error:", err);
//       ws.send(JSON.stringify({ success: false, error: "INVALID_MESSAGE" }));
//     }
//   });

//   ws.on("close", () => {
//     console.log("🔴 WebSocket connection closed");
//     // Remove from all rooms
//     for (const [roomHash, clients] of roomClients) {
//       clients.delete(ws);
//       if (clients.size === 0) {
//         roomClients.delete(roomHash);
//       }
//     }
//   });
// });

// export { roomClients };

// console.log(`🟢 WebSocket server is now running.`);


import express from "express";
import dotenv from "dotenv";
import http from "http";
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

// 👇 CREATE HTTP SERVER
const server = http.createServer(app);

// 👇 ATTACH WEBSOCKET TO SAME SERVER
const wss = new WebSocketServer({ server });

// Map of roomHash → Set of clients
const roomClients = new Map();

wss.on("connection", (ws) => {
  console.log("🟢 WebSocket connected");

  ws.on("message", async (rawData) => {
    try {
      const data = JSON.parse(rawData);
      await handleMessage(ws, data, wss, roomClients);
    } catch (err) {
      console.error("WS message error:", err);
      ws.send(JSON.stringify({ success: false, error: "INVALID_MESSAGE" }));
    }
  });

  ws.on("close", () => {
    console.log("🔴 WebSocket disconnected");
    for (const [roomHash, clients] of roomClients) {
      clients.delete(ws);
      if (clients.size === 0) roomClients.delete(roomHash);
    }
  });
});

// 👇 USE ONLY ONE PORT
const PORT = process.env.PORT || 3001;
server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 SecureCore running on port ${PORT}`);
  startPeriodicCleanup();
});

export { roomClients };



