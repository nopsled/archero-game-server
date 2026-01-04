/// <reference path="../../frida.d.ts" />

/**
 * Port 12020 Redirect Patcher
 * 
 * Redirects all port 12020 (game protocol) traffic to local Python server.
 */

import { Patcher } from "./core/socket_patcher";

// Configuration - matches Python server
const SANDBOX_IP = "10.0.1.22";  // Your local network IP
const GAME_PORT = 12020;

console.log("");
console.log("╔═══════════════════════════════════════════════════════════╗");
console.log("║   🎮 Port 12020 Redirect to Python Server                ║");
console.log("╚═══════════════════════════════════════════════════════════╝");
console.log("");
console.log(`[Port12020] Target: ${SANDBOX_IP}:${GAME_PORT}`);
console.log("");

// Enable connect() redirect for port 12020
Patcher.ConfigureConnectRedirect({
  enabled: true,
  targetIp: SANDBOX_IP,
  ports: [12020],
  allowlistHosts: [],  // No allowlist - redirect ALL 12020 traffic
  allowlistIps: [],
});

// Enable traffic capture for debugging
Patcher.EnableCapture({
  enabled: true,
  onlyPatched: true,
  ports: [12020],
  maxBytes: 4096,
  emitConsole: true,
  decodeEnabled: true,
  decodePorts: [12020],
  decodeMaxChunkBytes: 65536,
  decodeMaxFrameBytes: 256 * 1024,
  decodeMaxFramesPerSocket: 100,
  decodeLogPayloadBytes: 256,
});

console.log("");
console.log("╔═══════════════════════════════════════════════════════════╗");
console.log("║   ✅ Port 12020 Redirect Active                          ║");
console.log("╚═══════════════════════════════════════════════════════════╝");
console.log("");
