/**
 * Archero Sandbox Server
 *
 * Implementation of the Archero game server protocol.
 * - HTTP API on port 8080 (for config, static data)
 * - TCP Binary Protocol on port 12020 (for game communication)
 *
 * Run: bun run dev
 */

import * as crypto from "node:crypto";
import * as net from "node:net";
import { Hono } from "hono";
import { logger } from "hono/logger";

import {
  BinaryReader,
  BinaryWriter,
  createDefaultLoginResponse,
  readCUserLoginPacket,
  writeCRespUserLoginPacket,
} from "./protocol";

const app = new Hono();

// =============================================================================
// PROTOCOL CONSTANTS
// =============================================================================

const ENCRYPTION_KEY = "4ptjerlkgjlk34jylkej4rgklj4klyj";
const API_KEY = "A63B6DBE18D84CA29887198B4ACBDEE9";

// Message types (from game analysis)
const MSG_TYPE_USER_LOGIN = 0x0001;
const MSG_TYPE_USER_LOGIN_RESP = 0x0002;

// =============================================================================
// ENCRYPTION HELPERS
// =============================================================================

function desEncrypt(plaintext: string): string {
  const keyBuffer = Buffer.from(ENCRYPTION_KEY.slice(0, 8));
  const iv = Buffer.alloc(8, 0);
  const cipher = crypto.createCipheriv("des-cbc", keyBuffer, iv);
  cipher.setAutoPadding(true);
  let encrypted = cipher.update(plaintext, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
}

// Unused but kept for reference
function _desDecrypt(ciphertext: string): string {
  const keyBuffer = Buffer.from(ENCRYPTION_KEY.slice(0, 8));
  const iv = Buffer.alloc(8, 0);
  const decipher = crypto.createDecipheriv("des-cbc", keyBuffer, iv);
  decipher.setAutoPadding(true);
  let decrypted = decipher.update(ciphertext, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function encryptResponse(data: object): string {
  const json = JSON.stringify(data);
  const base64 = Buffer.from(json).toString("base64");
  return desEncrypt(base64);
}

// =============================================================================
// REQUEST VERIFICATION
// =============================================================================

function verifyRequest(
  habbyTime: string | undefined,
  habbyCheck: string | undefined,
  body: Buffer,
): boolean {
  if (!habbyTime || !habbyCheck) {
    console.log("[Sandbox] Missing HabbyTime or HabbyCheck headers");
    return false;
  }

  const input = Buffer.concat([Buffer.from(API_KEY), Buffer.from(habbyTime), body]);

  const expected = crypto.createHash("sha256").update(input).digest("hex").toUpperCase();

  const valid = habbyCheck === expected;
  if (!valid) {
    console.log(`[Sandbox] Invalid signature`);
    console.log(`  Expected: ${expected}`);
    console.log(`  Got:      ${habbyCheck}`);
  }
  return valid;
}

// =============================================================================
// BINARY PROTOCOL HANDLER
// =============================================================================

interface Packet {
  msgType: number;
  payload: Buffer;
}

function parsePacket(data: Buffer): { packet: Packet; remaining: Buffer } | null {
  if (data.length < 4) return null;

  const length = data.readUInt32LE(0);
  if (data.length < 4 + length) return null;

  const msgType = data.readUInt16LE(4);
  const payload = data.subarray(6, 4 + length);
  const remaining = data.subarray(4 + length);

  return { packet: { msgType, payload }, remaining };
}

function createPacket(msgType: number, payload: Buffer): Buffer {
  const length = 2 + payload.length;
  const header = Buffer.alloc(6);
  header.writeUInt32LE(length, 0);
  header.writeUInt16LE(msgType, 4);
  return Buffer.concat([header, payload]);
}

function handlePacket(packet: Packet): Buffer | null {
  console.log(
    `[TCP] Received message type 0x${packet.msgType.toString(16).padStart(4, "0")} (${packet.payload.length} bytes)`,
  );

  switch (packet.msgType) {
    case MSG_TYPE_USER_LOGIN: {
      try {
        const reader = new BinaryReader(packet.payload);
        const loginReq = readCUserLoginPacket(reader);
        console.log(
          `[TCP] Login request: transId=${loginReq.m_nTransID}, platform="${loginReq.m_strPlatform}"`,
        );

        // Create login response
        const loginResp = createDefaultLoginResponse(loginReq.m_nTransID);
        const writer = new BinaryWriter();
        writeCRespUserLoginPacket(writer, loginResp);

        return createPacket(MSG_TYPE_USER_LOGIN_RESP, Buffer.from(writer.toBytes()));
      } catch (e) {
        console.error(`[TCP] Failed to handle login: ${e}`);
        return null;
      }
    }

    default:
      logUnknownPacket(packet);
      return null;
  }
}

/**
 * Verbose logging for unknown/unhandled packets
 * Prints hex dump, attempts to parse common field types, and shows structure
 */
function logUnknownPacket(packet: Packet): void {
  const { msgType, payload } = packet;

  console.log(`\n${"=".repeat(80)}`);
  console.log(
    `[UNKNOWN PACKET] Message Type: 0x${msgType.toString(16).padStart(4, "0")} (${msgType})`,
  );
  console.log(`${"=".repeat(80)}`);
  console.log(`Payload Size: ${payload.length} bytes`);
  console.log(`Timestamp: ${new Date().toISOString()}`);
  console.log();

  // Full hex dump with ASCII
  console.log(`[HEX DUMP]`);
  console.log(`${"─".repeat(80)}`);
  printHexDump(payload);
  console.log();

  // Try to parse common fields
  console.log(`[FIELD ANALYSIS]`);
  console.log(`${"─".repeat(80)}`);

  if (payload.length >= 4) {
    try {
      // Common packet patterns: transId first
      const u32_0 = payload.readUInt32LE(0);
      console.log(`  offset 0: UInt32 = ${u32_0} (possibly m_nTransID)`);

      if (payload.length >= 6) {
        const u16_4 = payload.readUInt16LE(4);
        console.log(`  offset 4: UInt16 = ${u16_4} (possibly m_nType/m_nRequestType)`);
      }

      if (payload.length >= 8) {
        const u16_6 = payload.readUInt16LE(6);
        console.log(`  offset 6: UInt16 = ${u16_6}`);
      }

      if (payload.length >= 12) {
        const u32_8 = payload.readUInt32LE(8);
        console.log(`  offset 8: UInt32 = ${u32_8}`);
      }

      // Try to find strings (length-prefixed)
      console.log();
      console.log(`[STRING SEARCH]`);
      console.log(`${"─".repeat(80)}`);
      findStrings(payload);
    } catch (e) {
      console.log(`  (failed to parse fields: ${e})`);
    }
  }

  console.log();
  console.log(`${"=".repeat(80)}\n`);
}

function printHexDump(buffer: Buffer): void {
  const bytesPerLine = 16;
  for (let i = 0; i < buffer.length; i += bytesPerLine) {
    const line = buffer.subarray(i, Math.min(i + bytesPerLine, buffer.length));

    // Offset
    const offset = i.toString(16).padStart(8, "0");

    // Hex bytes
    const hexParts: string[] = [];
    for (let j = 0; j < bytesPerLine; j++) {
      if (j < line.length) {
        hexParts.push(line[j].toString(16).padStart(2, "0"));
      } else {
        hexParts.push("  ");
      }
    }
    const hex = hexParts.join(" ");

    // ASCII representation
    let ascii = "";
    for (let j = 0; j < line.length; j++) {
      const byte = line[j];
      if (byte >= 32 && byte <= 126) {
        ascii += String.fromCharCode(byte);
      } else {
        ascii += ".";
      }
    }

    console.log(`  ${offset}  ${hex}  |${ascii}|`);
  }
}

function findStrings(buffer: Buffer): void {
  // Look for length-prefixed strings (UInt16 length + UTF-8 data)
  for (let i = 0; i < buffer.length - 2; i++) {
    const length = buffer.readUInt16LE(i);
    if (length > 0 && length < 500 && i + 2 + length <= buffer.length) {
      const str = buffer.subarray(i + 2, i + 2 + length);
      // Check if it looks like printable ASCII/UTF-8
      let printable = true;
      for (let j = 0; j < str.length; j++) {
        if (str[j] < 32 && str[j] !== 10 && str[j] !== 13 && str[j] !== 9) {
          printable = false;
          break;
        }
      }
      if (printable && str.length > 2) {
        const text = str.toString("utf8");
        console.log(
          `  offset ${i}: String[${length}] = "${text.substring(0, 100)}${text.length > 100 ? "..." : ""}"`,
        );
      }
    }
  }
}

// =============================================================================
// TCP SERVER (Binary Protocol)
// =============================================================================

const TCP_PORT = 12020;

const tcpServer = net.createServer((socket) => {
  console.log(`[TCP] Client connected from ${socket.remoteAddress}:${socket.remotePort}`);

  let buffer = Buffer.alloc(0);

  socket.on("data", (data) => {
    buffer = Buffer.concat([buffer, data]);
    console.log(`[TCP] Received ${data.length} bytes (buffer: ${buffer.length} bytes)`);

    // Try to parse complete packets
    let result: { packet: Packet; remaining: Buffer } | null = parsePacket(buffer);
    while (result !== null) {
      const { packet, remaining } = result;
      buffer = remaining;

      const response = handlePacket(packet);
      if (response) {
        socket.write(response);
        console.log(`[TCP] Sent response: ${response.length} bytes`);
      }

      result = parsePacket(buffer);
    }
  });

  socket.on("close", () => {
    console.log(`[TCP] Client disconnected`);
  });

  socket.on("error", (err) => {
    console.error(`[TCP] Socket error: ${err.message}`);
  });
});

tcpServer.listen(TCP_PORT, () => {
  console.log(`[TCP] Binary protocol server listening on port ${TCP_PORT}`);
});

// =============================================================================
// HTTP MIDDLEWARE
// =============================================================================

app.use("*", logger());

// Log all requests
app.use("*", async (c, next) => {
  const habbyType = c.req.header("HabbyType");
  const habbyVersion = c.req.header("HabbyVersion");
  console.log(`[HTTP] HabbyType=${habbyType} HabbyVersion=${habbyVersion}`);
  await next();
});

// =============================================================================
// HTTP ROUTES
// =============================================================================

// Health check
app.get("/", (c) => {
  return c.json({ status: "ok", server: "archero-sandbox" });
});

// Main game API endpoint (handles all HabbyType requests)
app.put("/", async (c) => {
  const habbyTime = c.req.header("HabbyTime");
  const habbyCheck = c.req.header("HabbyCheck");
  const habbyType = c.req.header("HabbyType");
  const _habbyVersion = c.req.header("HabbyVersion");

  // Get raw body
  const body = Buffer.from(await c.req.arrayBuffer());
  console.log(`[HTTP] Request body (${body.length} bytes)`);

  // Verify signature (optional - disable for testing)
  const VERIFY_SIGNATURES = false;
  if (VERIFY_SIGNATURES && !verifyRequest(habbyTime, habbyCheck, body)) {
    return c.json({ error: "Invalid signature" }, 403);
  }

  // Handle different endpoint types
  const endpointId = parseInt(habbyType || "0", 10);
  let responseData: object;

  switch (endpointId) {
    case 8:
      // Device/platform info
      responseData = { code: 0, msg: "ok" };
      break;

    case 255:
      // Initial sync
      responseData = { code: 0, msg: "ok", data: {} };
      break;

    default:
      // Generic success response
      responseData = { code: 0, msg: "ok" };
  }

  // Send encrypted response
  const encrypted = encryptResponse(responseData);
  c.header("Habby", "archero_zip");
  return c.text(encrypted);
});

// Config file endpoints
app.get("/data/config/:filename", (c) => {
  const filename = c.req.param("filename");
  console.log(`[HTTP] Config request: ${filename}`);

  // Return minimal valid config
  let config: object;

  switch (filename) {
    case "game_config.json":
      config = {
        key_max: 20,
        key_recover_second: 720,
        new_mail_open_1: 1,
      };
      break;

    default:
      config = {};
  }

  const encrypted = encryptResponse(config);
  c.header("Habby", "archero_zip");
  c.header("last-modified", new Date().toUTCString());
  return c.text(encrypted);
});

// =============================================================================
// START HTTP SERVER
// =============================================================================

const HTTP_PORT = 8080;

console.log(`
╔═══════════════════════════════════════════╗
║     Archero Sandbox Server                ║
╠═══════════════════════════════════════════╣
║     HTTP API:  http://localhost:${HTTP_PORT}      ║
║     TCP Game:  tcp://localhost:${TCP_PORT}     ║
╚═══════════════════════════════════════════╝
`);

export default {
  port: HTTP_PORT,
  fetch: app.fetch,
};
