/**
 * Archero Sandbox Server
 *
 * A barebones implementation of the Archero game server protocol.
 *
 * Run: bun run dev
 */

import { Hono } from "hono";
import { logger } from "hono/logger";
import * as crypto from "crypto";

const app = new Hono();

// =============================================================================
// PROTOCOL CONSTANTS
// =============================================================================

const ENCRYPTION_KEY = "4ptjerlkgjlk34jylkej4rgklj4klyj";
const API_KEY = "A63B6DBE18D84CA29887198B4ACBDEE9";

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

function desDecrypt(ciphertext: string): string {
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
  body: Buffer
): boolean {
  if (!habbyTime || !habbyCheck) {
    console.log("[Sandbox] Missing HabbyTime or HabbyCheck headers");
    return false;
  }

  const input = Buffer.concat([
    Buffer.from(API_KEY),
    Buffer.from(habbyTime),
    body,
  ]);

  const expected = crypto
    .createHash("sha256")
    .update(input)
    .digest("hex")
    .toUpperCase();

  const valid = habbyCheck === expected;
  if (!valid) {
    console.log(`[Sandbox] Invalid signature`);
    console.log(`  Expected: ${expected}`);
    console.log(`  Got:      ${habbyCheck}`);
  }
  return valid;
}

// =============================================================================
// MIDDLEWARE
// =============================================================================

app.use("*", logger());

// Log all requests
app.use("*", async (c, next) => {
  const habbyType = c.req.header("HabbyType");
  const habbyVersion = c.req.header("HabbyVersion");
  console.log(`[Sandbox] HabbyType=${habbyType} HabbyVersion=${habbyVersion}`);
  await next();
});

// =============================================================================
// ROUTES
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
  const habbyVersion = c.req.header("HabbyVersion");

  // Get raw body
  const body = Buffer.from(await c.req.arrayBuffer());
  console.log(`[Sandbox] Request body (${body.length} bytes)`);

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
  console.log(`[Sandbox] Config request: ${filename}`);

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
// START SERVER
// =============================================================================

const PORT = 8080;

console.log(`
╔═══════════════════════════════════════════╗
║     Archero Sandbox Server                ║
║     http://localhost:${PORT}                  ║
╚═══════════════════════════════════════════╝
`);

export default {
  port: PORT,
  fetch: app.fetch,
};
