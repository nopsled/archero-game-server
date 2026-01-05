/// <reference path="../../frida.d.ts" />

/**
 * Combined Port 443 + 12020 Redirect Patcher
 *
 * Redirects:
 * - Port 12020 (game binary protocol) -> Local Python server
 * - Port 443 (HTTPS) -> Only game-relevant domains (habby.mobi, habby.com)
 *
 * Includes SSL pinning bypass for HTTPS interception.
 */

import { NativeTlsBypass } from "./native_tls_bypass";
import { FridaMultipleUnpinning } from "./multiple_unpinning";
import { Patcher } from "./core/socket_patcher";

// ============= CONFIGURATION =============
const SANDBOX_IP = "10.0.1.9"; // Host machine IP (MuMuPlayer Pro uses bridge networking)

// Game-relevant domains to redirect (excludes ads, analytics, CDNs)
const GAME_DOMAINS = [
  "*.habby.mobi", // Game API (excluding receiver.habby.mobi which is analytics)
  "*.habby.com", // Account services
  "archero*.com", // Any archero domains
];

// Domains to EXCLUDE (ads, analytics, etc)
const EXCLUDED_DOMAINS = [
  "receiver.habby.mobi", // Analytics
  "*.adjust.com",
  "*.branch.io",
  "*.amplitude.com",
  "*.facebook.com",
  "*.fbcdn.net",
  "*.google.com",
  "*.googleapis.com",
  "*.applovin.com",
  "*.unity3d.com",
  "*.mopub.com",
  "*.vungle.com",
  "*.crashlytics.com",
  "*.firebase.io",
];

console.log("");
console.log("╔════════════════════════════════════════════════════════════════╗");
console.log("║   🎮 Combined Port 443 + 12020 Patcher                        ║");
console.log("╚════════════════════════════════════════════════════════════════╝");
console.log("");
console.log(`[Patcher] Target Server: ${SANDBOX_IP}`);
console.log(`[Patcher] Port 12020: ALL traffic redirected`);
console.log(`[Patcher] Port 443: Only game domains redirected`);
console.log("");

// ============= SSL PINNING BYPASS =============
console.log("[Patcher] Loading SSL pinning bypass...");

NativeTlsBypass.enable(true);

setTimeout(() => {
  try {
    FridaMultipleUnpinning.bypass(true);
    console.log("[Patcher] ✓ FridaMultipleUnpinning loaded");
  } catch (e) {
    console.log("[Patcher] FridaMultipleUnpinning deferred: " + e);
  }
}, 1000);

// ============= DNS MONITORING =============
// Watch game domains to build IP->hostname mapping for redirect decisions
Patcher.PatchGetaddrinfoAllowlist(
  [], // Don't redirect DNS, just watch
  SANDBOX_IP,
  false,
  GAME_DOMAINS // Watch these domains
);

// ============= PORT 12020 REDIRECT =============
// Redirect ALL 12020 traffic (binary game protocol)
Patcher.ConfigureConnectRedirect({
  enabled: true,
  targetIp: SANDBOX_IP,
  ports: [12020],
  allowlistHosts: [], // No allowlist = redirect all
  allowlistIps: [],
});

// ============= PORT 443 REDIRECT =============
// Only redirect game-relevant HTTPS traffic
// The patcher will use DNS cache to map IPs to hostnames
Patcher.ConfigureConnectRedirect({
  enabled: true,
  targetIp: SANDBOX_IP,
  ports: [443],
  allowlistHosts: GAME_DOMAINS,
  allowlistIps: [], // Will be populated dynamically from DNS
});

// ============= TRAFFIC CAPTURE =============
Patcher.EnableCapture({
  enabled: true,
  onlyPatched: true,
  ports: [12020, 443],
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
console.log("╔════════════════════════════════════════════════════════════════╗");
console.log("║   ✅ Combined Patcher Active                                  ║");
console.log("║   ► Port 12020: Binary protocol → Python server               ║");
console.log("║   ► Port 443: Game HTTPS → Python server (ads bypassed)       ║");
console.log("╚════════════════════════════════════════════════════════════════╝");
console.log("");
