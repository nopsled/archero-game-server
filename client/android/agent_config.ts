/**
 * Minimal agent for fast iteration on config endpoints.
 *
 * - Redirects allowlisted config/game hostnames to the local sandbox server via tlsRemap (443 -> 18443).
 * - Enables basic cert/pinning bypass so the app accepts the local cert.
 * - Keeps hooks minimal so spawn-gating doesn't timeout.
 */

import { FridaMultipleUnpinning } from "./multiple_unpinning";
import { NativeTlsBypass } from "./native_tls_bypass";
import { Patcher } from "./socket_patcher";

console.log("[AgentConfig]: loaded");

FridaMultipleUnpinning.bypass(true);
try {
  NativeTlsBypass.enable(true);
  console.log("[AgentConfig]: Native TLS bypass enabled");
} catch (e) {
  console.log(`[AgentConfig]: Native TLS bypass failed: ${String(e)}`);
}

const LOCAL_TLS_PORT = 18443;

const ALLOWLIST = [
  // Common config endpoints (from dumps + observed domains)
  "config-archero.habby.mobi",
  "config-archero-test.habby.mobi",
  "hotupdate-archero.habby.com",
  "game-archero-v1.archerosvc.com",
  "config-archero.archerosvc.com",
  "mail-archero.habby.mobi",
  "receiver.habby.mobi",
  "*.archerosvc.com",
];

Patcher.ConfigureTlsRemap({
  enabled: true,
  matchIp: "127.0.0.2",
  targetIp: "127.0.0.1",
  fromPort: 443,
  toPort: LOCAL_TLS_PORT,
  maxAgeMs: 5000,
});

// Force allowlisted DNS results to 127.0.0.2 so PatchConnect can remap.
Patcher.PatchGetaddrinfoAllowlist(ALLOWLIST, "127.0.0.2", false, ALLOWLIST);

// Install connect hook; do not patch any ports directly (tlsRemap handles 443 for allowlisted hosts).
Patcher.PatchConnect("127.0.0.1", [], false);
