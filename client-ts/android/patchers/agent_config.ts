/**
 * Minimal agent for fast iteration on config endpoints.
 *
 * - Redirects allowlisted config/game hostnames to core.py directly (no adb reverse).
 * - Enables basic cert/pinning bypass so the app accepts the local cert.
 * - Keeps hooks minimal so spawn-gating doesn't timeout.
 */

import { FridaMultipleUnpinning } from "./patchers/multiple_unpinning";
import { NativeTlsBypass } from "./patchers/native_tls_bypass";
import { Patcher } from "./patchers/core/socket_patcher";

console.log("[AgentConfig]: loaded");

FridaMultipleUnpinning.bypass(true);
try {
  NativeTlsBypass.enable(true);
  console.log("[AgentConfig]: Native TLS bypass enabled");
} catch (e) {
  console.log(`[AgentConfig]: Native TLS bypass failed: ${String(e)}`);
}

// Android emulator default host bridge IP. For physical devices, set to your LAN IP.
const TARGET_SERVER_IP = "10.0.2.2";
const TARGET_SSL_PORT = 443;
const TARGET_GAME_PORT = 12020;

const DOMAIN_ALLOWLIST = [
  "habby.mobi",
  "*.habby.mobi",
  "receiver.habby.mobi",
  "hotupdate-archero.habby.com",
  "*.archerosvc.com",
  "game-archero-v1.archerosvc.com",
  "config-archero.archerosvc.com",
  "config-archero.habby.mobi",
  "config-archero-test.habby.mobi",
  "mail-archero.habby.mobi",
];

const GAME_SERVER_IPS = [
  "52.196.213.239", // Tokyo
  "52.58.11.88", // Frankfurt
  "52.76.226.28", // Singapore
];

// Force allowlisted DNS results to the core.py host so TLS hits the sandbox cert.
Patcher.PatchGetaddrinfoAllowlist(
  DOMAIN_ALLOWLIST,
  TARGET_SERVER_IP,
  false,
  DOMAIN_ALLOWLIST
);

// Redirect sockets for allowlisted hosts / known game server IPs to core.py.
Patcher.ConfigureConnectRedirect({
  enabled: true,
  targetIp: TARGET_SERVER_IP,
  ports: [TARGET_SSL_PORT, TARGET_GAME_PORT],
  allowlistHosts: DOMAIN_ALLOWLIST,
  allowlistIps: GAME_SERVER_IPS,
});

// Install connect hook (redirects are handled by ConfigureConnectRedirect).
Patcher.PatchConnect(TARGET_SERVER_IP, [], false);
