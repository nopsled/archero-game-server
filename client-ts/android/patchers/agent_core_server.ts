/**
 * Core server redirect agent (no adb reverse).
 *
 * Redirects Archero network endpoints directly to the host running core.py by
 * patching sockets at connect()/getaddrinfo() time.
 */

import { FridaMultipleUnpinning } from "./patchers/multiple_unpinning";
import { NativeTlsBypass } from "./patchers/native_tls_bypass";
import { Patcher } from "./patchers/core/socket_patcher";

console.log("[AgentCoreServer]: loaded");

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

FridaMultipleUnpinning.bypass(true);
try {
  NativeTlsBypass.enable(true);
  console.log("[AgentCoreServer]: Native TLS bypass enabled");
} catch (e) {
  console.log(`[AgentCoreServer]: Native TLS bypass failed: ${String(e)}`);
}

// Force allowlisted hostnames to resolve to the core.py host.
Patcher.PatchGetaddrinfoAllowlist(DOMAIN_ALLOWLIST, TARGET_SERVER_IP, false, DOMAIN_ALLOWLIST);

// Redirect sockets for allowlisted hosts / known game server IPs to the core.py host.
Patcher.ConfigureConnectRedirect({
  enabled: true,
  targetIp: TARGET_SERVER_IP,
  ports: [TARGET_SSL_PORT, TARGET_GAME_PORT],
  allowlistHosts: DOMAIN_ALLOWLIST,
  allowlistIps: GAME_SERVER_IPS,
});

// Install connect hook (redirects are handled by ConfigureConnectRedirect).
Patcher.PatchConnect(TARGET_SERVER_IP, [], false);
