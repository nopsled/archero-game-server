/**
 * Dev agent: config redirect + TLS bypass helpers + port-12020 capture.
 *
 * Use when you want the app to hit the local sandbox for config endpoints while
 * still capturing any eventual TCP game-protocol traffic on port 12020.
 */

import { FridaMultipleUnpinning } from "./patchers/multiple_unpinning";
import { NativeTlsBypass } from "./patchers/native_tls_bypass";
import { Patcher } from "./patchers/socket_patcher";

console.log("[AgentDev]: loaded");

// Keep this enabled even if the system CA is installed; some SDKs pin.
FridaMultipleUnpinning.bypass(true);
try {
  NativeTlsBypass.enable(true);
  console.log("[AgentDev]: Native TLS bypass enabled");
} catch (e) {
  console.log(`[AgentDev]: Native TLS bypass failed: ${String(e)}`);
}

// Capture and decode the custom length-prefixed framing on port 12020 when it happens.
Patcher.EnableCapture({
  enabled: true,
  onlyTracked: false,
  onlyPatched: false,
  ports: [12020],
  maxBytes: 4096,
  emitMessages: false,
  emitConsole: true,
  captureReadWrite: true,
  captureSyscalls: false,
  decodeEnabled: true,
  decodePorts: [12020],
  decodeMaxChunkBytes: 65536,
  decodeMaxFrameBytes: 256 * 1024,
  decodeMaxFramesPerSocket: 50,
  decodeLogPayloadBytes: 256,
});

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

Patcher.PatchGetaddrinfoAllowlist(
  DOMAIN_ALLOWLIST,
  TARGET_SERVER_IP,
  false,
  DOMAIN_ALLOWLIST
);

Patcher.ConfigureConnectRedirect({
  enabled: true,
  targetIp: TARGET_SERVER_IP,
  ports: [TARGET_SSL_PORT, TARGET_GAME_PORT],
  allowlistHosts: DOMAIN_ALLOWLIST,
  allowlistIps: GAME_SERVER_IPS,
});

Patcher.PatchConnect(TARGET_SERVER_IP, [], false);
