/**
 * Dev agent: config redirect + TLS bypass helpers + port-12020 capture.
 *
 * Use when you want the app to hit the local sandbox for config endpoints while
 * still capturing any eventual TCP game-protocol traffic on port 12020.
 */

import { FridaMultipleUnpinning } from "./multiple_unpinning";
import { NativeTlsBypass } from "./native_tls_bypass";
import { Patcher } from "./socket_patcher";

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

const LOCAL_TLS_PORT = 18443;
const ALLOWLIST = [
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

Patcher.PatchGetaddrinfoAllowlist(ALLOWLIST, "127.0.0.2", false, ALLOWLIST);
Patcher.PatchConnect("127.0.0.1", [], false);
