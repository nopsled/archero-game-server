/**
 * Agent to try to provoke early port-12020 activity by breaking HTTPS (443).
 *
 * This is useful when the client only attempts the TCP game protocol after some
 * specific startup path.
 */

import { Patcher } from "./socket_patcher";

console.log("[AgentForce12020]: loaded");

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

// Patch only HTTPS to localhost so those requests fail fast; do NOT patch 12020.
Patcher.PatchConnect("127.0.0.1", [443], false);
