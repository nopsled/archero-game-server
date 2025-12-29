/**
 * Minimal agent focused on capturing + decoding the TCP stream on port 12020.
 *
 * Intended for "real/original" protocol capture (no redirects, no TLS/Il2Cpp hooks),
 * so it should load quickly under spawn-gating.
 */

import { Patcher } from "./patchers/socket_patcher";

console.log("[Agent12020]: loaded");

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

// Track connect() so we can associate socket FDs with their remote port.
// No patching/redirecting.
Patcher.PatchConnect("127.0.0.1", [], false);
