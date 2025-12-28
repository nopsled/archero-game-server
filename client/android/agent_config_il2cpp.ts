/**
 * Config redirect agent (IL2CPP-enabled).
 *
 * Goal: make UnityWebRequest accept the local TLS cert so we can iterate on
 * config endpoints served by the sandbox server.
 */

import "frida-il2cpp-bridge";
import { Patcher } from "./socket_patcher";

console.log("[AgentConfigIl2cpp]: loaded");

const LOCAL_TLS_PORT = 18443;
const ALLOWLIST = [
  "hotupdate-archero.habby.com",
  "game-archero-v1.archerosvc.com",
  "config-archero.archerosvc.com",
  "*.archerosvc.com",
  "config-archero.habby.mobi",
  "config-archero-test.habby.mobi",
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

Il2Cpp.perform(() => {
  try {
    const unityWeb = Il2Cpp.domain.assembly("UnityEngine.UnityWebRequestModule").image;
    const certHandler = unityWeb.class("UnityEngine.Networking.CertificateHandler");

    const patchMethod = (name: string) => {
      try {
        const m = certHandler.method(name);
        m.implementation = function (...args: any[]) {
          // Always accept.
          return true;
        };
        console.log(`[AgentConfigIl2cpp]: patched CertificateHandler.${name} -> true`);
      } catch {
        // ignore missing
      }
    };

    patchMethod("ValidateCertificate");
    patchMethod("ValidateCertificateNative");
  } catch (e) {
    console.log(`[AgentConfigIl2cpp]: failed to patch CertificateHandler: ${String(e)}`);
  }
});
