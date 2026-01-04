/**
 * Config redirect agent (IL2CPP-enabled).
 *
 * Goal: make UnityWebRequest accept the local TLS cert so we can iterate on
 * config endpoints served by the sandbox server.
 */

import "frida-il2cpp-bridge";
import { Patcher } from "./patchers/core/socket_patcher";

console.log("[AgentConfigIl2cpp]: loaded");

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
