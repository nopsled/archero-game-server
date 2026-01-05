/// <reference path="../../frida.d.ts" />

import "frida-il2cpp-bridge";

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
const SANDBOX_IP = "10.0.2.2"; // Host machine IP (MuMuPlayer Pro uses bridge networking)

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

// ============= IL2CPP BYPASS =============
// ============= IL2CPP BYPASS =============
function hookCertificateHandler() {
  Il2Cpp.perform(() => {
    try {
      // 1. Hook UnityEngine.Networking.CertificateHandler
      const assembly = Il2Cpp.domain.tryAssembly("UnityEngine.CoreModule") ||
        Il2Cpp.domain.tryAssembly("UnityEngine.Networking");

      if (assembly) {
        const CertificateHandler = assembly.image.tryClass("UnityEngine.Networking.CertificateHandler");
        if (CertificateHandler) {
          const validateMethod = CertificateHandler.tryMethod("ValidateCertificate", 1);
          if (validateMethod) {
            validateMethod.implementation = function (certificateData: Il2Cpp.Object) {
              console.log("[CertificateHandler] ValidateCertificate called -> Bypassing");
              return true;
            };
            console.log("[Patcher] ✓ UnityEngine.Networking.CertificateHandler.ValidateCertificate hooked");
          }
        }
      }

      // 2. Hook HabbyClient (Observation)
      const habbyAssembly = Il2Cpp.domain.tryAssembly("Assembly-CSharp");
      if (habbyAssembly) {
        const HabbyClient = habbyAssembly.image.tryClass("HabbyClient");
        if (HabbyClient) {
          const ctor = HabbyClient.tryMethod(".ctor");
          if (ctor) {
            ctor.implementation = function () {
              console.log("[HabbyClient] Constructor called");
              return this.method(".ctor").invoke();
            }
          }
        }
      }

      // 3. Hook BestHTTP LegacyTlsAuthentication
      // BestHTTP uses BouncyCastle. We hook LegacyTlsAuthentication.NotifyServerCertificate
      // and force it to do nothing (swallow the exception).
      const bestHttpAssembly = Il2Cpp.domain.tryAssembly("BestHTTP");
      if (bestHttpAssembly) {
        const LegacyTlsAuth = bestHttpAssembly.image.tryClass("BestHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Tls.LegacyTlsAuthentication");
        if (LegacyTlsAuth) {
          const notifyMethod = LegacyTlsAuth.tryMethod("NotifyServerCertificate", 1);
          if (notifyMethod) {
            notifyMethod.implementation = function (cert: Il2Cpp.Object) {
              console.log("[BestHTTP] NotifyServerCertificate called -> Bypassing verification");
              // Do nothing = no exception thrown = success
              return;
            };
            console.log("[Patcher] ✓ BestHTTP LegacyTlsAuthentication hooked");
          } else {
            console.log("[Patcher] ! BestHTTP LegacyTlsAuthentication found but NotifyServerCertificate method missing");
          }
        } else {
          console.log("[Patcher] ! BestHTTP assembly found but LegacyTlsAuthentication class missing");
        }
      }

      // 4. Hook System.Net.ServicePointManager (Generic .NET)
      const systemAssembly = Il2Cpp.domain.tryAssembly("System");
      if (systemAssembly) {
        const ServicePointManager = systemAssembly.image.tryClass("System.Net.ServicePointManager");
        if (ServicePointManager) {
          // We can't easily overwrite a static property's backing field via method hooking directly.
          // Instead, we will look for the setter method and hook it to always ignore the input and set our own,
          // OR better yet, just execute code to SET it to a permissive delegate once.
          // But IL2CPP makes creating a delegate from scratch hard without a matching method signature available.
          // So we hook the *validation* itself if possible, but that's a callback.
          //
          // Alternative: Hook the property getter to always return our custom validator?
          // A safer bet is to hook the validation logic inside the internal validator if we can find it,
          // OR hook `ServerCertificateValidationCallback` property SETTER to force it to be null (some defaults are permissive)
          // or properly hook any method that CHECKS it.
          //
          // Let's try to just hook the `get_ServerCertificateValidationCallback` to return a custom delegate
          // requires creating a delegate object in IL2CPP memory which is complex.
          //
          // PLAN B: Start simple. Hook `CheckCertificateRevocationList` and return false.
          const checkRevocation = ServicePointManager.tryMethod("get_CheckCertificateRevocationList");
          if (checkRevocation) {
            checkRevocation.implementation = function () {
              return false;
            };
          }

          // Also hook `set_ServerCertificateValidationCallback` to log when it's set
          const setCallback = ServicePointManager.tryMethod("set_ServerCertificateValidationCallback");
          if (setCallback) {
            setCallback.implementation = function (callback: Il2Cpp.Object) {
              console.log("[ServicePointManager] set_ServerCertificateValidationCallback called - Intercepting?");
              // Ideally we would replace `callback` with our own, but creating one is hard.
              // For now, let's just log. If this is called, we know standard .NET is being used.
              return this.method("set_ServerCertificateValidationCallback").invoke(callback);
            }
          }
        }
      }


    } catch (e) {
      console.log("[Patcher] CertificateHandler hook failed: " + e);
    }
  });
}

// ============= NATIVE HOOKS =============
// Sync from logging script to Ensure BoringSSL/OpenSSL hooks are active
function hookNativeTLS() {
  // Ensure SSL_set_custom_verify is hooked if present (covered by NativeTlsBypass, but reinforcing)
  const modules = Process.enumerateModules();
  for (const mod of modules) {
    const name = mod.name.toLowerCase();
    if (!name.includes("ssl") && !name.includes("crypto") && !name.includes("boring")) continue;

    const setCustomVerify = mod.findExportByName("SSL_set_custom_verify");
    if (setCustomVerify) {
      Interceptor.attach(setCustomVerify, {
        onEnter(args) {
          args[1] = ptr(0); // mode = SSL_VERIFY_NONE
          args[2] = ptr(0); // callback = null
          // console.log(`[NativeTLS] Forced SSL_VERIFY_NONE on ${mod.name}`);
        }
      });
    }
  }
}

// ============= MAIN EXECUTION =============

// 1. Enable Native TLS Bypass (BoringSSL/mbedTLS/OpenSSL)
NativeTlsBypass.enable(true);

// 2. Enable IL2CPP CertificateHandler Bypass
hookCertificateHandler();

// 3. Reinforce Native TLS hooks
hookNativeTLS();

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

// ============= INSTALL CONNECT HOOK =============
// CRITICAL: ConfigureConnectRedirect only sets config, PatchConnect actually installs the hook!
Patcher.PatchConnect(SANDBOX_IP, [12020, 443], true);

// ============= TRAFFIC CAPTURE (DISABLED syscall hooks to prevent freeze) =============
Patcher.EnableCapture({
  enabled: true,
  onlyPatched: true,
  ports: [12020, 443],
  maxBytes: 4096,
  emitConsole: true,
  captureSyscalls: false,   // ← DISABLED: raw syscall() hooks cause freeze
  captureReadWrite: false,  // ← DISABLED: read/write hooks too heavy
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
console.log("║   ► Certificate Bypass: Native + IL2CPP                       ║");
console.log("╚════════════════════════════════════════════════════════════════╝");
console.log("");
