/// <reference path="../../frida.d.ts" />

/**
 * Combined Patcher + Logger for Port 443 + 12020
 *
 * This script BOTH:
 * 1. Redirects traffic to the local Python server 
 * 2. Logs all packets, TLS, and storage in real-time
 *
 * Usage:
 *   bun run patcher_logging:443_12020
 */

import "frida-il2cpp-bridge";
import { NativeTlsBypass } from "./native_tls_bypass";
import { Patcher } from "./core/socket_patcher";

console.log("");
console.log("╔════════════════════════════════════════════════════════════════╗");
console.log("║   🎮 Combined Patcher + Logger (443 + 12020)                  ║");
console.log("║   ► Redirects traffic to local server                         ║");
console.log("║   ► Logs packets, TLS, and storage in real-time              ║");
console.log("╚════════════════════════════════════════════════════════════════╝");
console.log("");

// =============================================================================
// CONFIGURATION
// =============================================================================

const SANDBOX_IP = "10.0.1.9"; // Host machine IP
const LOG_STORAGE = true;
const MAX_CAPTURE_BYTES = 4096;
const MAX_PREVIEW_LEN = 100;

// Game-relevant domains for 443 redirect
const GAME_DOMAINS = [
  "*.habby.mobi",
  "*.habby.com",
  "archero*.com",
];

// =============================================================================
// STATE TRACKING
// =============================================================================

let startTime = 0;
const ipToHostname = new Map<string, string>();
const fdToAddr = new Map<number, { ip: string; port: number }>();
let gameServerEndpoint = { host: "unknown", port: 12020 };

// Stats
const stats = {
  packets: { sent: 0, received: 0 },
  storage: { prefs: 0, save: 0, asset: 0 },
  connections: 0,
};

// =============================================================================
// HELPERS
// =============================================================================

function elapsed(): number { return startTime > 0 ? (Date.now() - startTime) / 1000 : 0; }
function ts(): string { return `[${elapsed().toFixed(2)}s]`; }

function safeString(val: any): string {
  if (val === null || val === undefined) return "null";
  try {
    if (val.class?.name === "String") return JSON.stringify(val.content ?? "");
    return String(val);
  } catch { return "<error>"; }
}

function preview(str: string, len = MAX_PREVIEW_LEN): string {
  return str.length > len ? str.substring(0, len) + "..." : str;
}

// =============================================================================
// IL2CPP FIELD DUMPING
// =============================================================================

function dumpAllFields(instance: any, depth = 0): Record<string, any> {
  if (depth > 2) return { _depth: "max" };
  const result: Record<string, any> = {};
  try {
    if (!instance || !instance.class) return result;
    instance.class.fields.forEach((field: any) => {
      if (field.isStatic) return;
      const fieldName = field.name;
      const typeName = field.type?.name || "unknown";
      try {
        const value = instance.field(fieldName).value;
        if (value === null || value === undefined) { result[fieldName] = null; return; }
        if (typeName === "String") { result[fieldName] = value.content ?? null; return; }
        if (typeName === "Boolean" || typeName === "bool") { result[fieldName] = !!value; return; }
        if (["Int32", "UInt32", "Int64", "UInt64", "Int16", "UInt16", "Byte", "SByte", "Single", "Double"].includes(typeName)) {
          result[fieldName] = Number(value); return;
        }
        if (typeName === "Byte[]") {
          const len = value.length || 0;
          if (len > 0 && len <= 128) {
            let hex = "";
            for (let i = 0; i < Math.min(len, 32); i++) hex += value.get(i).toString(16).padStart(2, "0");
            if (len > 32) hex += `...(${len})`;
            result[fieldName] = { type: "byte[]", len, hex };
          } else {
            result[fieldName] = { type: "byte[]", len };
          }
          return;
        }
        if (typeName.endsWith("[]")) { result[fieldName] = { type: typeName, len: value.length || 0 }; return; }
        if (typeName.startsWith("List`1") || typeName.startsWith("Dictionary`2")) {
          try { result[fieldName] = { type: typeName.split("`")[0], count: Number(value.method("get_Count").invoke()) }; }
          catch { result[fieldName] = { type: typeName.split("`")[0] }; }
          return;
        }
        if (value.class && depth < 2) {
          const nested = dumpAllFields(value, depth + 1);
          if (Object.keys(nested).length > 0) result[fieldName] = { type: typeName, fields: nested };
          return;
        }
        result[fieldName] = safeString(value);
      } catch { result[fieldName] = `<error>`; }
    });
  } catch { }
  return result;
}

function printFields(fields: Record<string, any>, indent = "│   "): void {
  for (const [key, value] of Object.entries(fields)) {
    if (value && typeof value === "object" && value.fields) {
      console.log(`${ts()} ${indent}${key}: {${value.type}}`);
      printFields(value.fields, indent + "  ");
    } else if (value && typeof value === "object" && value.type) {
      const extra = value.len !== undefined ? `, len=${value.len}` : value.count !== undefined ? `, count=${value.count}` : "";
      const hex = value.hex ? ` [${value.hex.substring(0, 24)}...]` : "";
      console.log(`${ts()} ${indent}${key}: ${value.type}${extra}${hex}`);
    } else {
      const display = JSON.stringify(value);
      console.log(`${ts()} ${indent}${key}: ${display.length > 60 ? display.substring(0, 60) + "..." : display}`);
    }
  }
}

// =============================================================================
// NATIVE HOOKS: DNS + CONNECT (Simplified for logging only)
// =============================================================================

function hookNativeNetwork(): void {
  console.log("[NATIVE] Setting up network logging hooks...");
  const libc = Process.getModuleByName("libc.so");

  // getaddrinfo - to map IPs to hostnames
  try {
    const ptr = libc.findExportByName("getaddrinfo");
    if (ptr) {
      Interceptor.attach(ptr, {
        onEnter(args) {
          try { (this as any).hostname = args[0].readUtf8String(); (this as any).result = args[3]; }
          catch { (this as any).hostname = null; }
        },
        onLeave(retval) {
          try {
            const hostname = (this as any).hostname;
            const resultPtr = (this as any).result;
            if (hostname && retval.toInt32() === 0 && resultPtr) {
              let ai = resultPtr.readPointer();
              let count = 0;
              while (!ai.isNull() && count < 50) {
                count++;
                try {
                  const family = ai.add(4).readS32();
                  if (family === 2) {
                    const addr = ai.add(Process.pointerSize === 8 ? 24 : 16).readPointer();
                    if (!addr.isNull()) {
                      const ip = `${addr.add(4).readU8()}.${addr.add(5).readU8()}.${addr.add(6).readU8()}.${addr.add(7).readU8()}`;
                      ipToHostname.set(ip, hostname);
                    }
                  }
                  ai = ai.add(Process.pointerSize === 8 ? 40 : 28).readPointer();
                } catch { break; }
              }
            }
          } catch { }
        },
      });
      console.log("   ✓ getaddrinfo");
    }
  } catch { }

  // connect - to log connections
  try {
    const ptr = libc.findExportByName("connect");
    if (ptr) {
      Interceptor.attach(ptr, {
        onEnter(args) {
          try {
            const fd = args[0].toInt32();
            const sockaddr = args[1];
            const family = sockaddr.readU16();
            if (family === 2) {
              const portBE = sockaddr.add(2).readU16();
              const port = ((portBE & 0xff) << 8) | ((portBE >> 8) & 0xff);
              const ip = `${sockaddr.add(4).readU8()}.${sockaddr.add(5).readU8()}.${sockaddr.add(6).readU8()}.${sockaddr.add(7).readU8()}`;
              fdToAddr.set(fd, { ip, port });
              if (port === 443 || port === 12020) {
                stats.connections++;
                const hostname = ipToHostname.get(ip) || ip;
                console.log(`${ts()} [CONNECT] ${hostname}:${port}`);
                if (port === 12020) {
                  gameServerEndpoint = { host: hostname, port };
                }
              }
            }
          } catch { }
        },
      });
      console.log("   ✓ connect");
    }
  } catch { }
}

// =============================================================================
// IL2CPP HOOKS: Game Protocol
// =============================================================================

function hookGameProtocol(): void {
  console.log("[IL2CPP] Waiting for runtime...");

  Il2Cpp.perform(() => {
    startTime = Date.now();
    console.log(`${ts()} [IL2CPP] Runtime ready, installing hooks...`);

    try {
      const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;
      hookTcpNetManager(asm);
      hookEncryption(asm);
      if (LOG_STORAGE) hookStorage(asm);

      console.log(`\n${ts()} [READY] All hooks installed. Logging in real-time...`);
      console.log("═".repeat(66));
    } catch (e) {
      console.log(`${ts()} [ERROR] Failed to hook IL2CPP: ${e}`);
    }
  });
}

function hookTcpNetManager(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] TcpNetManager...`);

  try {
    const tcpMgr = asm.class("TcpNetManager");
    tcpMgr.method("SendPacket").implementation = function (packet: Il2Cpp.Object) {
      try {
        const packetClass = packet.class;
        const packetName = packetClass.name;

        console.log(`\n${ts()} ┌────────────────────────────────────────────────────────────`);
        console.log(`${ts()} │ 📤 ${gameServerEndpoint.host}:${gameServerEndpoint.port} ← ${packetName}`);
        console.log(`${ts()} ├────────────────────────────────────────────────────────────`);

        const fields = dumpAllFields(packet);
        printFields(fields);
        console.log(`${ts()} └───────────────────────────────────────────\n`);

        stats.packets.sent++;
      } catch { }

      return this.method("SendPacket").invoke(packet);
    };
    console.log(`${ts()}   ✓ TcpNetManager.SendPacket`);
  } catch { }

  // Also hook HandleMsg to see received packets
  try {
    const tcpMgr = asm.class("TcpNetManager");
    tcpMgr.method("HandleMsg").implementation = function (msg: Il2Cpp.Object) {
      try {
        const msgClass = msg.class;
        const msgName = msgClass.name;

        console.log(`\n${ts()} ┌────────────────────────────────────────────────────────────`);
        console.log(`${ts()} │ 📥 ${gameServerEndpoint.host}:${gameServerEndpoint.port} → ${msgName}`);
        console.log(`${ts()} ├────────────────────────────────────────────────────────────`);

        const fields = dumpAllFields(msg);
        printFields(fields);
        console.log(`${ts()} └───────────────────────────────────────────\n`);

        stats.packets.received++;
      } catch { }

      return this.method("HandleMsg").invoke(msg);
    };
    console.log(`${ts()}   ✓ TcpNetManager.HandleMsg`);
  } catch { }
}

function hookEncryption(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Encryption...`);

  try {
    const rc4 = asm.class("RC4Encrypter");
    rc4.method(".ctor").implementation = function (...args: any[]) {
      const result = this.method(".ctor").invoke(...args);
      try {
        const key = this.field("m_arrayKey").value as any;
        if (key) {
          let keyHex = "";
          const len = Math.min(key.length || 0, 16);
          for (let i = 0; i < len; i++) keyHex += key.get(i).toString(16).padStart(2, "0");
          console.log(`${ts()} [CRYPTO] RC4 key: ${keyHex}`);
        }
      } catch { }
      return result;
    };
    console.log(`${ts()}   ✓ RC4Encrypter.ctor`);
  } catch { }
}

function hookStorage(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Storage...`);

  // LocalSave
  try {
    const localSave = asm.class("LocalSave");
    try {
      localSave.method("InitSaveData").implementation = function () {
        console.log(`${ts()} [SAVE] InitSaveData`);
        stats.storage.save++;
        return this.method("InitSaveData").invoke();
      };
      console.log(`${ts()}   ✓ LocalSave.InitSaveData`);
    } catch { }
    try {
      localSave.method("SaveDataRefresh").implementation = function () {
        console.log(`${ts()} [SAVE] SaveDataRefresh`);
        stats.storage.save++;
        return this.method("SaveDataRefresh").invoke();
      };
      console.log(`${ts()}   ✓ LocalSave.SaveDataRefresh`);
    } catch { }
  } catch { }

  // PlayerPrefsEncrypt
  try {
    const prefsEncrypt = asm.class("PlayerPrefsEncrypt");
    const getMethods = ["GetString", "GetInt", "GetBool", "GetLong"];
    for (const m of getMethods) {
      try {
        prefsEncrypt.method(m).implementation = function (...args: any[]) {
          const key = safeString(args[0]);
          const result = this.method(m).invoke(...args);
          const value = safeString(result);
          console.log(`${ts()} [PREFS] ${m}(${preview(key, 30)}) = ${preview(value, 50)}`);
          stats.storage.prefs++;
          return result;
        };
      } catch { }
    }
    console.log(`${ts()}   ✓ PlayerPrefsEncrypt`);
  } catch { }

  // ResourceManager
  try {
    const resourceMgr = asm.class("ResourceManager");
    resourceMgr.method("GetAssetBundle").implementation = function (...args: any[]) {
      const name = safeString(args[0]);
      console.log(`${ts()} [ASSET] GetAssetBundle(${preview(name, 40)})`);
      stats.storage.asset++;
      return this.method("GetAssetBundle").invoke(...args);
    };
    console.log(`${ts()}   ✓ ResourceManager.GetAssetBundle`);
  } catch { }
}

// =============================================================================
// SOCKET PATCHER SETUP
// =============================================================================

function setupSocketPatcher(): void {
  console.log("[PATCHER] Setting up socket redirection...");
  console.log(`[PATCHER] Target: ${SANDBOX_IP}`);

  // SSL pinning bypass
  NativeTlsBypass.enable(true);

  // Watch DNS for game domains
  Patcher.PatchGetaddrinfoAllowlist(
    [],
    SANDBOX_IP,
    false,
    GAME_DOMAINS
  );

  // Redirect port 12020 (all traffic)
  Patcher.ConfigureConnectRedirect({
    enabled: true,
    targetIp: SANDBOX_IP,
    ports: [12020],
    allowlistHosts: [],
    allowlistIps: [],
  });

  // Redirect port 443 (only game domains)
  Patcher.ConfigureConnectRedirect({
    enabled: true,
    targetIp: SANDBOX_IP,
    ports: [443],
    allowlistHosts: GAME_DOMAINS,
    allowlistIps: [],
  });

  // Enable capture for console output
  Patcher.EnableCapture({
    enabled: true,
    onlyPatched: true,
    ports: [12020, 443],
    maxBytes: MAX_CAPTURE_BYTES,
    emitConsole: true,
    decodeEnabled: true,
    decodePorts: [12020],
    decodeMaxChunkBytes: 65536,
    decodeMaxFrameBytes: 256 * 1024,
    decodeMaxFramesPerSocket: 100,
    decodeLogPayloadBytes: 256,
  });

  console.log("[PATCHER] ✓ Redirection configured");
}

// =============================================================================
// MAIN
// =============================================================================

// Run native hooks first (before socket patcher loads)
hookNativeNetwork();

// Setup socket patcher for redirection
setupSocketPatcher();

// Hook IL2CPP for packet and storage logging
hookGameProtocol();

console.log("");
console.log("╔════════════════════════════════════════════════════════════════╗");
console.log("║   ✅ Combined Patcher + Logger Active                         ║");
console.log("║   ► Port 12020: Binary protocol → Python server               ║");
console.log("║   ► Port 443: Game HTTPS → Python server                      ║");
console.log("║   ► Real-time logging of packets, TLS, storage                ║");
console.log("╚════════════════════════════════════════════════════════════════╝");
console.log("");
