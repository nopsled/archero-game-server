/// <reference path="../../frida.d.ts" />

/**
 * Port 12020 Redirect Patcher with Logging
 *
 * Redirects all port 12020 (game protocol) traffic to local Python server
 * with comprehensive IL2CPP logging for TcpNetManager, packets, and encryption.
 */

import { NativeTlsBypass } from "./native_tls_bypass";
import { FridaMultipleUnpinning } from "./multiple_unpinning";
import { Patcher } from "./core/socket_patcher";

// Configuration - matches Python server
const SANDBOX_IP = "10.0.2.2"; // Android emulator gateway to host
const GAME_PORT = 12020;
const DISCOVERY_DURATION_MS = 60000; // 60 seconds of logging

console.log("");
console.log("╔═══════════════════════════════════════════════════════════════╗");
console.log("║   🎮 Port 12020 Redirect + Logging                           ║");
console.log("╚═══════════════════════════════════════════════════════════════╝");
console.log("");
console.log(`[Patcher] Target Server: ${SANDBOX_IP}:${GAME_PORT}`);
console.log("");

// ============= SSL PINNING BYPASS =============
console.log("[Patcher] Loading SSL pinning bypass...");
NativeTlsBypass.enable(true);

setTimeout(() => {
  try {
    FridaMultipleUnpinning.bypass(true);
    console.log("[Patcher] ✓ FridaMultipleUnpinning loaded");
  } catch (e) {
    console.log("[Patcher] FridaMultipleUnpinning deferred: " + e);
  }
}, 1000);

// ============= PORT 12020 REDIRECT =============
Patcher.ConfigureConnectRedirect({
  enabled: true,
  targetIp: SANDBOX_IP,
  ports: [12020],
  allowlistHosts: [], // No allowlist - redirect ALL 12020 traffic
  allowlistIps: [],
});

// CRITICAL: Install the connect hook
Patcher.PatchConnect(SANDBOX_IP, [12020], true);

// Enable traffic capture for debugging
Patcher.EnableCapture({
  enabled: true,
  onlyPatched: true,
  ports: [12020],
  maxBytes: 4096,
  emitConsole: true,
  captureSyscalls: false,
  captureReadWrite: false,
  decodeEnabled: true,
  decodePorts: [12020],
  decodeMaxChunkBytes: 65536,
  decodeMaxFrameBytes: 256 * 1024,
  decodeMaxFramesPerSocket: 100,
  decodeLogPayloadBytes: 512,
});

console.log("");
console.log("╔═══════════════════════════════════════════════════════════════╗");
console.log("║   ✅ Port 12020 Redirect Active                              ║");
console.log("╚═══════════════════════════════════════════════════════════════╝");
console.log("");

// =============================================================================
// LOGGING
// =============================================================================

interface PacketCapture {
  t: number;
  direction: string;
  msgTypeName?: string;
  fields?: Record<string, any>;
}

const packetCaptures: PacketCapture[] = [];
const encryptionKeys: { t: number; type: string; key: string }[] = [];

let discoveryStartTime = 0;
let loginPacketSent = false;
let loginResponseReceived = false;

function elapsed(): number {
  return discoveryStartTime ? (Date.now() - discoveryStartTime) / 1000 : 0;
}

function ts(): string {
  return `[${elapsed().toFixed(2)}s]`;
}

function safeString(val: any): string {
  if (val === null || val === undefined) return "<null>";
  try {
    if (typeof val === "string") return val;
    if (typeof val === "number" || typeof val === "boolean") return String(val);
    if (val.toString && typeof val.toString === "function") {
      const s = val.toString();
      if (s !== "[object Object]" && s !== "") return s;
    }
    if (val.class?.name) return `[${val.class.name}]`;
  } catch (e) { }
  return "<unknown>";
}

function dumpAllFields(instance: any, depth: number = 0): Record<string, any> {
  const result: Record<string, any> = {};
  if (!instance || !instance.class) return result;

  try {
    instance.class.fields.forEach((field: any) => {
      try {
        const fieldName = field.name;
        const value = instance.field(fieldName).value;
        if (value === null || value === undefined) {
          result[fieldName] = "<null>";
          return;
        }
        const typeName = field.type?.name || "unknown";
        if (["Int32", "Int64", "UInt32", "UInt64", "Single", "Double", "Boolean"].includes(typeName)) {
          result[fieldName] = Number(value);
          return;
        }
        if (typeName === "String") {
          result[fieldName] = safeString(value);
          return;
        }
        if (typeName === "Byte[]") {
          try {
            result[fieldName] = { type: "Byte[]", length: value.length };
          } catch (e) {
            result[fieldName] = { type: "Byte[]", length: "?" };
          }
          return;
        }
        if (value.class && depth < 2) {
          const nested = dumpAllFields(value, depth + 1);
          result[fieldName] = Object.keys(nested).length > 0 ? { type: typeName, fields: nested } : { type: typeName };
          return;
        }
        result[fieldName] = safeString(value);
      } catch (e: any) {
        result[field.name] = `<error>`;
      }
    });
  } catch (e: any) { }
  return result;
}

function printFields(fields: Record<string, any>, indent: string = "│   "): void {
  for (const [key, value] of Object.entries(fields)) {
    if (value && typeof value === "object" && value.fields) {
      console.log(`${ts()} ${indent}${key}: {${value.type}}`);
      printFields(value.fields, indent + "  ");
    } else if (value && typeof value === "object" && value.type) {
      const extra = value.length !== undefined ? `, len=${value.length}` : "";
      console.log(`${ts()} ${indent}${key}: ${value.type}${extra}`);
    } else {
      const display = JSON.stringify(value);
      console.log(`${ts()} ${indent}${key}: ${display.length > 80 ? display.substring(0, 80) + "..." : display}`);
    }
  }
}

// =============================================================================
// IL2CPP HOOKS
// =============================================================================

function hookIl2Cpp(): void {
  console.log("[IL2CPP] Waiting for runtime...");

  Il2Cpp.perform(() => {
    discoveryStartTime = Date.now();
    console.log(`${ts()} [IL2CPP] Runtime ready, installing hooks...`);

    try {
      const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;
      hookLoginPackets(asm);
      hookTcpNetManager(asm);
      hookEncryption(asm);

      console.log(`\n${ts()} [READY] All hooks installed. Capturing for ${DISCOVERY_DURATION_MS / 1000}s...`);
      console.log("═".repeat(66));

      setTimeout(() => printSummary(), DISCOVERY_DURATION_MS);
    } catch (e) {
      console.log(`${ts()} [ERROR] Failed to hook: ${e}`);
    }
  });
}

function hookLoginPackets(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Login packets...`);
  const packetClasses = [
    "GameProtocol.CUserLoginPacket",
    "GameProtocol.CRespUserLoginPacket",
    "GameProtocol.CHeartBeatPacket",
    "GameProtocol.CRespHeartBeatPacket",
  ];

  for (const fullName of packetClasses) {
    try {
      const clazz = asm.class(fullName);
      const name = fullName.split(".").pop()!;

      try {
        clazz.method("WriteToStream").implementation = function (writer: any) {
          const fields = dumpAllFields(this);
          console.log(`\n${ts()} ┌─────────────────────────────────────────────────`);
          console.log(`${ts()} │ 📤 PACKET OUT: ${name}`);
          console.log(`${ts()} ├─────────────────────────────────────────────────`);
          printFields(fields);
          console.log(`${ts()} └─────────────────────────────────────────────────\n`);
          if (name === "CUserLoginPacket") loginPacketSent = true;
          packetCaptures.push({ t: elapsed(), direction: "C→S", msgTypeName: name, fields });
          return this.method("WriteToStream").invoke(writer);
        };
        console.log(`${ts()}   ✓ ${name}.WriteToStream`);
      } catch (e) { }

      try {
        clazz.method("ReadFromStream").implementation = function (reader: any) {
          const result = this.method("ReadFromStream").invoke(reader);
          const fields = dumpAllFields(this);
          console.log(`\n${ts()} ┌─────────────────────────────────────────────────`);
          console.log(`${ts()} │ 📥 PACKET IN: ${name}`);
          console.log(`${ts()} ├─────────────────────────────────────────────────`);
          printFields(fields);
          console.log(`${ts()} └─────────────────────────────────────────────────\n`);
          if (name === "CRespUserLoginPacket") loginResponseReceived = true;
          packetCaptures.push({ t: elapsed(), direction: "S→C", msgTypeName: name, fields });
          return result;
        };
        console.log(`${ts()}   ✓ ${name}.ReadFromStream`);
      } catch (e) { }
    } catch (e) { }
  }
}

function hookTcpNetManager(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] TcpNetManager...`);
  try {
    const tcpNetMgr = asm.class("TcpNetManager");

    try {
      tcpNetMgr.method("SendPacket").implementation = function (packet: any, msgId: any) {
        const packetType = packet?.class?.name || "unknown";
        console.log(`${ts()} [TCPNET] SendPacket(msgId=${msgId}) → ${packetType}`);
        return this.method("SendPacket").invoke(packet, msgId);
      };
      console.log(`${ts()}   ✓ TcpNetManager.SendPacket`);
    } catch (e) { }

    try {
      tcpNetMgr.method("HandleMsg").implementation = function (msgId: any, data: any) {
        const len = data?.length || 0;
        console.log(`${ts()} [TCPNET] HandleMsg(msgId=${msgId}) ← ${len} bytes`);
        return this.method("HandleMsg").invoke(msgId, data);
      };
      console.log(`${ts()}   ✓ TcpNetManager.HandleMsg`);
    } catch (e) { }
  } catch (e) {
    console.log(`${ts()}   ✗ TcpNetManager not found`);
  }
}

function hookEncryption(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Encryption...`);
  try {
    const rc4 = asm.class("RC4Encrypter");
    try {
      rc4.method(".ctor").implementation = function (key: any) {
        const keyStr = safeString(key);
        console.log(`${ts()} [CRYPTO] 🔑 RC4Encrypter.ctor`);
        console.log(`${ts()}   KEY: ${keyStr.substring(0, 64)}${keyStr.length > 64 ? "..." : ""}`);
        encryptionKeys.push({ t: elapsed(), type: "RC4_init", key: keyStr });
        return this.method(".ctor").invoke(key);
      };
      console.log(`${ts()}   ✓ RC4Encrypter.ctor`);
    } catch (e) { }
  } catch (e) { }
}

function printSummary(): void {
  const totalTime = elapsed();
  console.log("\n");
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║               PORT 12020 PROTOCOL SUMMARY                    ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
  console.log(`\n📊 Session: ${totalTime.toFixed(1)}s | Login sent: ${loginPacketSent ? "✓" : "✗"} | Login received: ${loginResponseReceived ? "✓" : "✗"}`);
  console.log(`\n🔐 Keys (${encryptionKeys.length}): ${encryptionKeys.map(k => k.key.substring(0, 16) + "...").join(", ")}`);
  console.log(`\n📦 Packets (${packetCaptures.length}): ${packetCaptures.map(p => `${p.direction === "C→S" ? "📤" : "📥"}${p.msgTypeName}`).join(", ")}`);
  console.log("\n" + "═".repeat(66));
}

// =============================================================================
// MAIN
// =============================================================================

hookIl2Cpp();
