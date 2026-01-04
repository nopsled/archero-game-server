/**
 * Authentication Flow Discovery Tool
 *
 * Captures the complete authentication/login sequence during the first 15-30 seconds
 * of game startup to understand the server communication protocol for emulation.
 *
 * Hooks:
 *   - GameProtocol login packets (CUserLoginPacket, CRespUserLoginPacket)
 *   - Network layer (NetManager, TcpServer, TcpPacket)
 *   - Binary serialization (CustomBinaryReader/Writer)
 *   - HTTP requests (Habby.Tool.Http, HTTPSendClient)
 *   - Encryption (NetEncrypt, RC4Encrypter)
 *   - DNS and socket connections
 *
 * Output: Real-time console log + structured JSON summary
 *
 * Usage:
 *   bun run build:auth-discovery
 *   adb shell am force-stop com.habby.archero
 *   adb shell monkey -p com.habby.archero -c android.intent.category.LAUNCHER 1
 *   sleep 3
 *   frida -U -N com.habby.archero -l android/build/auth_flow_discovery.js 2>&1 | tee logs/sessions/auth_$(date +%Y%m%d_%H%M%S).log
 */

import "frida-il2cpp-bridge";
import { FridaMultipleUnpinning } from "../patchers/multiple_unpinning";
import { NativeTlsBypass } from "../patchers/native_tls_bypass";

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║        ARCHERO AUTHENTICATION FLOW DISCOVERY                ║");
console.log("║        Capturing first 30 seconds of startup                ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

// =============================================================================
// CONFIGURATION
// =============================================================================

const DISCOVERY_DURATION_MS = 30000; // 30 seconds - covers full login sequence
const ENABLE_SSL_BYPASS = true;
const VERBOSE_BINARY_OPS = false; // Set true to log every Read/Write call

// =============================================================================
// DATA STRUCTURES
// =============================================================================

interface AuthEvent {
  t: number;           // elapsed time (seconds)
  phase: string;       // "dns" | "connect" | "http" | "tcp" | "packet" | "crypto" | "binary"
  direction?: string;  // "C→S" (client to server) or "S→C" (server to client)
  class?: string;
  method?: string;
  data: Record<string, any>;
}

interface PacketCapture {
  t: number;
  direction: string;
  msgType: number;
  msgTypeName?: string;
  rawHex?: string;
  fields?: Record<string, any>;
}

const authEvents: AuthEvent[] = [];
const packetCaptures: PacketCapture[] = [];
const dnsLookups = new Map<string, string[]>();
const connections: { ip: string; port: number; t: number }[] = [];
const httpRequests: { t: number; url: string; method: string; headers?: Record<string, string> }[] = [];

let discoveryStartTime = 0;
let loginPacketSent = false;
let loginResponseReceived = false;

// Known message types from protocol analysis
const MESSAGE_TYPES: Record<number, string> = {
  0x0001: "CUserLoginPacket",
  0x0002: "CRespUserLoginPacket",
  0x0003: "CHeartBeatPacket",
  0x0004: "CRespHeartBeatPacket",
  0x0005: "CSyncUserPacket",
  0x0006: "CRespSyncUserPacket",
  // Add more as discovered
};

// =============================================================================
// HELPERS
// =============================================================================

function elapsed(): number {
  return (Date.now() - discoveryStartTime) / 1000;
}

function ts(): string {
  return `[${elapsed().toFixed(2)}s]`;
}

function logEvent(event: AuthEvent): void {
  authEvents.push(event);
}

function formatHex(bytes: number[], maxLen = 64): string {
  const hex = bytes.slice(0, maxLen).map(b => b.toString(16).padStart(2, '0')).join(' ');
  return bytes.length > maxLen ? `${hex}... (+${bytes.length - maxLen} bytes)` : hex;
}

function readBytes(ptr: NativePointer, len: number): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < len; i++) {
    bytes.push(ptr.add(i).readU8());
  }
  return bytes;
}

function safeString(val: any): string {
  if (val === null || val === undefined) return "<null>";
  try {
    if (val.class?.name === "String") {
      return val.content ?? "<empty>";
    }
    return String(val);
  } catch {
    return "<error>";
  }
}

function dumpFields(instance: any): Record<string, any> {
  const result: Record<string, any> = {};
  try {
    instance.class.fields.forEach((field: any) => {
      if (field.isStatic) return;
      try {
        const value = instance.field(field.name).value;
        const typeName = field.type?.name || "unknown";
        
        if (typeName === "String") {
          result[field.name] = value?.content ?? null;
        } else if (typeName === "Boolean" || typeName === "bool") {
          result[field.name] = !!value;
        } else if (["Int32", "UInt32", "Int64", "UInt64", "Int16", "UInt16", "Byte"].includes(typeName)) {
          result[field.name] = Number(value);
        } else if (typeName.startsWith("List`1")) {
          try {
            const count = value.method("get_Count").invoke();
            result[field.name] = `List[${count}]`;
          } catch {
            result[field.name] = "List[?]";
          }
        } else if (typeName === "Byte[]") {
          const len = value?.length ?? 0;
          result[field.name] = `byte[${len}]`;
        } else {
          result[field.name] = safeString(value);
        }
      } catch {
        result[field.name] = "<error>";
      }
    });
  } catch {
    // ignore
  }
  return result;
}

// =============================================================================
// SSL BYPASS (to observe HTTPS traffic)
// =============================================================================

if (ENABLE_SSL_BYPASS) {
  FridaMultipleUnpinning.bypass(true);
  console.log(`${ts()} [SSL] Pinning bypass enabled`);
  
  try {
    NativeTlsBypass.enable(true);
    console.log(`${ts()} [SSL] Native TLS bypass enabled`);
  } catch (e) {
    console.log(`${ts()} [SSL] Native TLS bypass failed: ${e}`);
  }
}

// =============================================================================
// NATIVE HOOKS: DNS & SOCKET
// =============================================================================

function hookNativeNetwork(): void {
  // Hook getaddrinfo for DNS
  const getaddrinfoPtr = Module.findExportByName(null, "getaddrinfo");
  if (getaddrinfoPtr) {
    const getaddrinfoFn = new NativeFunction(getaddrinfoPtr, "int", ["pointer", "pointer", "pointer", "pointer"]);
    
    Interceptor.replace(getaddrinfoPtr, new NativeCallback((name, service, hints, res) => {
      const hostname = name.readUtf8String() ?? "<null>";
      const result = getaddrinfoFn(name, service, hints, res) as number;
      
      if (result === 0 && hostname !== "<null>") {
        try {
          const list = (res as NativePointer).readPointer();
          if (!list.isNull()) {
            let cur = list;
            let safety = 0;
            while (!cur.isNull() && safety++ < 10) {
              const family = cur.add(4).readS32();
              const aiAddr = cur.add(Process.pointerSize === 8 ? 24 : 16).readPointer();
              
              if (family === 2 && !aiAddr.isNull()) { // AF_INET
                const ipBytes = aiAddr.add(4);
                const ip = `${ipBytes.readU8()}.${ipBytes.add(1).readU8()}.${ipBytes.add(2).readU8()}.${ipBytes.add(3).readU8()}`;
                
                if (!dnsLookups.has(hostname)) {
                  dnsLookups.set(hostname, []);
                }
                const ips = dnsLookups.get(hostname)!;
                if (!ips.includes(ip)) {
                  ips.push(ip);
                  console.log(`${ts()} [DNS] ${hostname} → ${ip}`);
                  logEvent({ t: elapsed(), phase: "dns", data: { hostname, ip } });
                }
              }
              cur = cur.add(Process.pointerSize === 8 ? 40 : 32).readPointer();
            }
          }
        } catch (e) {
          // ignore parse errors
        }
      }
      return result;
    }, "int", ["pointer", "pointer", "pointer", "pointer"]));
  }
  
  // Hook connect() for TCP connections
  const connectPtr = Module.findExportByName(null, "connect");
  if (connectPtr) {
    Interceptor.attach(connectPtr, {
      onEnter(args) {
        const sockaddr = args[1];
        const family = sockaddr.readU16();
        
        if (family === 2) { // AF_INET
          const portBE = sockaddr.add(2).readU16();
          const port = ((portBE & 0xff) << 8) | ((portBE >> 8) & 0xff);
          const ip = `${sockaddr.add(4).readU8()}.${sockaddr.add(5).readU8()}.${sockaddr.add(6).readU8()}.${sockaddr.add(7).readU8()}`;
          
          // Filter interesting connections
          if (port === 443 || port === 12020 || port === 80) {
            console.log(`${ts()} [CONNECT] ${ip}:${port}`);
            connections.push({ ip, port, t: elapsed() });
            logEvent({ t: elapsed(), phase: "connect", data: { ip, port } });
          }
        }
      }
    });
  }
}

// =============================================================================
// IL2CPP HOOKS
// =============================================================================

function hookIl2Cpp(): void {
  console.log(`${ts()} [IL2CPP] Waiting for runtime...`);
  
  Il2Cpp.perform(() => {
    discoveryStartTime = Date.now();
    console.log(`${ts()} [IL2CPP] Runtime ready, installing hooks...`);
    
    const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    
    // =========================================================================
    // 1. LOGIN PACKETS (GameProtocol namespace)
    // =========================================================================
    hookLoginPackets(asm);
    
    // =========================================================================
    // 2. NETWORK LAYER (Dxx.Net namespace)
    // =========================================================================
    hookNetworkLayer(asm);
    
    // =========================================================================
    // 3. TCP LAYER (TcpServer / TcpPacket)
    // =========================================================================
    hookTcpLayer(asm);
    
    // =========================================================================
    // 4. BINARY SERIALIZATION
    // =========================================================================
    hookBinarySerialization(asm);
    
    // =========================================================================
    // 5. ENCRYPTION
    // =========================================================================
    hookEncryption(asm);
    
    // =========================================================================
    // 6. HTTP LAYER
    // =========================================================================
    hookHttpLayer();
    
    // =========================================================================
    // 7. SDK / ACCOUNT
    // =========================================================================
    hookAccountLayer(asm);
    
    console.log(`\n${ts()} [READY] All hooks installed. Capturing for ${DISCOVERY_DURATION_MS / 1000}s...`);
    console.log("═".repeat(66));
    
    // Schedule summary
    setTimeout(() => {
      printSummary();
    }, DISCOVERY_DURATION_MS);
  });
}

// =============================================================================
// HOOK: Login Packets
// =============================================================================

function hookLoginPackets(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] GameProtocol login packets...`);
  
  const packetClasses = [
    "GameProtocol.CUserLoginPacket",
    "GameProtocol.CRespUserLoginPacket",
    "GameProtocol.CHeartBeatPacket",
    "GameProtocol.CRespHeartBeatPacket",
    "GameProtocol.CSyncUserPacket",
    "GameProtocol.CRespSyncUserPacket",
  ];
  
  for (const fullName of packetClasses) {
    try {
      const [ns, name] = fullName.split(".");
      const clazz = asm.class(fullName);
      
      // Hook WriteToStream (outgoing packets)
      try {
        clazz.method("WriteToStream").implementation = function(writer: any) {
          const fields = dumpFields(this);
          const isLogin = name === "CUserLoginPacket";
          
          console.log(`\n${ts()} ┌─────────────────────────────────────────────────`);
          console.log(`${ts()} │ 📤 PACKET OUT: ${name}`);
          console.log(`${ts()} ├─────────────────────────────────────────────────`);
          for (const [k, v] of Object.entries(fields)) {
            console.log(`${ts()} │   ${k}: ${JSON.stringify(v)}`);
          }
          console.log(`${ts()} └─────────────────────────────────────────────────\n`);
          
          if (isLogin) {
            loginPacketSent = true;
            logEvent({
              t: elapsed(),
              phase: "packet",
              direction: "C→S",
              class: name,
              method: "WriteToStream",
              data: fields,
            });
          }
          
          packetCaptures.push({
            t: elapsed(),
            direction: "C→S",
            msgType: 0x0001,
            msgTypeName: name,
            fields,
          });
          
          return this.method("WriteToStream").invoke(writer);
        };
        console.log(`${ts()}   ✓ ${name}.WriteToStream`);
      } catch { /* method doesn't exist */ }
      
      // Hook ReadFromStream (incoming packets)
      try {
        clazz.method("ReadFromStream").implementation = function(reader: any) {
          const result = this.method("ReadFromStream").invoke(reader);
          const fields = dumpFields(this);
          const isLoginResp = name === "CRespUserLoginPacket";
          
          console.log(`\n${ts()} ┌─────────────────────────────────────────────────`);
          console.log(`${ts()} │ 📥 PACKET IN: ${name}`);
          console.log(`${ts()} ├─────────────────────────────────────────────────`);
          for (const [k, v] of Object.entries(fields)) {
            console.log(`${ts()} │   ${k}: ${JSON.stringify(v)}`);
          }
          console.log(`${ts()} └─────────────────────────────────────────────────\n`);
          
          if (isLoginResp) {
            loginResponseReceived = true;
            logEvent({
              t: elapsed(),
              phase: "packet",
              direction: "S→C",
              class: name,
              method: "ReadFromStream",
              data: fields,
            });
          }
          
          packetCaptures.push({
            t: elapsed(),
            direction: "S→C",
            msgType: 0x0002,
            msgTypeName: name,
            fields,
          });
          
          return result;
        };
        console.log(`${ts()}   ✓ ${name}.ReadFromStream`);
      } catch { /* method doesn't exist */ }
      
    } catch (e) {
      // Class not found - may be named differently
    }
  }
}

// =============================================================================
// HOOK: Network Layer (NetManager)
// =============================================================================

function hookNetworkLayer(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Network layer...`);
  
  const netClasses = [
    "Dxx.Net.NetManager",
    "Dxx.Net.NetConfig",
  ];
  
  for (const fullName of netClasses) {
    try {
      const clazz = asm.class(fullName);
      const shortName = fullName.split(".").pop()!;
      
      clazz.methods.forEach(method => {
        // Skip common methods
        if (["ToString", "GetHashCode", "Equals", "Finalize", ".cctor"].includes(method.name)) return;
        if (method.name.startsWith("get_") || method.name.startsWith("set_")) return;
        
        // Hook interesting methods
        const interestingPatterns = ["Connect", "Send", "Receive", "Init", "Start", "Login", "Request"];
        const isInteresting = interestingPatterns.some(p => method.name.includes(p));
        
        if (isInteresting) {
          try {
            clazz.method(method.name).implementation = function(...args: any[]) {
              const argStrs = args.map(a => safeString(a));
              console.log(`${ts()} [NET] ${shortName}.${method.name}(${argStrs.join(", ")})`);
              
              logEvent({
                t: elapsed(),
                phase: "tcp",
                class: shortName,
                method: method.name,
                data: { args: argStrs },
              });
              
              return this.method(method.name).invoke(...args);
            };
          } catch { /* skip */ }
        }
      });
    } catch { /* class not found */ }
  }
}

// =============================================================================
// HOOK: TCP Layer
// =============================================================================

function hookTcpLayer(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] TCP layer...`);
  
  // Hook TcpServer.SendPacket - outgoing TCP data
  try {
    const tcpServer = asm.class("TcpServer.TcpServer");
    
    try {
      tcpServer.method("SendPacket").implementation = function(packet: any) {
        const packetType = packet?.class?.name || "unknown";
        console.log(`${ts()} [TCP] SendPacket → ${packetType}`);
        
        logEvent({
          t: elapsed(),
          phase: "tcp",
          direction: "C→S",
          class: "TcpServer",
          method: "SendPacket",
          data: { packetType },
        });
        
        return this.method("SendPacket").invoke(packet);
      };
      console.log(`${ts()}   ✓ TcpServer.SendPacket`);
    } catch { /* method variant */ }
    
    // Hook OnReceive for incoming TCP data
    try {
      tcpServer.method("OnReceive").implementation = function(data: any, len: any) {
        console.log(`${ts()} [TCP] OnReceive ← ${len} bytes`);
        
        logEvent({
          t: elapsed(),
          phase: "tcp",
          direction: "S→C",
          class: "TcpServer",
          method: "OnReceive",
          data: { length: Number(len) },
        });
        
        return this.method("OnReceive").invoke(data, len);
      };
      console.log(`${ts()}   ✓ TcpServer.OnReceive`);
    } catch { /* method variant */ }
    
  } catch (e) {
    console.log(`${ts()}   ✗ TcpServer not found`);
  }
  
  // Hook TCPPacket namespace classes
  try {
    const tcpPacketClasses = ["TCPPacket.PacketSender", "TCPPacket.PacketReceiver", "TCPPacket.PacketProcessor"];
    for (const fullName of tcpPacketClasses) {
      try {
        const clazz = asm.class(fullName);
        const shortName = fullName.split(".").pop()!;
        
        clazz.methods.forEach(method => {
          if (["ToString", "GetHashCode", "Equals", "Finalize", ".cctor", ".ctor"].includes(method.name)) return;
          
          try {
            clazz.method(method.name).implementation = function(...args: any[]) {
              const argStrs = args.map(a => safeString(a));
              console.log(`${ts()} [TCP] ${shortName}.${method.name}(${argStrs.join(", ")})`);
              return this.method(method.name).invoke(...args);
            };
          } catch { /* skip */ }
        });
      } catch { /* class not found */ }
    }
  } catch { /* namespace not found */ }
}

// =============================================================================
// HOOK: Binary Serialization
// =============================================================================

function hookBinarySerialization(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Binary serialization...`);
  
  const binaryClasses = [
    "GameProtocol.CustomBinaryReader",
    "GameProtocol.CustomBinaryWriter",
  ];
  
  for (const fullName of binaryClasses) {
    try {
      const clazz = asm.class(fullName);
      const shortName = fullName.split(".").pop()!;
      const isReader = shortName.includes("Reader");
      
      // Hook key methods
      const methods = isReader 
        ? ["ReadInt32", "ReadUInt32", "ReadInt64", "ReadUInt64", "ReadString", "ReadBoolean", "ReadUInt16", "ReadByte"]
        : ["WriteInt32", "WriteUInt32", "WriteInt64", "WriteUInt64", "WriteString", "WriteBoolean", "WriteUInt16", "WriteByte"];
      
      for (const methodName of methods) {
        try {
          clazz.method(methodName).implementation = function(...args: any[]) {
            const result = this.method(methodName).invoke(...args);
            
            if (VERBOSE_BINARY_OPS) {
              if (isReader) {
                console.log(`${ts()} [BIN] ${methodName}() → ${safeString(result)}`);
              } else {
                console.log(`${ts()} [BIN] ${methodName}(${args.map(a => safeString(a)).join(", ")})`);
              }
            }
            
            return result;
          };
        } catch { /* method variant */ }
      }
      
      console.log(`${ts()}   ✓ ${shortName}`);
    } catch { /* class not found */ }
  }
}

// =============================================================================
// HOOK: Encryption
// =============================================================================

function hookEncryption(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Encryption...`);
  
  // NetEncrypt
  try {
    const netEncrypt = asm.class("NetEncrypt");
    
    const encryptMethods = ["Encrypt", "Decrypt", "Encrypt_UTF8", "DesEncrypt", "DesDecrypt"];
    for (const methodName of encryptMethods) {
      try {
        netEncrypt.method(methodName).implementation = function(...args: any[]) {
          const result = this.method(methodName).invoke(...args);
          const inputStr = args.length > 0 ? safeString(args[0]) : "";
          const outputStr = safeString(result);
          
          console.log(`${ts()} [CRYPTO] NetEncrypt.${methodName}`);
          console.log(`${ts()}   IN:  ${inputStr.substring(0, 100)}${inputStr.length > 100 ? "..." : ""}`);
          console.log(`${ts()}   OUT: ${outputStr.substring(0, 100)}${outputStr.length > 100 ? "..." : ""}`);
          
          logEvent({
            t: elapsed(),
            phase: "crypto",
            class: "NetEncrypt",
            method: methodName,
            data: { 
              inputPreview: inputStr.substring(0, 50),
              outputPreview: outputStr.substring(0, 50),
            },
          });
          
          return result;
        };
        console.log(`${ts()}   ✓ NetEncrypt.${methodName}`);
      } catch { /* method variant */ }
    }
  } catch { /* class not found */ }
  
  // RC4Encrypter
  try {
    const rc4 = asm.class("RC4Encrypter");
    
    try {
      rc4.method("Encrypt").implementation = function(data: any, key: any) {
        const result = this.method("Encrypt").invoke(data, key);
        console.log(`${ts()} [CRYPTO] RC4Encrypter.Encrypt (key: ${safeString(key).substring(0, 20)}...)`);
        
        logEvent({
          t: elapsed(),
          phase: "crypto",
          class: "RC4Encrypter",
          method: "Encrypt",
          data: { keyPreview: safeString(key).substring(0, 20) },
        });
        
        return result;
      };
      console.log(`${ts()}   ✓ RC4Encrypter.Encrypt`);
    } catch { /* method variant */ }
  } catch { /* class not found */ }
}

// =============================================================================
// HOOK: HTTP Layer
// =============================================================================

function hookHttpLayer(): void {
  console.log(`${ts()} [HOOK] HTTP layer...`);
  
  try {
    // HabbyToolLib HTTP
    const habbyToolAsm = Il2Cpp.domain.assembly("HabbyToolLib").image;
    const httpManager = habbyToolAsm.class("Habby.Tool.Http.HttpManager");
    
    httpManager.methods.forEach(method => {
      if (method.name.includes("Request") || method.name.includes("Send") || method.name.includes("Post") || method.name.includes("Get")) {
        try {
          httpManager.method(method.name).implementation = function(...args: any[]) {
            const url = args.length > 0 ? safeString(args[0]) : "";
            console.log(`${ts()} [HTTP] HttpManager.${method.name}: ${url}`);
            
            httpRequests.push({ t: elapsed(), url, method: method.name });
            logEvent({
              t: elapsed(),
              phase: "http",
              class: "HttpManager",
              method: method.name,
              data: { url },
            });
            
            return this.method(method.name).invoke(...args);
          };
        } catch { /* skip */ }
      }
    });
    
    console.log(`${ts()}   ✓ Habby.Tool.Http.HttpManager`);
  } catch { /* assembly not found */ }
  
  // Assembly-CSharp HTTP classes
  try {
    const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    const httpClasses = ["HTTPSendClient", "Dxx.Net.HttpRequest"];
    
    for (const className of httpClasses) {
      try {
        const clazz = asm.class(className);
        
        clazz.methods.forEach(method => {
          if (method.name.includes("Send") || method.name.includes("Request") || method.name.includes("Post")) {
            try {
              clazz.method(method.name).implementation = function(...args: any[]) {
                const argStrs = args.map(a => safeString(a));
                console.log(`${ts()} [HTTP] ${className}.${method.name}(${argStrs.join(", ").substring(0, 100)})`);
                
                logEvent({
                  t: elapsed(),
                  phase: "http",
                  class: className,
                  method: method.name,
                  data: { args: argStrs },
                });
                
                return this.method(method.name).invoke(...args);
              };
            } catch { /* skip */ }
          }
        });
      } catch { /* class not found */ }
    }
  } catch { /* skip */ }
}

// =============================================================================
// HOOK: Account / SDK Layer
// =============================================================================

function hookAccountLayer(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Account/SDK layer...`);
  
  const sdkClasses = [
    "SdkManager",
    "AccountManager",
    "Habby.Account.AccountManager",
  ];
  
  for (const className of sdkClasses) {
    try {
      const clazz = asm.class(className);
      const shortName = className.split(".").pop()!;
      
      clazz.methods.forEach(method => {
        if (["ToString", "GetHashCode", "Equals", "Finalize", ".cctor"].includes(method.name)) return;
        
        const patterns = ["Login", "Auth", "Token", "Account", "User", "Session", "Init"];
        if (patterns.some(p => method.name.includes(p))) {
          try {
            clazz.method(method.name).implementation = function(...args: any[]) {
              const argStrs = args.map(a => safeString(a));
              console.log(`${ts()} [SDK] ${shortName}.${method.name}(${argStrs.join(", ")})`);
              
              logEvent({
                t: elapsed(),
                phase: "sdk",
                class: shortName,
                method: method.name,
                data: { args: argStrs },
              });
              
              return this.method(method.name).invoke(...args);
            };
          } catch { /* skip */ }
        }
      });
    } catch { /* class not found */ }
  }
}

// =============================================================================
// SUMMARY
// =============================================================================

function printSummary(): void {
  const totalTime = elapsed();
  
  console.log("\n");
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║               AUTHENTICATION FLOW SUMMARY                    ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");
  
  console.log(`\n📊 Session Statistics:`);
  console.log(`   Duration: ${totalTime.toFixed(1)}s`);
  console.log(`   Total events: ${authEvents.length}`);
  console.log(`   Login packet sent: ${loginPacketSent ? "✓" : "✗"}`);
  console.log(`   Login response received: ${loginResponseReceived ? "✓" : "✗"}`);
  
  console.log(`\n🌐 DNS Lookups (${dnsLookups.size} hosts):`);
  dnsLookups.forEach((ips, hostname) => {
    console.log(`   ${hostname} → ${ips.join(", ")}`);
  });
  
  console.log(`\n🔌 TCP Connections (${connections.length}):`);
  connections.forEach(c => {
    console.log(`   [${c.t.toFixed(2)}s] ${c.ip}:${c.port}`);
  });
  
  console.log(`\n📦 Packets Captured (${packetCaptures.length}):`);
  packetCaptures.forEach(p => {
    const dir = p.direction === "C→S" ? "📤" : "📥";
    console.log(`   [${p.t.toFixed(2)}s] ${dir} ${p.msgTypeName || `0x${p.msgType.toString(16)}`}`);
  });
  
  console.log(`\n🌍 HTTP Requests (${httpRequests.length}):`);
  httpRequests.forEach(r => {
    console.log(`   [${r.t.toFixed(2)}s] ${r.method}: ${r.url}`);
  });
  
  // Timeline view
  console.log(`\n📅 Authentication Timeline:`);
  console.log("─".repeat(66));
  const sortedEvents = [...authEvents].sort((a, b) => a.t - b.t);
  for (const ev of sortedEvents.slice(0, 50)) {
    const phase = ev.phase.padEnd(8);
    const dir = ev.direction ? ` ${ev.direction}` : "";
    const detail = ev.class ? `${ev.class}.${ev.method}` : JSON.stringify(ev.data).substring(0, 50);
    console.log(`   [${ev.t.toFixed(2)}s] [${phase}]${dir} ${detail}`);
  }
  if (sortedEvents.length > 50) {
    console.log(`   ... and ${sortedEvents.length - 50} more events`);
  }
  
  // Output structured JSON
  console.log(`\n📋 JSON Summary (copy for analysis):`);
  console.log("─".repeat(66));
  const summary = {
    session: {
      duration: totalTime,
      loginSent: loginPacketSent,
      loginReceived: loginResponseReceived,
    },
    dns: Object.fromEntries(dnsLookups),
    connections,
    packets: packetCaptures,
    http: httpRequests,
    timeline: sortedEvents.slice(0, 100),
  };
  console.log(JSON.stringify(summary, null, 2));
  
  console.log("\n" + "═".repeat(66));
  console.log("Discovery complete. Review the timeline above for auth flow.");
  console.log("═".repeat(66));
}

// =============================================================================
// MAIN
// =============================================================================

hookNativeNetwork();
hookIl2Cpp();
