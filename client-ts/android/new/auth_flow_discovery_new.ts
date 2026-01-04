/**
 * Authentication Flow Discovery Tool - Android Version (Enhanced)
 *
 * Captures the complete authentication/login sequence during the first 30 seconds
 * of game startup. Enhanced version with recursive field dumping for 50+ types.
 *
 * Usage:
 *   cd client-ts
 *   bun run auth-discovery:new
 *
 * Or manually:
 *   bun run build:auth-discovery:new
 *   frida -U -f com.habby.archero -l android/build/auth_flow_discovery_new.js
 */

/// <reference path="../../frida.d.ts" />

import "frida-il2cpp-bridge";

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║     ARCHERO AUTH FLOW DISCOVERY (Android - Enhanced)        ║");
console.log("║     Capturing first 30 seconds of startup                   ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

// =============================================================================
// CONFIGURATION
// =============================================================================

const DISCOVERY_DURATION_MS = 30000;
const VERBOSE_BINARY_OPS = false;
const LOG_SSL_DATA = true;

// =============================================================================
// DATA STRUCTURES
// =============================================================================

interface AuthEvent {
  t: number;
  phase: string;
  direction?: string;
  class?: string;
  method?: string;
  data: Record<string, any>;
}

interface PacketCapture {
  t: number;
  direction: string;
  msgType?: number;
  msgTypeName?: string;
  fields?: Record<string, any>;
}

interface FieldValue {
  type: string;
  length?: number;
  count?: number | string;
  hex?: string;
  fields?: Record<string, any>;
}

const authEvents: AuthEvent[] = [];
const packetCaptures: PacketCapture[] = [];
const dnsLookups = new Map<string, string[]>();
const connections: { ip: string; port: number; t: number }[] = [];
const httpRequests: { t: number; url: string; method: string }[] = [];
const encryptionKeys: { t: number; type: string; key: string }[] = [];

let discoveryStartTime = 0;
let loginPacketSent = false;
let loginResponseReceived = false;

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

function safeString(val: any): string {
  if (val === null || val === undefined) return "<null>";
  try {
    if (val.class && val.class.name === "String") {
      return val.content ?? "<empty>";
    }
    return String(val);
  } catch (e) {
    return "<error>";
  }
}

/**
 * Recursively dump all fields from an IL2CPP object instance.
 * Handles 50+ field types including primitives, strings, arrays, and lists.
 */
function dumpAllFields(instance: any, depth: number = 0): Record<string, any> {
  if (depth > 3) return { _depth: "max reached" };
  
  const result: Record<string, any> = {};
  
  try {
    if (!instance || !instance.class) return result;
    
    instance.class.fields.forEach((field: any) => {
      if (field.isStatic) return;
      
      const fieldName = field.name;
      const typeName = field.type ? field.type.name : "unknown";
      
      try {
        const value = instance.field(fieldName).value;
        
        // Handle null/undefined
        if (value === null || value === undefined) {
          result[fieldName] = null;
          return;
        }
        
        // String
        if (typeName === "String") {
          result[fieldName] = value.content ?? null;
          return;
        }
        
        // Boolean
        if (typeName === "Boolean" || typeName === "bool") {
          result[fieldName] = !!value;
          return;
        }
        
        // Numeric primitives
        if (["Int32", "UInt32", "Int64", "UInt64", "Int16", "UInt16", "Byte", "SByte", "Single", "Double"].includes(typeName)) {
          result[fieldName] = Number(value);
          return;
        }
        
        // Byte array - provide hex dump
        if (typeName === "Byte[]") {
          const len = value.length || 0;
          if (len > 0 && len <= 256) {
            let hexStr = "";
            for (let i = 0; i < Math.min(len, 64); i++) {
              hexStr += value.get(i).toString(16).padStart(2, "0");
            }
            if (len > 64) hexStr += `...(${len} total)`;
            result[fieldName] = { type: "byte[]", length: len, hex: hexStr } as FieldValue;
          } else {
            result[fieldName] = { type: "byte[]", length: len } as FieldValue;
          }
          return;
        }
        
        // UInt16 array
        if (typeName === "UInt16[]") {
          const len = value.length || 0;
          result[fieldName] = { type: "uint16[]", length: len } as FieldValue;
          return;
        }
        
        // Generic arrays
        if (typeName.endsWith("[]")) {
          const len = value.length || 0;
          result[fieldName] = { type: typeName, length: len } as FieldValue;
          return;
        }
        
        // List<T>
        if (typeName.startsWith("List`1")) {
          try {
            const count = value.method("get_Count").invoke();
            result[fieldName] = { type: "List", count: Number(count) } as FieldValue;
          } catch (e) {
            result[fieldName] = { type: "List", count: "?" } as FieldValue;
          }
          return;
        }
        
        // Dictionary<K,V>
        if (typeName.startsWith("Dictionary`2")) {
          try {
            const count = value.method("get_Count").invoke();
            result[fieldName] = { type: "Dictionary", count: Number(count) } as FieldValue;
          } catch (e) {
            result[fieldName] = { type: "Dictionary", count: "?" } as FieldValue;
          }
          return;
        }
        
        // Nested objects - recurse with depth limit
        if (value.class && depth < 2) {
          const nested = dumpAllFields(value, depth + 1);
          if (Object.keys(nested).length > 0) {
            result[fieldName] = { type: typeName, fields: nested } as FieldValue;
          } else {
            result[fieldName] = { type: typeName } as FieldValue;
          }
          return;
        }
        
        // Fallback
        result[fieldName] = safeString(value);
        
      } catch (e: any) {
        result[fieldName] = `<error: ${e.message || e}>`;
      }
    });
  } catch (e: any) {
    result._error = e.message || String(e);
  }
  
  return result;
}

/**
 * Pretty print fields to console
 */
function printFields(fields: Record<string, any>, indent: string = "│   "): void {
  for (const [key, value] of Object.entries(fields)) {
    if (value && typeof value === "object" && value.fields) {
      console.log(`${ts()} ${indent}${key}: {${value.type}}`);
      printFields(value.fields, indent + "  ");
    } else if (value && typeof value === "object" && value.type) {
      const extra = value.length !== undefined ? `, len=${value.length}` : 
                    value.count !== undefined ? `, count=${value.count}` : "";
      const hex = value.hex ? ` [${value.hex.substring(0, 32)}${value.hex.length > 32 ? "..." : ""}]` : "";
      console.log(`${ts()} ${indent}${key}: ${value.type}${extra}${hex}`);
    } else {
      const display = JSON.stringify(value);
      console.log(`${ts()} ${indent}${key}: ${display.length > 100 ? display.substring(0, 100) + "..." : display}`);
    }
  }
}

// =============================================================================
// NATIVE HOOKS: DNS & SOCKET (Android)
// =============================================================================

function hookNativeNetwork(): void {
  console.log("[NATIVE] Setting up DNS/Socket hooks...");
  
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
              // Android uses different struct layout based on pointer size
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
    console.log("   ✓ getaddrinfo hooked");
  }
  
  // Hook connect() for TCP connections
  const connectPtr = Module.findExportByName(null, "connect");
  if (connectPtr) {
    Interceptor.attach(connectPtr, {
      onEnter(args) {
        const sockaddr = args[1];
        const family = sockaddr.readU16(); // Android uses sa_family_t
        
        if (family === 2) { // AF_INET
          const portBE = sockaddr.add(2).readU16();
          const port = ((portBE & 0xff) << 8) | ((portBE >> 8) & 0xff);
          const ip = `${sockaddr.add(4).readU8()}.${sockaddr.add(5).readU8()}.${sockaddr.add(6).readU8()}.${sockaddr.add(7).readU8()}`;
          
          if (port === 443 || port === 12020 || port === 80 || port === 8080) {
            console.log(`${ts()} [CONNECT] ${ip}:${port}`);
            connections.push({ ip, port, t: elapsed() });
            logEvent({ t: elapsed(), phase: "connect", data: { ip, port } });
          }
        }
      }
    });
    console.log("   ✓ connect hooked");
  }
}

// =============================================================================
// NATIVE HOOKS: Socket send/recv
// =============================================================================

function hookSockets(): void {
  console.log("[NATIVE] Setting up socket send/recv hooks...");
  
  try {
    const sendPtr = Module.findExportByName(null, "send");
    if (sendPtr) {
      Interceptor.attach(sendPtr, {
        onEnter(args) {
          const fd = args[0].toInt32();
          const socktype = Socket.type(fd);
          
          if (socktype !== "tcp" && socktype !== "tcp6") return;
          
          const address = Socket.peerAddress(fd);
          if (address === null) return;
          
          const data = args[1];
          const size = args[2].toInt32();
          
          if (size > 0 && size < 10000) {
            console.log(`${ts()} [SOCKET:send] → ${JSON.stringify(address)} (${size} bytes)`);
            try {
              const buffer = data.readByteArray(Math.min(size, 256));
              if (buffer) {
                console.log(hexdump(buffer, { offset: 0, length: Math.min(size, 256), header: false, ansi: true }));
              }
            } catch (e) {}
          }
        }
      });
      console.log("   ✓ send hooked");
    }
  } catch (e) {
    console.log(`   ✗ Socket hooks failed: ${e}`);
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
    
    // List available assemblies for debugging
    console.log(`${ts()} [IL2CPP] Available assemblies:`);
    Il2Cpp.domain.assemblies.forEach(asm => {
      console.log(`   - ${asm.name}`);
    });
    
    try {
      const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;
      
      discoverGameProtocolClasses(asm);
      hookLoginPackets(asm);
      hookNetworkLayer(asm);
      hookTcpLayer(asm);
      hookTcpNetManager(asm);
      hookEncryption(asm);
      hookHttpLayer();
      
      console.log(`\n${ts()} [READY] All hooks installed. Capturing for ${DISCOVERY_DURATION_MS / 1000}s...`);
      console.log("═".repeat(66));
      
      setTimeout(() => {
        printSummary();
      }, DISCOVERY_DURATION_MS);
      
    } catch (e) {
      console.log(`${ts()} [ERROR] Failed to hook Assembly-CSharp: ${e}`);
    }
  });
}

// =============================================================================
// DISCOVER: GameProtocol Classes
// =============================================================================

function discoverGameProtocolClasses(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [DISCOVER] Scanning GameProtocol namespace...`);
  
  const gameProtocolClasses: string[] = [];
  
  try {
    asm.classes.forEach(clazz => {
      if (clazz.namespace === "GameProtocol") {
        gameProtocolClasses.push(clazz.name);
      }
    });
    
    console.log(`${ts()}   Found ${gameProtocolClasses.length} GameProtocol classes`);
    
    // Log interesting ones
    const loginRelated = gameProtocolClasses.filter(name => 
      name.toLowerCase().includes("login") || 
      name.toLowerCase().includes("user") ||
      name.toLowerCase().includes("sync") ||
      name.toLowerCase().includes("heartbeat") ||
      name.toLowerCase().includes("resp")
    );
    
    console.log(`${ts()}   Auth-related classes:`);
    loginRelated.slice(0, 20).forEach(name => console.log(`${ts()}     - GameProtocol.${name}`));
    if (loginRelated.length > 20) {
      console.log(`${ts()}     ... and ${loginRelated.length - 20} more`);
    }
  } catch (e) {
    console.log(`${ts()}   Could not enumerate GameProtocol classes: ${e}`);
  }
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
      const clazz = asm.class(fullName);
      const name = fullName.split(".").pop()!;
      
      // Hook WriteToStream
      try {
        clazz.method("WriteToStream").implementation = function(writer: any) {
          const fields = dumpAllFields(this);
          const isLogin = name === "CUserLoginPacket";
          
          console.log(`\n${ts()} ┌─────────────────────────────────────────────────`);
          console.log(`${ts()} │ 📤 PACKET OUT: ${name}`);
          console.log(`${ts()} ├─────────────────────────────────────────────────`);
          printFields(fields);
          console.log(`${ts()} └─────────────────────────────────────────────────\n`);
          
          if (isLogin) loginPacketSent = true;
          
          logEvent({
            t: elapsed(),
            phase: "packet",
            direction: "C→S",
            class: name,
            method: "WriteToStream",
            data: fields,
          });
          
          packetCaptures.push({
            t: elapsed(),
            direction: "C→S",
            msgTypeName: name,
            fields,
          });
          
          return this.method("WriteToStream").invoke(writer);
        };
        console.log(`${ts()}   ✓ ${name}.WriteToStream`);
      } catch (e) {
        // Try OnWriteToStream for some packet types
        try {
          clazz.method("OnWriteToStream").implementation = function(writer: any) {
            const fields = dumpAllFields(this);
            
            console.log(`\n${ts()} ┌─────────────────────────────────────────────────`);
            console.log(`${ts()} │ 📤 PACKET OUT: ${name}`);
            console.log(`${ts()} ├─────────────────────────────────────────────────`);
            printFields(fields);
            console.log(`${ts()} └─────────────────────────────────────────────────\n`);
            
            if (name === "CUserLoginPacket") loginPacketSent = true;
            
            logEvent({
              t: elapsed(),
              phase: "packet",
              direction: "C→S",
              class: name,
              method: "OnWriteToStream",
              data: fields,
            });
            
            packetCaptures.push({
              t: elapsed(),
              direction: "C→S",
              msgTypeName: name,
              fields,
            });
            
            return this.method("OnWriteToStream").invoke(writer);
          };
          console.log(`${ts()}   ✓ ${name}.OnWriteToStream`);
        } catch (e2) {}
      }
      
      // Hook ReadFromStream
      try {
        clazz.method("ReadFromStream").implementation = function(reader: any) {
          const result = this.method("ReadFromStream").invoke(reader);
          const fields = dumpAllFields(this);
          const isLoginResp = name === "CRespUserLoginPacket";
          
          console.log(`\n${ts()} ┌─────────────────────────────────────────────────`);
          console.log(`${ts()} │ 📥 PACKET IN: ${name}`);
          console.log(`${ts()} ├─────────────────────────────────────────────────`);
          printFields(fields);
          console.log(`${ts()} └─────────────────────────────────────────────────\n`);
          
          if (isLoginResp) loginResponseReceived = true;
          
          logEvent({
            t: elapsed(),
            phase: "packet",
            direction: "S→C",
            class: name,
            method: "ReadFromStream",
            data: fields,
          });
          
          packetCaptures.push({
            t: elapsed(),
            direction: "S→C",
            msgTypeName: name,
            fields,
          });
          
          return result;
        };
        console.log(`${ts()}   ✓ ${name}.ReadFromStream`);
      } catch (e) {}
      
    } catch (e) {}
  }
}

// =============================================================================
// HOOK: Network Layer
// =============================================================================

function hookNetworkLayer(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Network layer...`);
  
  const netClasses = ["Dxx.Net.NetManager", "Dxx.Net.NetConfig"];
  
  for (const fullName of netClasses) {
    try {
      const clazz = asm.class(fullName);
      const shortName = fullName.split(".").pop()!;
      
      clazz.methods.forEach(method => {
        if (["ToString", "GetHashCode", "Equals", "Finalize", ".cctor"].includes(method.name)) return;
        if (method.name.startsWith("get_") || method.name.startsWith("set_")) return;
        
        const patterns = ["Connect", "Send", "Receive", "Init", "Start", "Login", "Request"];
        if (patterns.some(p => method.name.includes(p))) {
          try {
            clazz.method(method.name).implementation = function(...args: any[]) {
              const argStrs = args.map(a => safeString(a));
              console.log(`${ts()} [NET] ${shortName}.${method.name}(${argStrs.join(", ")})`);
              
              logEvent({
                t: elapsed(),
                phase: "net",
                class: shortName,
                method: method.name,
                data: { args: argStrs },
              });
              
              return this.method(method.name).invoke(...args);
            };
          } catch (e) {}
        }
      });
      
      console.log(`${ts()}   ✓ ${shortName}`);
    } catch (e) {}
  }
}

// =============================================================================
// HOOK: TCP Layer
// =============================================================================

function hookTcpLayer(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] TCP layer...`);
  
  try {
    const tcpServer = asm.class("TcpServer.TcpServer");
    
    try {
      tcpServer.method("SendPacket").implementation = function(packet: any) {
        const packetType = packet && packet.class ? packet.class.name : "unknown";
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
    } catch (e) {}
    
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
    } catch (e) {}
    
  } catch (e) {
    console.log(`${ts()}   ✗ TcpServer not found`);
  }
}

// =============================================================================
// HOOK: TcpNetManager
// =============================================================================

function hookTcpNetManager(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] TcpNetManager...`);
  
  try {
    const tcpNetMgr = asm.class("TcpNetManager");
    
    try {
      tcpNetMgr.method("SendPacket").implementation = function(packet: any, msgId: any) {
        const packetType = packet && packet.class ? packet.class.name : "unknown";
        console.log(`${ts()} [TCPNET] SendPacket(${msgId}) → ${packetType}`);
        
        logEvent({
          t: elapsed(),
          phase: "tcpnet",
          direction: "C→S",
          class: "TcpNetManager",
          method: "SendPacket",
          data: { packetType, msgId: Number(msgId) },
        });
        
        return this.method("SendPacket").invoke(packet, msgId);
      };
      console.log(`${ts()}   ✓ TcpNetManager.SendPacket`);
    } catch (e) {}
    
    try {
      tcpNetMgr.method("SendBuffer").implementation = function(buffer: any) {
        const len = buffer ? buffer.length : 0;
        console.log(`${ts()} [TCPNET] SendBuffer (${len} bytes)`);
        
        logEvent({
          t: elapsed(),
          phase: "tcpnet",
          direction: "C→S",
          class: "TcpNetManager",
          method: "SendBuffer",
          data: { length: len },
        });
        
        return this.method("SendBuffer").invoke(buffer);
      };
      console.log(`${ts()}   ✓ TcpNetManager.SendBuffer`);
    } catch (e) {}
    
  } catch (e) {
    console.log(`${ts()}   ✗ TcpNetManager not found`);
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
      } catch (e) {}
    }
  } catch (e) {}
  
  // RC4Encrypter
  try {
    const rc4 = asm.class("RC4Encrypter");
    
    try {
      rc4.method("Encrypt").implementation = function(data: any, key: any) {
        const keyStr = safeString(key);
        const result = this.method("Encrypt").invoke(data, key);
        
        console.log(`${ts()} [CRYPTO] RC4Encrypter.Encrypt`);
        console.log(`${ts()}   KEY: ${keyStr.substring(0, 32)}${keyStr.length > 32 ? "..." : ""}`);
        
        encryptionKeys.push({ t: elapsed(), type: "RC4", key: keyStr });
        
        logEvent({
          t: elapsed(),
          phase: "crypto",
          class: "RC4Encrypter",
          method: "Encrypt",
          data: { keyPreview: keyStr.substring(0, 32) },
        });
        
        return result;
      };
      console.log(`${ts()}   ✓ RC4Encrypter.Encrypt`);
    } catch (e) {}
    
    // Hook constructor to capture key
    try {
      rc4.method(".ctor").implementation = function(key: any) {
        const keyStr = safeString(key);
        console.log(`${ts()} [CRYPTO] RC4Encrypter.ctor`);
        console.log(`${ts()}   KEY: ${keyStr.substring(0, 32)}${keyStr.length > 32 ? "..." : ""}`);
        
        encryptionKeys.push({ t: elapsed(), type: "RC4_init", key: keyStr });
        
        return this.method(".ctor").invoke(key);
      };
      console.log(`${ts()}   ✓ RC4Encrypter.ctor`);
    } catch (e) {}
    
  } catch (e) {}
}

// =============================================================================
// HOOK: HTTP Layer
// =============================================================================

function hookHttpLayer(): void {
  console.log(`${ts()} [HOOK] HTTP layer...`);
  
  try {
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
        } catch (e) {}
      }
    });
    
    console.log(`${ts()}   ✓ Habby.Tool.Http.HttpManager`);
  } catch (e) {}
  
  try {
    const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;
    
    try {
      const httpClient = asm.class("HTTPSendClient");
      httpClient.methods.forEach(method => {
        if (method.name.includes("Send") || method.name.includes("Request")) {
          try {
            httpClient.method(method.name).implementation = function(...args: any[]) {
              const argStrs = args.map(a => safeString(a));
              console.log(`${ts()} [HTTP] HTTPSendClient.${method.name}(${argStrs.join(", ").substring(0, 100)})`);
              
              logEvent({
                t: elapsed(),
                phase: "http",
                class: "HTTPSendClient",
                method: method.name,
                data: { args: argStrs },
              });
              
              return this.method(method.name).invoke(...args);
            };
          } catch (e) {}
        }
      });
      console.log(`${ts()}   ✓ HTTPSendClient`);
    } catch (e) {}
  } catch (e) {}
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
  
  console.log(`\n🔐 Encryption Keys Captured (${encryptionKeys.length}):`);
  encryptionKeys.forEach(k => {
    console.log(`   [${k.t.toFixed(2)}s] ${k.type}: ${k.key.substring(0, 40)}${k.key.length > 40 ? "..." : ""}`);
  });
  
  console.log(`\n📦 Packets Captured (${packetCaptures.length}):`);
  packetCaptures.forEach(p => {
    const dir = p.direction === "C→S" ? "📤" : "📥";
    console.log(`   [${p.t.toFixed(2)}s] ${dir} ${p.msgTypeName}`);
  });
  
  console.log(`\n🌍 HTTP Requests (${httpRequests.length}):`);
  httpRequests.forEach(r => {
    console.log(`   [${r.t.toFixed(2)}s] ${r.method}: ${r.url}`);
  });
  
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
  
  console.log(`\n📋 JSON Summary:`);
  console.log("─".repeat(66));
  const summary = {
    session: { duration: totalTime, loginSent: loginPacketSent, loginReceived: loginResponseReceived },
    dns: Object.fromEntries(dnsLookups),
    connections,
    encryptionKeys: encryptionKeys.map(k => ({ t: k.t, type: k.type, keyPreview: k.key.substring(0, 32) })),
    packets: packetCaptures.map(p => ({ t: p.t, direction: p.direction, type: p.msgTypeName })),
    http: httpRequests,
    eventCount: authEvents.length,
  };
  console.log(JSON.stringify(summary, null, 2));
  
  console.log("\n" + "═".repeat(66));
}

// =============================================================================
// MAIN
// =============================================================================

hookNativeNetwork();
hookSockets();
hookIl2Cpp();
