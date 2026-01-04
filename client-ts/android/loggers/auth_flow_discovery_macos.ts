/**
 * Authentication Flow Discovery Tool - macOS Version
 *
 * Captures the complete authentication/login sequence during the first 30 seconds
 * of game startup on macOS. Adapted for macOS IL2CPP structure.
 *
 * Usage (macOS):
 *   cd client-ts
 *   bun run build:auth-discovery
 *   frida -l android/build/auth_flow_discovery.js -f /Applications/Archero.app/Contents/MacOS/Archero
 *
 * Or use the npm script:
 *   bun run auth-discovery:macos
 */

import "frida-il2cpp-bridge";

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║     ARCHERO AUTH FLOW DISCOVERY (macOS)                      ║");
console.log("║     Capturing first 30 seconds of startup                    ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

// =============================================================================
// CONFIGURATION
// =============================================================================

const DISCOVERY_DURATION_MS = 30000;
const VERBOSE_BINARY_OPS = false;

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
  msgType: number;
  msgTypeName?: string;
  fields?: Record<string, any>;
}

const authEvents: AuthEvent[] = [];
const packetCaptures: PacketCapture[] = [];
const dnsLookups = new Map<string, string[]>();
const connections: { ip: string; port: number; t: number }[] = [];
const httpRequests: { t: number; url: string; method: string }[] = [];

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
  } catch {}
  return result;
}

// =============================================================================
// NATIVE HOOKS: DNS & SOCKET (macOS)
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
              // macOS uses different struct layout
              const aiAddr = cur.add(32).readPointer(); // ai_addr on macOS x86_64
              
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
              cur = cur.add(48).readPointer(); // ai_next on macOS
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
        const family = sockaddr.add(1).readU8(); // macOS sockaddr uses sin_len + sin_family
        
        if (family === 2) { // AF_INET
          const portBE = sockaddr.add(2).readU16();
          const port = ((portBE & 0xff) << 8) | ((portBE >> 8) & 0xff);
          const ip = `${sockaddr.add(4).readU8()}.${sockaddr.add(5).readU8()}.${sockaddr.add(6).readU8()}.${sockaddr.add(7).readU8()}`;
          
          if (port === 443 || port === 12020 || port === 80) {
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
      
      hookLoginPackets(asm);
      hookNetworkLayer(asm);
      hookTcpLayer(asm);
      hookBinarySerialization(asm);
      hookEncryption(asm);
      hookHttpLayer();
      hookAccountLayer(asm);
      
      console.log(`\n${ts()} [READY] All hooks installed. Capturing for ${DISCOVERY_DURATION_MS / 1000}s...`);
      console.log("═".repeat(66));
      
      setTimeout(() => {
        printSummary();
      }, DISCOVERY_DURATION_MS);
      
    } catch (e) {
      console.log(`${ts()} [ERROR] Failed to hook Assembly-CSharp: ${e}`);
      console.log(`${ts()} [INFO] Trying alternative assembly names...`);
      
      // Try to find the correct assembly
      Il2Cpp.domain.assemblies.forEach(asm => {
        if (asm.name.toLowerCase().includes("csharp") || asm.name.toLowerCase().includes("game")) {
          console.log(`${ts()}   Found candidate: ${asm.name}`);
        }
      });
    }
  });
}

// =============================================================================
// HOOK: Login Packets
// =============================================================================

function hookLoginPackets(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] GameProtocol login packets...`);
  
  // First, discover what classes exist in GameProtocol namespace
  let gameProtocolClasses: string[] = [];
  
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
      name.toLowerCase().includes("heartbeat")
    );
    loginRelated.forEach(name => console.log(`${ts()}   - GameProtocol.${name}`));
  } catch (e) {
    console.log(`${ts()}   Could not enumerate GameProtocol classes: ${e}`);
  }
  
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
          const fields = dumpFields(this);
          const isLogin = name === "CUserLoginPacket";
          
          console.log(`\n${ts()} ┌─────────────────────────────────────────────────`);
          console.log(`${ts()} │ 📤 PACKET OUT: ${name}`);
          console.log(`${ts()} ├─────────────────────────────────────────────────`);
          for (const [k, v] of Object.entries(fields)) {
            console.log(`${ts()} │   ${k}: ${JSON.stringify(v)}`);
          }
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
            msgType: 0x0001,
            msgTypeName: name,
            fields,
          });
          
          return this.method("WriteToStream").invoke(writer);
        };
        console.log(`${ts()}   ✓ ${name}.WriteToStream`);
      } catch {}
      
      // Hook ReadFromStream
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
            msgType: 0x0002,
            msgTypeName: name,
            fields,
          });
          
          return result;
        };
        console.log(`${ts()}   ✓ ${name}.ReadFromStream`);
      } catch {}
      
    } catch {}
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
                phase: "tcp",
                class: shortName,
                method: method.name,
                data: { args: argStrs },
              });
              
              return this.method(method.name).invoke(...args);
            };
          } catch {}
        }
      });
    } catch {}
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
    } catch {}
    
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
    } catch {}
    
  } catch {
    console.log(`${ts()}   ✗ TcpServer not found`);
  }
}

// =============================================================================
// HOOK: Binary Serialization
// =============================================================================

function hookBinarySerialization(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Binary serialization...`);
  
  const binaryClasses = ["GameProtocol.CustomBinaryReader", "GameProtocol.CustomBinaryWriter"];
  
  for (const fullName of binaryClasses) {
    try {
      const clazz = asm.class(fullName);
      const shortName = fullName.split(".").pop()!;
      const isReader = shortName.includes("Reader");
      
      const methods = isReader 
        ? ["ReadInt32", "ReadUInt32", "ReadInt64", "ReadUInt64", "ReadString", "ReadBoolean", "ReadUInt16"]
        : ["WriteInt32", "WriteUInt32", "WriteInt64", "WriteUInt64", "WriteString", "WriteBoolean", "WriteUInt16"];
      
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
        } catch {}
      }
      
      console.log(`${ts()}   ✓ ${shortName}`);
    } catch {}
  }
}

// =============================================================================
// HOOK: Encryption
// =============================================================================

function hookEncryption(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Encryption...`);
  
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
      } catch {}
    }
  } catch {}
  
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
    } catch {}
  } catch {}
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
        } catch {}
      }
    });
    
    console.log(`${ts()}   ✓ Habby.Tool.Http.HttpManager`);
  } catch {}
  
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
            } catch {}
          }
        });
      } catch {}
    }
  } catch {}
}

// =============================================================================
// HOOK: Account Layer
// =============================================================================

function hookAccountLayer(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Account/SDK layer...`);
  
  const sdkClasses = ["SdkManager", "AccountManager", "Habby.Account.AccountManager"];
  
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
          } catch {}
        }
      });
    } catch {}
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
    packets: packetCaptures,
    http: httpRequests,
    timeline: sortedEvents.slice(0, 100),
  };
  console.log(JSON.stringify(summary, null, 2));
  
  console.log("\n" + "═".repeat(66));
}

// =============================================================================
// MAIN
// =============================================================================

hookNativeNetwork();
hookIl2Cpp();
