/**
 * Combined TLS + Game Protocol Logger for Server Emulation
 * 
 * Captures both:
 * - Port 443 HTTPS/TLS traffic (game server APIs, analytics)
 * - Port 12020 binary game protocol (login, sync, heartbeat)
 * 
 * Designed for developing a private server emulator/sandbox.
 * 
 * Usage:
 *   cd client-ts
 *   bun run combined:log
 */

/// <reference path="../../frida.d.ts" />

import "frida-il2cpp-bridge";

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║     ARCHERO COMBINED LOGGER (443 + 12020)                   ║");
console.log("║     For Server Emulation / Sandbox Development              ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

// =============================================================================
// CONFIGURATION
// =============================================================================

const DISCOVERY_DURATION_MS = 90000;
const MAX_CAPTURE_BYTES = 4096;
const FILTER_ADS = true;
const SAVE_JSON = true;

// =============================================================================
// HOST CLASSIFICATION (for TLS traffic)
// =============================================================================

type HostClass = "game" | "analytics" | "ads" | "unknown";

const GAME_HOSTS = ["habby.mobi", "habby.com", "archero"];
const AD_HOSTS = [
  "applovin.com", "facebook.com", "fbcdn.net", "google.com", "googleapis.com",
  "googleadservices.com", "doubleclick.net", "unity3d.com", "unityads.unity3d.com",
  "moloco.com", "vungle.com", "mopub.com", "admob", "crashlytics",
  "fundingchoicesmessages", "app-measurement",
];
const ANALYTICS_HOSTS = [
  "receiver.habby.mobi", "adjust.com", "branch.io", "amplitude.com",
  "mixpanel.com", "segment.io", "firebase",
];

function classifyHost(hostname: string): HostClass {
  const lower = hostname.toLowerCase();
  for (const pattern of GAME_HOSTS) {
    if (lower.includes(pattern)) {
      if (lower.includes("receiver.habby.mobi")) return "analytics";
      return "game";
    }
  }
  for (const pattern of ANALYTICS_HOSTS) if (lower.includes(pattern)) return "analytics";
  for (const pattern of AD_HOSTS) if (lower.includes(pattern)) return "ads";
  return "unknown";
}

function shouldLogTls(classification: HostClass): boolean {
  if (FILTER_ADS && classification === "ads") return false;
  return true;
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

interface TlsCapture {
  t: number;
  type: "tls";
  direction: "send" | "recv";
  host: string;
  port: number;
  classification: HostClass;
  bytes: number;
  http?: {
    method?: string;
    path?: string;
    statusCode?: number;
    contentType?: string;
  };
  body?: string;
}

interface PacketCapture {
  t: number;
  type: "packet";
  direction: "C→S" | "S→C";
  packetName: string;
  fields: Record<string, any>;
}

interface NetworkEvent {
  t: number;
  type: "dns" | "connect";
  host?: string;
  ip?: string;
  port?: number;
}

// Unified capture store
const captures: (TlsCapture | PacketCapture | NetworkEvent)[] = [];

// State tracking
let startTime = 0;
const fdToAddr = new Map<number, { ip: string; port: number }>();
const ipToHostname = new Map<string, string>();
const sslToFd = new Map<string, number>();
const sslToHostname = new Map<string, string>();
const pendingSNI = new Map<number, string>(); // fd -> SNI hostname from ClientHello
let SSL_get_fd: NativeFunction<number, [NativePointer]> | null = null;

// Stats
const stats = {
  tls: { total: 0, game: 0, analytics: 0, ads: 0, unknown: 0, filtered: 0 },
  packets: { sent: 0, received: 0 },
  connections: 0,
};

let loginPacketSent = false;
let loginResponseReceived = false;

// =============================================================================
// HELPERS
// =============================================================================

function elapsed(): number {
  return startTime > 0 ? (Date.now() - startTime) / 1000 : 0;
}

function ts(): string {
  return `[${elapsed().toFixed(2)}s]`;
}

function safeString(val: any): string {
  if (val === null || val === undefined) return "<null>";
  try {
    if (val.class && val.class.name === "String") return val.content ?? "<empty>";
    return String(val);
  } catch { return "<error>"; }
}

function toAscii(buffer: ArrayBuffer, maxBytes = 512): string {
  const bytes = new Uint8Array(buffer);
  const length = Math.min(bytes.length, maxBytes);
  let out = "";
  for (let i = 0; i < length; i++) {
    const b = bytes[i];
    if (b === 0x0d) out += "\\r";
    else if (b === 0x0a) out += "\\n";
    else if (b >= 0x20 && b <= 0x7e) out += String.fromCharCode(b);
    else out += ".";
  }
  return out;
}

function bufferToString(buffer: ArrayBuffer, maxLen = 2048): string {
  const bytes = new Uint8Array(buffer);
  const length = Math.min(bytes.length, maxLen);
  let str = "";
  for (let i = 0; i < length; i++) str += String.fromCharCode(bytes[i]);
  return str;
}

// =============================================================================
// HTTP PARSING
// =============================================================================

function parseHttpRequest(data: ArrayBuffer): { method?: string; path?: string; contentType?: string } | null {
  try {
    const str = bufferToString(data, 1024);
    const match = str.match(/^(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+HTTP/);
    if (!match) return null;
    const ctMatch = str.match(/\r\nContent-Type:\s*([^\r\n]+)/i);
    return { method: match[1], path: match[2], contentType: ctMatch?.[1] };
  } catch { return null; }
}

function parseHttpResponse(data: ArrayBuffer): { statusCode?: number; contentType?: string } | null {
  try {
    const str = bufferToString(data, 1024);
    const match = str.match(/^HTTP\/[\d.]+\s+(\d+)/);
    if (!match) return null;
    const ctMatch = str.match(/\r\nContent-Type:\s*([^\r\n]+)/i);
    return { statusCode: parseInt(match[1]), contentType: ctMatch?.[1] };
  } catch { return null; }
}

function extractBody(data: ArrayBuffer): string | undefined {
  try {
    const str = bufferToString(data, 4096);
    const idx = str.indexOf("\r\n\r\n");
    if (idx < 0) return undefined;
    const body = str.substring(idx + 4, idx + 4 + 1024);
    return body.length > 0 ? body : undefined;
  } catch { return undefined; }
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
          try {
            const count = value.method("get_Count").invoke();
            result[fieldName] = { type: typeName.split("`")[0], count: Number(count) };
          } catch { result[fieldName] = { type: typeName.split("`")[0] }; }
          return;
        }
        if (value.class && depth < 2) {
          const nested = dumpAllFields(value, depth + 1);
          if (Object.keys(nested).length > 0) result[fieldName] = { type: typeName, fields: nested };
          return;
        }
        result[fieldName] = safeString(value);
      } catch (e: any) { result[fieldName] = `<error>`; }
    });
  } catch {}
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
// TLS HOST RESOLUTION
// =============================================================================

function extractHostHeader(data: ArrayBuffer): string | null {
  try {
    const str = bufferToString(data, 512);
    const match = str.match(/\r\nHost:\s*([^\r\n:]+)/i);
    return match ? match[1].trim() : null;
  } catch { return null; }
}

// Extract SNI from TLS ClientHello handshake
function extractSNI(data: ArrayBuffer): string | null {
  try {
    const bytes = new Uint8Array(data);
    // Check TLS record: 0x16 = Handshake, 0x03 0x01 = TLS 1.0 (used in ClientHello)
    if (bytes.length < 5 || bytes[0] !== 0x16) return null;
    // Handshake type should be ClientHello (0x01)
    if (bytes.length < 6 || bytes[5] !== 0x01) return null;
    
    let pos = 43; // Skip: record header(5) + handshake hdr(4) + version(2) + random(32)
    if (bytes.length <= pos) return null;
    
    // Skip session ID
    const sessionLen = bytes[pos];
    pos += 1 + sessionLen;
    if (bytes.length <= pos + 2) return null;
    
    // Skip cipher suites
    const cipherLen = (bytes[pos] << 8) | bytes[pos + 1];
    pos += 2 + cipherLen;
    if (bytes.length <= pos + 1) return null;
    
    // Skip compression methods
    const compLen = bytes[pos];
    pos += 1 + compLen;
    if (bytes.length <= pos + 2) return null;
    
    // Extensions length
    const extLen = (bytes[pos] << 8) | bytes[pos + 1];
    pos += 2;
    const extEnd = pos + extLen;
    
    // Parse extensions
    while (pos + 4 < extEnd && pos + 4 < bytes.length) {
      const extType = (bytes[pos] << 8) | bytes[pos + 1];
      const extDataLen = (bytes[pos + 2] << 8) | bytes[pos + 3];
      pos += 4;
      
      if (extType === 0) { // SNI extension
        if (pos + 5 < bytes.length) {
          // Skip SNI list length (2 bytes), type (1 byte)
          const nameLen = (bytes[pos + 3] << 8) | bytes[pos + 4];
          if (pos + 5 + nameLen <= bytes.length) {
            let hostname = "";
            for (let i = 0; i < nameLen; i++) {
              hostname += String.fromCharCode(bytes[pos + 5 + i]);
            }
            return hostname;
          }
        }
      }
      pos += extDataLen;
    }
  } catch {}
  return null;
}

function getHostForFd(fd: number): { host: string; port: number } {
  const addr = fdToAddr.get(fd);
  if (addr) {
    // Try SNI first, then DNS cache, then IP
    const sni = pendingSNI.get(fd);
    if (sni) return { host: sni, port: addr.port };
    const dns = ipToHostname.get(addr.ip);
    if (dns) return { host: dns, port: addr.port };
    return { host: addr.ip, port: addr.port };
  }
  return { host: "unknown", port: 443 };
}

function getHostForSSL(ssl: NativePointer, data?: ArrayBuffer): { host: string; port: number } {
  const sslKey = ssl.toString();
  const cached = sslToHostname.get(sslKey);
  if (cached) {
    const fd = sslToFd.get(sslKey);
    return { host: cached, port: fd !== undefined ? fdToAddr.get(fd)?.port || 443 : 443 };
  }
  
  let fd = sslToFd.get(sslKey) ?? -1;
  if (fd < 0 && SSL_get_fd) {
    try { fd = SSL_get_fd(ssl); if (fd >= 0) sslToFd.set(sslKey, fd); } catch {}
  }
  
  if (data) {
    // Try SNI extraction first (for ClientHello)
    const sni = extractSNI(data);
    if (sni) {
      sslToHostname.set(sslKey, sni);
      if (fd >= 0) {
        pendingSNI.set(fd, sni);
        const addr = fdToAddr.get(fd);
        if (addr && !ipToHostname.has(addr.ip)) ipToHostname.set(addr.ip, sni);
      }
      return { host: sni, port: fd >= 0 ? fdToAddr.get(fd)?.port || 443 : 443 };
    }
    
    // Try HTTP Host header
    const host = extractHostHeader(data);
    if (host) {
      sslToHostname.set(sslKey, host);
      if (fd >= 0) {
        const addr = fdToAddr.get(fd);
        if (addr && !ipToHostname.has(addr.ip)) ipToHostname.set(addr.ip, host);
      }
      return { host, port: fd >= 0 ? fdToAddr.get(fd)?.port || 443 : 443 };
    }
  }
  
  if (fd >= 0) return getHostForFd(fd);
  return { host: "unknown", port: 443 };
}

// =============================================================================
// NATIVE HOOKS: DNS + CONNECT + TLS
// =============================================================================

function hookNativeNetwork(): void {
  console.log("[NATIVE] Setting up network hooks...");
  const libc = Process.getModuleByName("libc.so");

  // getaddrinfo - capture DNS resolution results
  try {
    const ptr = libc.findExportByName("getaddrinfo");
    if (ptr) {
      Interceptor.attach(ptr, {
        onEnter(args) {
          try {
            (this as any).hostname = args[0].readUtf8String();
            (this as any).result = args[3];
          } catch { (this as any).hostname = null; }
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
                  if (family === 2) { // AF_INET
                    const addrOffset = Process.pointerSize === 8 ? 24 : 16;
                    const addr = ai.add(addrOffset).readPointer();
                    if (!addr.isNull()) {
                      const ip = `${addr.add(4).readU8()}.${addr.add(5).readU8()}.${addr.add(6).readU8()}.${addr.add(7).readU8()}`;
                      ipToHostname.set(ip, hostname);
                    }
                  }
                  // Move to next addrinfo (ai_next is at end of struct)
                  const nextOffset = Process.pointerSize === 8 ? 40 : 28;
                  ai = ai.add(nextOffset).readPointer();
                } catch { break; }
              }
              captures.push({ t: elapsed(), type: "dns", host: hostname });
            }
          } catch { }
        },
      });
      console.log("   ✓ getaddrinfo");
    }
  } catch { }

  // gethostbyname - legacy DNS resolution (used by some libraries)
  try {
    const ptr = libc.findExportByName("gethostbyname");
    if (ptr) {
      Interceptor.attach(ptr, {
        onEnter(args) {
          try { (this as any).hostname = args[0].readUtf8String(); } catch { (this as any).hostname = null; }
        },
        onLeave(retval) {
          try {
            const hostname = (this as any).hostname;
            if (hostname && !retval.isNull()) {
              // struct hostent: h_addr_list is at offset 16 (32-bit) or 24 (64-bit)
              const addrListOffset = Process.pointerSize === 8 ? 24 : 16;
              const addrList = retval.add(addrListOffset).readPointer();
              if (!addrList.isNull()) {
                const addrPtr = addrList.readPointer();
                if (!addrPtr.isNull()) {
                  const ip = `${addrPtr.readU8()}.${addrPtr.add(1).readU8()}.${addrPtr.add(2).readU8()}.${addrPtr.add(3).readU8()}`;
                  ipToHostname.set(ip, hostname);
                }
              }
            }
          } catch { }
        },
      });
      console.log("   ✓ gethostbyname");
    }
  } catch { }

  // android_getaddrinfofornet - Android-specific DNS
  try {
    const ptr = libc.findExportByName("android_getaddrinfofornet");
    if (ptr) {
      Interceptor.attach(ptr, {
        onEnter(args) {
          try { (this as any).hostname = args[0].readUtf8String(); (this as any).result = args[3]; } catch { (this as any).hostname = null; }
        },
        onLeave(retval) {
          try {
            const hostname = (this as any).hostname;
            const resultPtr = (this as any).result;
            if (hostname && retval.toInt32() === 0 && resultPtr) {
              let ai = resultPtr.readPointer();
              if (!ai.isNull()) {
                const family = ai.add(4).readS32();
                if (family === 2) {
                  const addr = ai.add(Process.pointerSize === 8 ? 24 : 16).readPointer();
                  if (!addr.isNull()) {
                    const ip = `${addr.add(4).readU8()}.${addr.add(5).readU8()}.${addr.add(6).readU8()}.${addr.add(7).readU8()}`;
                    ipToHostname.set(ip, hostname);
                  }
                }
              }
            }
          } catch {}
        },
      });
      console.log("   ✓ android_getaddrinfofornet");
    }
  } catch {}

  // connect - track socket file descriptors to IPs
  try {
    const ptr = libc.findExportByName("connect");
    if (ptr) {
      Interceptor.attach(ptr, {
        onEnter(args) {
          try {
            const fd = args[0].toInt32();
            const sockaddr = args[1];
            const family = sockaddr.readU16();
            if (family === 2) { // AF_INET
              const portBE = sockaddr.add(2).readU16();
              const port = ((portBE & 0xff) << 8) | ((portBE >> 8) & 0xff);
              const ip = `${sockaddr.add(4).readU8()}.${sockaddr.add(5).readU8()}.${sockaddr.add(6).readU8()}.${sockaddr.add(7).readU8()}`;
              fdToAddr.set(fd, { ip, port });
              if (port === 443 || port === 12020) {
                stats.connections++;
                const hostname = ipToHostname.get(ip) || ip;
                captures.push({ t: elapsed(), type: "connect", ip, port, host: hostname });
                if (ipToHostname.has(ip)) {
                  console.log(`${ts()} [CONNECT] ${hostname}:${port}`);
                } else {
                  console.log(`${ts()} [CONNECT] ${ip}:${port}`);
                }
              }
            }
          } catch {}
        },
      });
      console.log("   ✓ connect");
    }
  } catch {}
}

function hookTLS(): void {
  console.log("[NATIVE] Setting up TLS hooks...");
  const modules = Process.enumerateModules();
  
  // Search modules that may contain SSL functions
  const sslModules = modules.filter(mod => {
    const name = mod.name.toLowerCase();
    return name.includes("ssl") || name.includes("crypto") || name.includes("unity");
  });

    try {
      const getFdPtr = mod.findExportByName("SSL_get_fd");
      if (getFdPtr) {
        SSL_get_fd = new NativeFunction(getFdPtr, "int", ["pointer"]);
        console.log("   ✓ SSL_get_fd");
      }
    } catch {}

    try {
      const setFdPtr = mod.findExportByName("SSL_set_fd");
      if (setFdPtr) {
        Interceptor.attach(setFdPtr, {
          onEnter(args) { sslToFd.set(args[0].toString(), args[1].toInt32()); },
        });
        console.log("   ✓ SSL_set_fd");
      }
    } catch {}

  // SSL_ctrl - captures SNI hostname via SSL_set_tlsext_host_name (cmd=55)
  try {
    const ctrlPtr = mod.findExportByName("SSL_ctrl");
    if (ctrlPtr) {
      Interceptor.attach(ctrlPtr, {
        onEnter(args) {
          try {
            const cmd = args[1].toInt32();
            // SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
            if (cmd === 55) {
              const hostname = args[3].readUtf8String();
              if (hostname) {
                const sslKey = args[0].toString();
                sslToHostname.set(sslKey, hostname);
                const fd = sslToFd.get(sslKey);
                if (fd !== undefined) {
                  const addr = fdToAddr.get(fd);
                  if (addr) {
                    ipToHostname.set(addr.ip, hostname);
                  }
                }
              }
            }
          } catch { }
        },
      });
      console.log("   ✓ SSL_ctrl (SNI)");
    }
  } catch { }

    try {
      const sslRead = mod.findExportByName("SSL_read");
      if (sslRead) {
        Interceptor.attach(sslRead, {
          onEnter(args) { (this as any).ssl = args[0]; (this as any).buf = args[1]; },
          onLeave(retval) {
            const ret = retval.toInt32();
            if (ret > 0) {
              const data = (this as any).buf.readByteArray(Math.min(ret, MAX_CAPTURE_BYTES));
              if (data) {
                // Try to resolve host - for recv, we don't have Host header but cache should be populated from previous send
                let { host, port } = getHostForSSL((this as any).ssl);

                // If still unknown, try to get fd and lookup by IP one more time
                if (host === "unknown") {
                  const sslKey = ((this as any).ssl as NativePointer).toString();
                  let fd = sslToFd.get(sslKey);
                  if (fd === undefined && SSL_get_fd) {
                    try {
                      fd = SSL_get_fd((this as any).ssl);
                      if (fd >= 0) sslToFd.set(sslKey, fd);
                    } catch { }
                  }
                  if (fd !== undefined) {
                    const addr = fdToAddr.get(fd);
                    if (addr) {
                      const cachedHost = ipToHostname.get(addr.ip);
                      if (cachedHost) {
                        host = cachedHost;
                        sslToHostname.set(sslKey, host);
                      }
                      port = addr.port;
                    }
                  }
                }

                const classification = classifyHost(host);
                stats.tls.total++; stats.tls[classification]++;
                if (!shouldLogTls(classification)) { stats.tls.filtered++; return; }
                
                const http = parseHttpResponse(data);
                const capture: TlsCapture = { t: elapsed(), type: "tls", direction: "recv", host, port, classification, bytes: ret, http: http || undefined };
                const body = extractBody(data);
                if (body) capture.body = body.substring(0, 500);
                captures.push(capture);
                
                console.log(`${ts()} [TLS:RECV] ← ${host}:${port} [${classification.toUpperCase()}] (${ret}B)`);
                if (http?.statusCode) console.log(`   HTTP ${http.statusCode}`);
              }
            }
          },
        });
        console.log("   ✓ SSL_read");
      }
    } catch {}

    try {
      const sslWrite = mod.findExportByName("SSL_write");
      if (sslWrite) {
        Interceptor.attach(sslWrite, {
          onEnter(args) { (this as any).ssl = args[0]; (this as any).buf = args[1]; (this as any).num = args[2].toInt32(); },
          onLeave(retval) {
            const ret = retval.toInt32();
            if (ret > 0) {
              const data = (this as any).buf.readByteArray(Math.min(ret, MAX_CAPTURE_BYTES));
              if (data) {
                const { host, port } = getHostForSSL((this as any).ssl, data);
                const classification = classifyHost(host);
                stats.tls.total++; stats.tls[classification]++;
                if (!shouldLogTls(classification)) { stats.tls.filtered++; return; }
                
                const http = parseHttpRequest(data);
                const capture: TlsCapture = { t: elapsed(), type: "tls", direction: "send", host, port, classification, bytes: ret, http: http || undefined };
                const body = extractBody(data);
                if (body) capture.body = body.substring(0, 500);
                captures.push(capture);
                
                console.log(`${ts()} [TLS:SEND] → ${host}:${port} [${classification.toUpperCase()}] (${ret}B)`);
                if (http?.method) console.log(`   ${http.method} ${http.path}`);
              }
            }
          },
        });
        console.log("   ✓ SSL_write");
      }
    } catch {}

    break; // Only first SSL lib
  }
}

// =============================================================================
// IL2CPP HOOKS: Game Protocol (Port 12020)
// =============================================================================

function hookGameProtocol(): void {
  console.log("[IL2CPP] Waiting for runtime...");

  Il2Cpp.perform(() => {
    startTime = Date.now();
    console.log(`${ts()} [IL2CPP] Runtime ready, installing protocol hooks...`);

    try {
      const asm = Il2Cpp.domain.assembly("Assembly-CSharp").image;
      hookLoginPackets(asm);
      hookSyncPackets(asm);
      hookTcpNetManager(asm);
      hookEncryption(asm);
      
      console.log(`\n${ts()} [READY] All hooks installed. Capturing for ${DISCOVERY_DURATION_MS / 1000}s...`);
      console.log("═".repeat(66));
      
      setTimeout(() => printSummary(), DISCOVERY_DURATION_MS);
    } catch (e) {
      console.log(`${ts()} [ERROR] Failed to hook IL2CPP: ${e}`);
    }
  });
}

function hookLoginPackets(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Login packets...`);

  const packets = [
    "GameProtocol.CUserLoginPacket",
    "GameProtocol.CRespUserLoginPacket",
    "GameProtocol.CHeartBeatPacket",
    "GameProtocol.CRespHeartBeatPacket",
  ];

  for (const fullName of packets) {
    try {
      const clazz = asm.class(fullName);
      const hookName = fullName.split(".").pop()!; // For logging during setup

      try {
        clazz.method("WriteToStream").implementation = function (writer: any) {
          // Get actual runtime class name from the instance
          const actualName = (this as any).class?.name || hookName;
          const fields = dumpAllFields(this);
          console.log(`\n${ts()} ┌───────────────────────────────────────────`);
          console.log(`${ts()} │ 📤 PACKET OUT: ${actualName}`);
          console.log(`${ts()} ├───────────────────────────────────────────`);
          printFields(fields);
          console.log(`${ts()} └───────────────────────────────────────────\n`);

          if (actualName === "CUserLoginPacket") loginPacketSent = true;
          stats.packets.sent++;
          captures.push({ t: elapsed(), type: "packet", direction: "C→S", packetName: actualName, fields });

          return this.method("WriteToStream").invoke(writer);
        };
        console.log(`${ts()}   ✓ ${hookName}.WriteToStream`);
      } catch {}

      try {
        clazz.method("ReadFromStream").implementation = function (reader: any) {
          const result = this.method("ReadFromStream").invoke(reader);
          // Get actual runtime class name from the instance
          const actualName = (this as any).class?.name || hookName;
          const fields = dumpAllFields(this);

          console.log(`\n${ts()} ┌───────────────────────────────────────────`);
          console.log(`${ts()} │ 📥 PACKET IN: ${actualName}`);
          console.log(`${ts()} ├───────────────────────────────────────────`);
          printFields(fields);
          console.log(`${ts()} └───────────────────────────────────────────\n`);

          if (actualName === "CRespUserLoginPacket") loginResponseReceived = true;
          stats.packets.received++;
          captures.push({ t: elapsed(), type: "packet", direction: "S→C", packetName: actualName, fields });

          return result;
        };
        console.log(`${ts()}   ✓ ${hookName}.ReadFromStream`);
      } catch {}
    } catch {}
  }
}

function hookSyncPackets(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Sync packets...`);

  const packets = [
    "GameProtocol.CSyncUserPacket",
    "GameProtocol.CRespSyncUserPacket",
  ];

  for (const fullName of packets) {
    try {
      const clazz = asm.class(fullName);
      const hookName = fullName.split(".").pop()!;

      try {
        clazz.method("WriteToStream").implementation = function (writer: any) {
          const actualName = (this as any).class?.name || hookName;
          const fields = dumpAllFields(this);
          console.log(`${ts()} 📤 ${actualName} (${Object.keys(fields).length} fields)`);
          stats.packets.sent++;
          captures.push({ t: elapsed(), type: "packet", direction: "C→S", packetName: actualName, fields });
          return this.method("WriteToStream").invoke(writer);
        };
      } catch {}

      try {
        clazz.method("ReadFromStream").implementation = function (reader: any) {
          const result = this.method("ReadFromStream").invoke(reader);
          const actualName = (this as any).class?.name || hookName;
          const fields = dumpAllFields(this);
          console.log(`${ts()} 📥 ${actualName} (${Object.keys(fields).length} fields)`);
          stats.packets.received++;
          captures.push({ t: elapsed(), type: "packet", direction: "S→C", packetName: actualName, fields });
          return result;
        };
      } catch {}
    } catch {}
  }
}

function hookTcpNetManager(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] TcpNetManager...`);
  try {
    const tcpNetMgr = asm.class("TcpNetManager");
    try {
      tcpNetMgr.method("SendPacket").implementation = function (packet: any, msgId: any) {
        const packetType = packet?.class?.name || "unknown";
        console.log(`${ts()} [TCP] SendPacket(${msgId}) → ${packetType}`);
        return this.method("SendPacket").invoke(packet, msgId);
      };
      console.log(`${ts()}   ✓ TcpNetManager.SendPacket`);
    } catch {}
  } catch {}
}

function hookEncryption(asm: Il2Cpp.Image): void {
  console.log(`${ts()} [HOOK] Encryption...`);
  try {
    const rc4 = asm.class("RC4Encrypter");
    try {
      rc4.method(".ctor").implementation = function (key: any) {
        const keyStr = safeString(key);
        console.log(`${ts()} [CRYPTO] RC4 Key: ${keyStr.substring(0, 32)}${keyStr.length > 32 ? "..." : ""}`);
        return this.method(".ctor").invoke(key);
      };
      console.log(`${ts()}   ✓ RC4Encrypter.ctor`);
    } catch {}
  } catch {}
}

// =============================================================================
// SUMMARY
// =============================================================================

function printSummary(): void {
  console.log("\n\n");
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║               COMBINED CAPTURE SUMMARY                       ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");

  console.log(`\n📊 Statistics:`);
  console.log(`   Duration: ${elapsed().toFixed(1)}s`);
  console.log(`   Login sent: ${loginPacketSent ? "✓" : "✗"} | Login received: ${loginResponseReceived ? "✓" : "✗"}`);
  console.log(`   Connections: ${stats.connections}`);
  console.log(`   TLS: ${stats.tls.total} (game=${stats.tls.game}, analytics=${stats.tls.analytics}, filtered=${stats.tls.filtered})`);
  console.log(`   Packets: sent=${stats.packets.sent}, received=${stats.packets.received}`);

  // Group captures
  const tlsCaptures = captures.filter(c => c.type === "tls") as TlsCapture[];
  const packetCaptures = captures.filter(c => c.type === "packet") as PacketCapture[];

  console.log(`\n📊 TLS Traffic by Host:`);
  const byHost = new Map<string, { send: number; recv: number; class: HostClass }>();
  for (const c of tlsCaptures) {
    const e = byHost.get(c.host) || { send: 0, recv: 0, class: c.classification };
    if (c.direction === "send") e.send += c.bytes; else e.recv += c.bytes;
    byHost.set(c.host, e);
  }
  for (const [host, s] of byHost.entries()) {
    console.log(`   [${s.class.toUpperCase().padEnd(9)}] ${host}: ↑${s.send}B ↓${s.recv}B`);
  }

  console.log(`\n📊 Game Packets:`);
  for (const p of packetCaptures) {
    console.log(`   [${p.t.toFixed(2)}s] ${p.direction} ${p.packetName}`);
  }

  if (SAVE_JSON) {
    console.log(`\n📁 JSON Output (${captures.length} events):`);
    console.log("=== BEGIN JSON ===");
    for (const c of captures) {
      console.log(JSON.stringify(c));
    }
    console.log("=== END JSON ===");
  }
}

// =============================================================================
// MAIN
// =============================================================================

hookNativeNetwork();
hookTLS();
hookGameProtocol();
