/**
 * TLS Traffic Logger v2 - Android
 * 
 * Improved version with:
 * - Host classification (game vs ads/analytics)
 * - Filtering of ad network traffic
 * - Structured JSON output for server emulation
 * - HTTP request/response parsing
 * - Gzip decompression attempts
 * 
 * Usage:
 *   cd client-ts
 *   bun run port443:log:v2
 */

/// <reference path="../../frida.d.ts" />

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║     ARCHERO TLS TRAFFIC LOGGER v2                           ║");
console.log("║     Game-focused capture with filtering                      ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

// =============================================================================
// CONFIGURATION
// =============================================================================

const DISCOVERY_DURATION_MS = 90000;
const MAX_CAPTURE_BYTES = 4096;
const FILTER_ADS = true;         // Skip logging ad network traffic
const GAME_ONLY = false;         // Only log traffic to known game servers
const SAVE_JSON = true;          // Save captures to JSON file
const VERBOSE_HEADERS = false;   // Show all headers in console

// =============================================================================
// HOST CLASSIFICATION
// =============================================================================

type HostClass = "game" | "analytics" | "ads" | "unknown";

// Known game server domains
const GAME_HOSTS = [
  "habby.mobi",
  "habby.com",
  "archero",
];

// Known ad network domains (to filter)
const AD_HOSTS = [
  "applovin.com",
  "facebook.com",
  "fbcdn.net",
  "google.com",
  "googleapis.com",
  "googleadservices.com",
  "doubleclick.net",
  "unity3d.com",
  "unityads.unity3d.com",
  "moloco.com",
  "vungle.com",
  "mopub.com",
  "admob",
  "crashlytics",
  "fundingchoicesmessages",
  "app-measurement",
];

// Analytics (not ads, but not core game)
const ANALYTICS_HOSTS = [
  "receiver.habby.mobi",  // ThinkingData analytics
  "adjust.com",
  "branch.io",
  "amplitude.com",
  "mixpanel.com",
  "segment.io",
  "firebase",
];

function classifyHost(hostname: string): HostClass {
  const lower = hostname.toLowerCase();
  
  // Check game hosts first
  for (const pattern of GAME_HOSTS) {
    if (lower.includes(pattern)) {
      // Exclude analytics subdomain
      if (lower.includes("receiver.habby.mobi")) return "analytics";
      return "game";
    }
  }
  
  // Check analytics
  for (const pattern of ANALYTICS_HOSTS) {
    if (lower.includes(pattern)) return "analytics";
  }
  
  // Check ad networks
  for (const pattern of AD_HOSTS) {
    if (lower.includes(pattern)) return "ads";
  }
  
  return "unknown";
}

function shouldLog(classification: HostClass): boolean {
  if (GAME_ONLY && classification !== "game") return false;
  if (FILTER_ADS && classification === "ads") return false;
  return true;
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

interface HttpInfo {
  method?: string;
  path?: string;
  statusCode?: number;
  statusText?: string;
  headers: Record<string, string>;
  contentType?: string;
  contentEncoding?: string;
  contentLength?: number;
}

interface BodyInfo {
  type: "text" | "binary" | "json";
  data: string;
  truncated?: boolean;
  originalSize?: number;
}

interface TlsCapture {
  t: number;
  direction: "send" | "recv";
  host: string;
  port: number;
  classification: HostClass;
  bytes: number;
  http?: HttpInfo;
  body?: BodyInfo;
  raw?: string;  // First N bytes as escaped string
}

// =============================================================================
// STATE
// =============================================================================

let startTime = 0;
const captures: TlsCapture[] = [];

// Mapping tables
const fdToAddr = new Map<number, { ip: string; port: number }>();
const ipToHostname = new Map<string, string>();
const sslToFd = new Map<string, number>();
const sslToHostname = new Map<string, string>();
const hostnameToIPs = new Map<string, string[]>();

let SSL_get_fd: NativeFunction<number, [NativePointer]> | null = null;

// Stats
const stats = {
  total: 0,
  game: 0,
  analytics: 0,
  ads: 0,
  unknown: 0,
  filtered: 0,
};

// =============================================================================
// HELPERS
// =============================================================================

function elapsed(): number {
  return startTime > 0 ? (Date.now() - startTime) / 1000 : 0;
}

function ts(): string {
  return `[${elapsed().toFixed(2)}s]`;
}

function toAscii(buffer: ArrayBuffer, maxBytes = MAX_CAPTURE_BYTES): string {
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
  for (let i = 0; i < length; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return str;
}

function toBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  // Frida doesn't have btoa, use manual encoding
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  let i = 0;
  while (i < binary.length) {
    const a = binary.charCodeAt(i++);
    const b = i < binary.length ? binary.charCodeAt(i++) : 0;
    const c = i < binary.length ? binary.charCodeAt(i++) : 0;
    const triple = (a << 16) | (b << 8) | c;
    result += chars[(triple >> 18) & 0x3f];
    result += chars[(triple >> 12) & 0x3f];
    result += i > binary.length + 1 ? "=" : chars[(triple >> 6) & 0x3f];
    result += i > binary.length ? "=" : chars[triple & 0x3f];
  }
  return result;
}

// =============================================================================
// HTTP PARSING
// =============================================================================

function parseHttpRequest(data: ArrayBuffer): HttpInfo | null {
  try {
    const str = bufferToString(data, 2048);
    const lines = str.split("\r\n");
    if (lines.length < 1) return null;
    
    // Parse request line: METHOD PATH HTTP/1.1
    const requestLine = lines[0];
    const match = requestLine.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/);
    if (!match) return null;
    
    const headers: Record<string, string> = {};
    let i = 1;
    while (i < lines.length && lines[i] !== "") {
      const colonIdx = lines[i].indexOf(":");
      if (colonIdx > 0) {
        const key = lines[i].substring(0, colonIdx).trim();
        const value = lines[i].substring(colonIdx + 1).trim();
        headers[key.toLowerCase()] = value;
      }
      i++;
    }
    
    return {
      method: match[1],
      path: match[2],
      headers,
      contentType: headers["content-type"],
      contentEncoding: headers["content-encoding"],
      contentLength: headers["content-length"] ? parseInt(headers["content-length"]) : undefined,
    };
  } catch {
    return null;
  }
}

function parseHttpResponse(data: ArrayBuffer): HttpInfo | null {
  try {
    const str = bufferToString(data, 2048);
    const lines = str.split("\r\n");
    if (lines.length < 1) return null;
    
    // Parse status line: HTTP/1.1 200 OK
    const statusLine = lines[0];
    const match = statusLine.match(/^HTTP\/[\d.]+\s+(\d+)\s*(.*)/);
    if (!match) return null;
    
    const headers: Record<string, string> = {};
    let i = 1;
    while (i < lines.length && lines[i] !== "") {
      const colonIdx = lines[i].indexOf(":");
      if (colonIdx > 0) {
        const key = lines[i].substring(0, colonIdx).trim();
        const value = lines[i].substring(colonIdx + 1).trim();
        headers[key.toLowerCase()] = value;
      }
      i++;
    }
    
    return {
      statusCode: parseInt(match[1]),
      statusText: match[2],
      headers,
      contentType: headers["content-type"],
      contentEncoding: headers["content-encoding"],
      contentLength: headers["content-length"] ? parseInt(headers["content-length"]) : undefined,
    };
  } catch {
    return null;
  }
}

function extractHttpBody(data: ArrayBuffer): BodyInfo | null {
  try {
    const str = bufferToString(data, 8192);
    const bodyStart = str.indexOf("\r\n\r\n");
    if (bodyStart < 0) return null;
    
    const bodyStr = str.substring(bodyStart + 4);
    if (bodyStr.length === 0) return null;
    
    // Check if it looks like JSON
    const trimmed = bodyStr.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      return {
        type: "json",
        data: trimmed.substring(0, 4096),
        truncated: trimmed.length > 4096,
        originalSize: trimmed.length,
      };
    }
    
    // Check if it's printable text
    let printable = true;
    for (let i = 0; i < Math.min(100, bodyStr.length); i++) {
      const c = bodyStr.charCodeAt(i);
      if (c < 32 && c !== 9 && c !== 10 && c !== 13) {
        printable = false;
        break;
      }
    }
    
    if (printable) {
      return {
        type: "text",
        data: bodyStr.substring(0, 2048),
        truncated: bodyStr.length > 2048,
        originalSize: bodyStr.length,
      };
    }
    
    // Binary - base64 encode
    const bytes = new Uint8Array(data);
    const bodyBytes = bytes.slice(bodyStart + 4, Math.min(bytes.length, bodyStart + 4 + 1024));
    return {
      type: "binary",
      data: toBase64(bodyBytes.buffer),
      truncated: bytes.length > bodyStart + 4 + 1024,
      originalSize: bytes.length - bodyStart - 4,
    };
  } catch {
    return null;
  }
}

// =============================================================================
// HOST RESOLUTION
// =============================================================================

function extractHostHeader(data: ArrayBuffer): string | null {
  try {
    const bytes = new Uint8Array(data);
    const maxLen = Math.min(bytes.length, 1024);
    let str = "";
    for (let i = 0; i < maxLen; i++) {
      str += String.fromCharCode(bytes[i]);
    }
    const match = str.match(/\r\nHost:\s*([^\r\n]+)/i);
    if (match) {
      return match[1].split(":")[0].trim();
    }
  } catch {}
  return null;
}

function getHostForFd(fd: number): { host: string; port: number } {
  const addr = fdToAddr.get(fd);
  if (addr) {
    const hostname = ipToHostname.get(addr.ip) || addr.ip;
    return { host: hostname, port: addr.port };
  }
  return { host: "unknown", port: 443 };
}

function getHostForSSL(ssl: NativePointer, dataForHostExtract?: ArrayBuffer): { host: string; port: number } {
  const sslKey = ssl.toString();

  // 1. Check cached hostname
  const cachedHost = sslToHostname.get(sslKey);
  if (cachedHost) {
    const cachedFd = sslToFd.get(sslKey);
    if (cachedFd !== undefined) {
      const addr = fdToAddr.get(cachedFd);
      return { host: cachedHost, port: addr?.port || 443 };
    }
    return { host: cachedHost, port: 443 };
  }

  // 2. Try SSL_get_fd
  let fd = -1;
  if (SSL_get_fd) {
    try {
      fd = SSL_get_fd(ssl);
      if (fd >= 0) {
        sslToFd.set(sslKey, fd);
      }
    } catch {}
  }

  // 3. Extract Host header
  if (dataForHostExtract) {
    const hostFromHeader = extractHostHeader(dataForHostExtract);
    if (hostFromHeader) {
      sslToHostname.set(sslKey, hostFromHeader);
      if (fd >= 0) {
        const addr = fdToAddr.get(fd);
        if (addr && !ipToHostname.has(addr.ip)) {
          ipToHostname.set(addr.ip, hostFromHeader);
        }
      }
      const addr = fd >= 0 ? fdToAddr.get(fd) : undefined;
      return { host: hostFromHeader, port: addr?.port || 443 };
    }
  }

  // 4. Fall back to fd lookup
  if (fd >= 0) {
    return getHostForFd(fd);
  }

  return { host: "unknown", port: 443 };
}

// =============================================================================
// LOGGING
// =============================================================================

function classTag(c: HostClass): string {
  switch (c) {
    case "game": return "\x1b[32m[GAME]\x1b[0m";
    case "analytics": return "\x1b[33m[ANLYT]\x1b[0m";
    case "ads": return "\x1b[90m[ADS]\x1b[0m";
    default: return "\x1b[36m[???]\x1b[0m";
  }
}

function logCapture(capture: TlsCapture): void {
  stats.total++;
  stats[capture.classification]++;
  
  if (!shouldLog(capture.classification)) {
    stats.filtered++;
    return;
  }
  
  captures.push(capture);
  
  const dir = capture.direction === "send" ? "→" : "←";
  const tag = classTag(capture.classification);
  
  console.log(`\n${ts()} [${capture.direction.toUpperCase()}] ${dir} ${capture.host}:${capture.port} ${tag} (${capture.bytes}B)`);
  
  if (capture.http) {
    if (capture.direction === "send" && capture.http.method) {
      console.log(`   ${capture.http.method} ${capture.http.path}`);
    } else if (capture.direction === "recv" && capture.http.statusCode) {
      console.log(`   HTTP ${capture.http.statusCode} ${capture.http.statusText || ""}`);
    }
    
    if (VERBOSE_HEADERS && capture.http.headers) {
      for (const [k, v] of Object.entries(capture.http.headers)) {
        console.log(`   ${k}: ${v.substring(0, 80)}`);
      }
    } else if (capture.http.contentType) {
      console.log(`   Content-Type: ${capture.http.contentType}`);
    }
  }
  
  if (capture.body && capture.body.type !== "binary") {
    const preview = capture.body.data.substring(0, 200);
    console.log(`   Body: ${preview}${capture.body.data.length > 200 ? "..." : ""}`);
  } else if (capture.raw) {
    console.log(`   ${capture.raw.substring(0, 200)}${capture.raw.length > 200 ? "..." : ""}`);
  }
}

// =============================================================================
// HOOKS
// =============================================================================

function hookNetwork(): void {
  console.log(`\n${ts()} [HOOKS] Installing hooks...`);
  const libc = Process.getModuleByName("libc.so");

  // getaddrinfo - map hostname -> IPs
  try {
    const ptr = libc.findExportByName("getaddrinfo");
    if (ptr) {
      Interceptor.attach(ptr, {
        onEnter(args) {
          try {
            (this as any).hostname = args[0].readUtf8String();
            (this as any).result = args[3];
          } catch {
            (this as any).hostname = null;
          }
        },
        onLeave(retval) {
          try {
            const hostname = (this as any).hostname;
            const resultPtr = (this as any).result;
            if (hostname && retval.toInt32() === 0 && resultPtr) {
              let ai = resultPtr.readPointer();
              const ips: string[] = [];
              while (!ai.isNull()) {
                const family = ai.add(4).readInt();
                if (family === 2) {
                  const addr = ai.add(Process.pointerSize === 8 ? 24 : 16).readPointer();
                  if (!addr.isNull()) {
                    const ip = `${addr.add(4).readU8()}.${addr.add(5).readU8()}.${addr.add(6).readU8()}.${addr.add(7).readU8()}`;
                    ips.push(ip);
                    if (!ipToHostname.has(ip)) {
                      ipToHostname.set(ip, hostname);
                    }
                  }
                }
                ai = ai.add(Process.pointerSize === 8 ? 48 : 32).readPointer();
              }
              if (ips.length > 0) {
                hostnameToIPs.set(hostname, ips);
              }
            }
          } catch {}
        },
      });
      console.log("   ✓ getaddrinfo");
    }
  } catch {}

  // connect - track fd -> address
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
            }
          } catch {}
        },
      });
      console.log("   ✓ connect");
    }
  } catch {}

  // Find SSL module and hook
  const modules = Process.enumerateModules();
  for (const mod of modules) {
    if (mod.name.toLowerCase().includes("ssl")) {
      // SSL_get_fd
      try {
        const getFdPtr = mod.findExportByName("SSL_get_fd");
        if (getFdPtr) {
          SSL_get_fd = new NativeFunction(getFdPtr, "int", ["pointer"]);
          console.log(`   ✓ SSL_get_fd`);
        }
      } catch {}

      // SSL_set_fd
      try {
        const setFdPtr = mod.findExportByName("SSL_set_fd");
        if (setFdPtr) {
          Interceptor.attach(setFdPtr, {
            onEnter(args) {
              const ssl = args[0];
              const fd = args[1].toInt32();
              sslToFd.set(ssl.toString(), fd);
            },
          });
          console.log(`   ✓ SSL_set_fd`);
        }
      } catch {}

      // SSL_read
      try {
        const sslRead = mod.findExportByName("SSL_read");
        if (sslRead) {
          Interceptor.attach(sslRead, {
            onEnter(args) {
              (this as any).ssl = args[0];
              (this as any).buf = args[1];
            },
            onLeave(retval) {
              const ret = retval.toInt32();
              if (ret > 0) {
                const data = (this as any).buf.readByteArray(Math.min(ret, MAX_CAPTURE_BYTES));
                if (data) {
                  const { host, port } = getHostForSSL((this as any).ssl, undefined);
                  const classification = classifyHost(host);
                  
                  const capture: TlsCapture = {
                    t: elapsed(),
                    direction: "recv",
                    host,
                    port,
                    classification,
                    bytes: ret,
                    raw: toAscii(data),
                  };
                  
                  // Try to parse as HTTP response
                  const httpInfo = parseHttpResponse(data);
                  if (httpInfo) {
                    capture.http = httpInfo;
                    const body = extractHttpBody(data);
                    if (body) capture.body = body;
                  }
                  
                  logCapture(capture);
                }
              }
            },
          });
          console.log(`   ✓ SSL_read`);
        }
      } catch {}

      // SSL_write
      try {
        const sslWrite = mod.findExportByName("SSL_write");
        if (sslWrite) {
          Interceptor.attach(sslWrite, {
            onEnter(args) {
              (this as any).ssl = args[0];
              (this as any).buf = args[1];
              (this as any).num = args[2].toInt32();
            },
            onLeave(retval) {
              const ret = retval.toInt32();
              if (ret > 0) {
                const data = (this as any).buf.readByteArray(Math.min(ret, MAX_CAPTURE_BYTES));
                if (data) {
                  const { host, port } = getHostForSSL((this as any).ssl, data);
                  const classification = classifyHost(host);
                  
                  const capture: TlsCapture = {
                    t: elapsed(),
                    direction: "send",
                    host,
                    port,
                    classification,
                    bytes: ret,
                    raw: toAscii(data),
                  };
                  
                  // Try to parse as HTTP request
                  const httpInfo = parseHttpRequest(data);
                  if (httpInfo) {
                    capture.http = httpInfo;
                    const body = extractHttpBody(data);
                    if (body) capture.body = body;
                  }
                  
                  logCapture(capture);
                }
              }
            },
          });
          console.log(`   ✓ SSL_write`);
        }
      } catch {}
      
      break; // Only hook first SSL library
    }
  }
}

// =============================================================================
// SUMMARY & OUTPUT
// =============================================================================

function printSummary(): void {
  console.log("\n\n");
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║               TLS TRAFFIC SUMMARY v2                         ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");

  console.log(`\n📊 Classification breakdown:`);
  console.log(`   Total:     ${stats.total}`);
  console.log(`   Game:      ${stats.game}`);
  console.log(`   Analytics: ${stats.analytics}`);
  console.log(`   Ads:       ${stats.ads} (filtered: ${stats.filtered})`);
  console.log(`   Unknown:   ${stats.unknown}`);

  // Group by host
  const byHost = new Map<string, { send: number; recv: number; count: number; class: HostClass }>();
  for (const cap of captures) {
    const key = cap.host;
    const existing = byHost.get(key) || { send: 0, recv: 0, count: 0, class: cap.classification };
    if (cap.direction === "send") existing.send += cap.bytes;
    else existing.recv += cap.bytes;
    existing.count++;
    byHost.set(key, existing);
  }

  console.log(`\n📊 Traffic by host (logged only):`);
  for (const [host, s] of byHost.entries()) {
    const tag = s.class === "game" ? "🎮" : s.class === "analytics" ? "📊" : "❓";
    console.log(`   ${tag} ${host}: ${s.count} req, ↑${s.send}B ↓${s.recv}B`);
  }

  console.log(`\n📊 Logged captures: ${captures.length}`);
  
  // Print known IP mappings for game hosts
  console.log(`\n📊 Known game host IPs:`);
  for (const [ip, host] of ipToHostname.entries()) {
    const cls = classifyHost(host);
    if (cls === "game" || cls === "analytics") {
      console.log(`   ${ip} → ${host}`);
    }
  }

  // Save JSON output
  if (SAVE_JSON && captures.length > 0) {
    console.log(`\n📁 Saving ${captures.length} captures to JSON...`);
    const jsonLines = captures.map(c => JSON.stringify(c)).join("\n");
    console.log(`\n=== JSON OUTPUT (copy to file) ===`);
    console.log(jsonLines);
    console.log(`=== END JSON OUTPUT ===`);
  }
}

// =============================================================================
// MAIN
// =============================================================================

function main(): void {
  startTime = Date.now();
  hookNetwork();
  
  console.log(`\n${ts()} [CONFIG] FILTER_ADS=${FILTER_ADS}, GAME_ONLY=${GAME_ONLY}, SAVE_JSON=${SAVE_JSON}`);
  console.log(`${ts()} [READY] Capturing for ${DISCOVERY_DURATION_MS / 1000}s...`);
  console.log("═".repeat(66));
  
  setTimeout(() => printSummary(), DISCOVERY_DURATION_MS);
}

setTimeout(() => main(), 500);
