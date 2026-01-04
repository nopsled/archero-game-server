/**
 * TLS Traffic Logger - Android
 * Captures plaintext HTTPS traffic with domain correlation
 * 
 * Domain resolution strategy:
 * 1. SSL_get_fd -> fd -> IP -> hostname from getaddrinfo cache
 * 2. Parse HTTP Host header from request content
 * 3. Track SSL* -> hostname from SSL_set_tlsext_host_name (SNI)
 */

/// <reference path="../../frida.d.ts" />

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║     ARCHERO TLS TRAFFIC LOGGER                               ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

const DISCOVERY_DURATION_MS = 90000;
const MAX_CAPTURE_BYTES = 2048;

let startTime = 0;
function elapsed(): number {
  return startTime > 0 ? (Date.now() - startTime) / 1000 : 0;
}
function ts(): string {
  return `[${elapsed().toFixed(2)}s]`;
}

// ===== MAPPING TABLES =====
// Map fd -> IP:port from connect()
const fdToAddr = new Map<number, { ip: string; port: number }>();
// Map IP -> hostname from getaddrinfo
const ipToHostname = new Map<string, string>();
// Map SSL* -> fd from SSL_set_fd
const sslToFd = new Map<string, number>();
// Map SSL* -> hostname from SNI or first HTTP request
const sslToHostname = new Map<string, string>();
// Track hostname -> IPs from getaddrinfo results
const hostnameToIPs = new Map<string, string[]>();

// Native function pointers
let SSL_get_fd: NativeFunction<number, [NativePointer]> | null = null;

interface TlsCapture {
  t: number;
  direction: "send" | "recv";
  host: string;
  port: number;
  bytes: number;
  ascii: string;
}

const captures: TlsCapture[] = [];

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

// Extract Host header from HTTP request data
function extractHostHeader(data: ArrayBuffer): string | null {
  try {
    const bytes = new Uint8Array(data);
    // Only check first 1KB for headers
    const maxLen = Math.min(bytes.length, 1024);
    let str = "";
    for (let i = 0; i < maxLen; i++) {
      str += String.fromCharCode(bytes[i]);
    }
    // Look for Host: header (case insensitive)
    const match = str.match(/\r\nHost:\s*([^\r\n]+)/i);
    if (match) {
      // Remove port if present
      return match[1].split(":")[0].trim();
    }
  } catch { }
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

  // 1. Check if we already cached hostname for this SSL*
  const cachedHost = sslToHostname.get(sslKey);
  if (cachedHost) {
    // Get port from fd mapping
    const cachedFd = sslToFd.get(sslKey);
    if (cachedFd !== undefined) {
      const addr = fdToAddr.get(cachedFd);
      return { host: cachedHost, port: addr?.port || 443 };
    }
    return { host: cachedHost, port: 443 };
  }

  // 2. Try to get fd via SSL_get_fd
  let fd = -1;
  if (SSL_get_fd) {
    try {
      fd = SSL_get_fd(ssl);
      if (fd >= 0) {
        sslToFd.set(sslKey, fd);
      }
    } catch { }
  }

  // 3. Try extracting Host header from HTTP data
  if (dataForHostExtract) {
    const hostFromHeader = extractHostHeader(dataForHostExtract);
    if (hostFromHeader) {
      sslToHostname.set(sslKey, hostFromHeader);
      // Also try to update IP mapping if we have the fd
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

  // 4. Fall back to fd -> IP -> hostname chain
  if (fd >= 0) {
    return getHostForFd(fd);
  }

  return { host: "unknown", port: 443 };
}

// =============================================================================
// HOOKS
// =============================================================================

function hookNetwork(): void {
  console.log(`\n${ts()} [HOOKS] Installing hooks...`);
  const libc = Process.getModuleByName("libc.so");

  // getaddrinfo - map hostname -> IPs and IP -> hostname
  try {
    const ptr = libc.findExportByName("getaddrinfo");
    if (ptr) {
      Interceptor.attach(ptr, {
        onEnter(args) {
          try {
            (this as any).hostname = args[0].readUtf8String();
            (this as any).result = args[3];  // struct addrinfo **res
          } catch {
            (this as any).hostname = null;
          }
        },
        onLeave(retval) {
          try {
            const hostname = (this as any).hostname;
            const resultPtr = (this as any).result;
            if (hostname && retval.toInt32() === 0 && resultPtr) {
              // Parse result list to get all resolved IPs
              let ai = resultPtr.readPointer();
              const ips: string[] = [];
              while (!ai.isNull()) {
                const family = ai.add(4).readInt();  // ai_family
                if (family === 2) {  // AF_INET
                  const addr = ai.add(Process.pointerSize === 8 ? 24 : 16).readPointer();
                  if (!addr.isNull()) {
                    // Skip first 2 bytes (address family), then 2 bytes port, then 4 bytes IP
                    const ip = `${addr.add(4).readU8()}.${addr.add(5).readU8()}.${addr.add(6).readU8()}.${addr.add(7).readU8()}`;
                    ips.push(ip);
                    if (!ipToHostname.has(ip)) {
                      ipToHostname.set(ip, hostname);
                    }
                  }
                }
                // Move to next result
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
  } catch { }

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
              // AF_INET
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
  } catch { }

  // Find SSL module and hook
  const modules = Process.enumerateModules();
  for (const mod of modules) {
    if (mod.name.toLowerCase().includes("ssl")) {
      // Get SSL_get_fd for resolving hostname
      try {
        const getFdPtr = mod.findExportByName("SSL_get_fd");
        if (getFdPtr) {
          SSL_get_fd = new NativeFunction(getFdPtr, "int", ["pointer"]);
          console.log(`   ✓ SSL_get_fd`);
        }
      } catch { }

      // SSL_set_fd - track SSL* -> fd mapping
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
      } catch { }

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
                  // For recv, try to extract host from response cookies/headers if needed
                  const { host, port } = getHostForSSL((this as any).ssl, undefined);
                  const ascii = toAscii(data);
                  console.log(`\n${ts()} [RECV] ← ${host}:${port} (${ret}B)`);
                  console.log(`   ${ascii.substring(0, 400)}${ascii.length > 400 ? "..." : ""}`);
                  captures.push({ t: elapsed(), direction: "recv", host, port, bytes: ret, ascii });
                }
              }
            },
          });
          console.log(`   ✓ SSL_read`);
        }
      } catch { }

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
                  // For send, extract Host header from HTTP request
                  const { host, port } = getHostForSSL((this as any).ssl, data);
                  const ascii = toAscii(data);
                  console.log(`\n${ts()} [SEND] → ${host}:${port} (${ret}B)`);
                  console.log(`   ${ascii.substring(0, 400)}${ascii.length > 400 ? "..." : ""}`);
                  captures.push({ t: elapsed(), direction: "send", host, port, bytes: ret, ascii });
                }
              }
            },
          });
          console.log(`   ✓ SSL_write`);
        }
      } catch { }
      break; // Only hook first SSL library
    }
  }
}

function printSummary(): void {
  console.log("\n\n");
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║               TLS TRAFFIC SUMMARY                            ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");

  const byHost = new Map<string, { send: number; recv: number; count: number }>();
  for (const cap of captures) {
    const key = cap.host;
    const stats = byHost.get(key) || { send: 0, recv: 0, count: 0 };
    if (cap.direction === "send") stats.send += cap.bytes;
    else stats.recv += cap.bytes;
    stats.count++;
    byHost.set(key, stats);
  }

  console.log(`\n📊 Traffic by host:`);
  for (const [host, stats] of byHost.entries()) {
    console.log(`   ${host}: ${stats.count} requests, ↑${stats.send}B ↓${stats.recv}B`);
  }

  console.log(`\n📊 Total: ${captures.length} captures`);
  console.log(`\n📊 Known IP → hostname mappings:`);
  for (const [ip, host] of ipToHostname.entries()) {
    console.log(`   ${ip} → ${host}`);
  }
  console.log(`\n📊 Active SSL connections: ${sslToHostname.size}`);
}

function main(): void {
  startTime = Date.now();
  hookNetwork();
  console.log(`\n${ts()} [READY] Capturing for ${DISCOVERY_DURATION_MS / 1000}s...`);
  console.log("═".repeat(66));
  setTimeout(() => printSummary(), DISCOVERY_DURATION_MS);
}

setTimeout(() => main(), 500);
