/**
 * TLS Traffic Logger - Android
 *
 * Intercepts PLAINTEXT data before TLS encryption and after decryption
 * by hooking BouncyCastle TlsProtocol.WriteData and ReadApplicationData.
 *
 * Usage:
 *   cd client-ts
 *   bun run build:port443
 *   frida -U -f com.habby.archero -l android/build/port_443_logger.js
 */

/// <reference path="../../frida.d.ts" />

console.log("╔══════════════════════════════════════════════════════════════╗");
console.log("║     ARCHERO TLS TRAFFIC LOGGER (Android)                     ║");
console.log("║     Intercepts plaintext before/after TLS encryption         ║");
console.log("╚══════════════════════════════════════════════════════════════╝");

// =============================================================================
// CONFIGURATION
// =============================================================================

const DISCOVERY_DURATION_MS = 60000; // 60 seconds
const MAX_CAPTURE_BYTES = 2048;
const LOG_HEX_DUMP = true;
const LOG_ASCII = true;

let startTime = 0;

function elapsed(): number {
  return startTime > 0 ? (Date.now() - startTime) / 1000 : 0;
}

function ts(): string {
  return `[${elapsed().toFixed(2)}s]`;
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

interface TlsCapture {
  t: number;
  direction: "write" | "read";
  bytes: number;
  preview: string;
  hex?: string;
}

interface Connection {
  t: number;
  ip: string;
  port: number;
}

const tlsCaptures: TlsCapture[] = [];
const connections: Connection[] = [];
const dnsLookups = new Map<string, number>();

// =============================================================================
// HELPERS
// =============================================================================

function toHex(buffer: ArrayBuffer, maxBytes = MAX_CAPTURE_BYTES): string {
  const bytes = new Uint8Array(buffer);
  const length = Math.min(bytes.length, maxBytes);
  let out = "";
  for (let i = 0; i < length; i++) {
    out += bytes[i].toString(16).padStart(2, "0") + " ";
    if ((i + 1) % 32 === 0) out += "\n                    ";
  }
  if (bytes.length > maxBytes) out += `...(+${bytes.length - maxBytes}B)`;
  return out.trim();
}

function toAscii(buffer: ArrayBuffer, maxBytes = MAX_CAPTURE_BYTES): string {
  const bytes = new Uint8Array(buffer);
  const length = Math.min(bytes.length, maxBytes);
  let out = "";
  for (let i = 0; i < length; i++) {
    const b = bytes[i];
    out += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
  }
  if (bytes.length > maxBytes) out += `...(+${bytes.length - maxBytes}B)`;
  return out;
}

function readIl2CppByteArray(
  arrayPtr: NativePointer,
  offset: number,
  len: number
): ArrayBuffer | null {
  try {
    if (arrayPtr.isNull()) return null;

    // IL2CPP array structure:
    // +0x00: Il2CppObject (klass pointer, monitor)
    // +0x10: bounds (for multi-dim arrays, usually null for 1D)
    // +0x18: max_length (size_t)
    // +0x20: data starts (for 64-bit)
    // For 32-bit it's different offsets

    const is64Bit = Process.pointerSize === 8;
    const dataOffset = is64Bit ? 0x20 : 0x10;

    const dataPtr = arrayPtr.add(dataOffset).add(offset);
    return dataPtr.readByteArray(len);
  } catch (e) {
    return null;
  }
}

// =============================================================================
// NATIVE DNS/CONNECT HOOKS
// =============================================================================

function hookNativeNetwork(): void {
  console.log(`\n${ts()} [HOOKS] Installing native network hooks...`);

  const libc = Process.getModuleByName("libc.so");

  // --- getaddrinfo ---
  try {
    const ptr = libc.findExportByName("getaddrinfo");
    if (ptr) {
      Interceptor.attach(ptr, {
        onEnter(args) {
          try {
            (this as any).hostname = args[0].readUtf8String();
          } catch {
            (this as any).hostname = null;
          }
        },
        onLeave(retval) {
          try {
            const hostname = (this as any).hostname;
            if (hostname && retval.toInt32() === 0) {
              dnsLookups.set(hostname, elapsed());
              console.log(`${ts()} [DNS] 🔍 ${hostname}`);
            }
          } catch {}
        },
      });
      console.log("   ✓ getaddrinfo()");
    }
  } catch (e) {
    console.log(`   ✗ getaddrinfo failed: ${e}`);
  }

  // --- connect ---
  try {
    const ptr = libc.findExportByName("connect");
    if (ptr) {
      Interceptor.attach(ptr, {
        onEnter(args) {
          try {
            const sockaddr = args[1];
            const family = sockaddr.readU16();
            if (family === 2) {
              // AF_INET
              const portBE = sockaddr.add(2).readU16();
              const port = ((portBE & 0xff) << 8) | ((portBE >> 8) & 0xff);
              const ip =
                sockaddr.add(4).readU8() +
                "." +
                sockaddr.add(5).readU8() +
                "." +
                sockaddr.add(6).readU8() +
                "." +
                sockaddr.add(7).readU8();

              if (port === 443) {
                console.log(`${ts()} [TCP] 🔌 connect → ${ip}:${port}`);
                connections.push({ t: elapsed(), ip, port });
              }
            }
          } catch {}
        },
      });
      console.log("   ✓ connect()");
    }
  } catch (e) {
    console.log(`   ✗ connect failed: ${e}`);
  }
}

// =============================================================================
// NATIVE TLS HOOKS (BouncyCastle in libil2cpp.so)
// =============================================================================

function hookTlsNative(): void {
  console.log(`\n${ts()} [HOOKS] Installing native TLS hooks (BouncyCastle)...`);

  const libil2cpp = Process.getModuleByName("libil2cpp.so");
  console.log(`   libil2cpp.so base: ${libil2cpp.base}`);

  // Addresses from IDA analysis:
  // TlsProtocol.WriteData: 0x50dd42c
  // TlsProtocol.ReadApplicationData: 0x50dcc88
  // BestHTTP versions:
  // TlsProtocol.WriteData: 0x600dfa4
  // TlsProtocol.ReadApplicationData: 0x600ce4c

  const hookPoints = [
    // BouncyCastle (Org.BouncyCastle.Crypto.Tls.TlsProtocol)
    { name: "TlsProtocol.WriteData", offset: 0x50dd42c, direction: "write" as const },
    { name: "TlsProtocol.ReadApplicationData", offset: 0x50dcc88, direction: "read" as const },
    // BestHTTP SecureProtocol version
    {
      name: "BestHTTP.TlsProtocol.WriteData",
      offset: 0x600dfa4,
      direction: "write" as const,
    },
    {
      name: "BestHTTP.TlsProtocol.ReadApplicationData",
      offset: 0x600ce4c,
      direction: "read" as const,
    },
  ];

  for (const hook of hookPoints) {
    try {
      const addr = libil2cpp.base.add(hook.offset);

      Interceptor.attach(addr, {
        onEnter(args) {
          // void WriteData(TlsProtocol* this, Byte[] buf, int offset, int len)
          // int ReadApplicationData(TlsProtocol* this, Byte[] buf, int offset, int len)
          (this as any).buf = args[1];
          (this as any).offset = args[2].toInt32();
          (this as any).len = args[3].toInt32();
          (this as any).direction = hook.direction;
          (this as any).name = hook.name;
        },
        onLeave(retval) {
          try {
            const buf = (this as any).buf;
            const offset = (this as any).offset;
            let len = (this as any).len;
            const direction = (this as any).direction;
            const name = (this as any).name;

            // For read, the return value is the actual bytes read
            if (direction === "read") {
              const actualRead = retval.toInt32();
              if (actualRead > 0) {
                len = actualRead;
              } else {
                return; // No data read
              }
            }

            if (len <= 0) return;

            const data = readIl2CppByteArray(buf, offset, Math.min(len, MAX_CAPTURE_BYTES));
            if (!data) return;

            const hex = toHex(data);
            const ascii = toAscii(data);

            const arrow = direction === "write" ? "↑ SEND" : "↓ RECV";
            console.log(`\n${ts()} [TLS] ${arrow} (${len}B) via ${name}`);

            if (LOG_HEX_DUMP) {
              console.log(`        ${hex}`);
            }
            if (LOG_ASCII) {
              const preview = ascii.substring(0, 200);
              console.log(`        ASCII: "${preview}${ascii.length > 200 ? "..." : ""}"`);
            }

            tlsCaptures.push({
              t: elapsed(),
              direction,
              bytes: len,
              preview: ascii.substring(0, 500),
              hex: hex.substring(0, 500),
            });
          } catch (e) {
            // Silently ignore errors
          }
        },
      });

      console.log(`   ✓ ${hook.name} @ ${addr}`);
    } catch (e) {
      console.log(`   ✗ ${hook.name} failed: ${e}`);
    }
  }

  // Also hook TlsStream.Write/Read as alternative entry points
  const streamHooks = [
    { name: "TlsStream.Write (BC)", offset: 0x50ea398, direction: "write" as const },
    { name: "TlsStream.Read (BC)", offset: 0x50ea26c, direction: "read" as const },
    { name: "TlsStream.Write (BestHTTP)", offset: 0x601c0b8, direction: "write" as const },
  ];

  for (const hook of streamHooks) {
    try {
      const addr = libil2cpp.base.add(hook.offset);

      Interceptor.attach(addr, {
        onEnter(args) {
          (this as any).buf = args[1];
          (this as any).offset = args[2].toInt32();
          (this as any).len = args[3].toInt32();
          (this as any).direction = hook.direction;
          (this as any).name = hook.name;
        },
        onLeave(retval) {
          try {
            const buf = (this as any).buf;
            const offset = (this as any).offset;
            let len = (this as any).len;
            const direction = (this as any).direction;
            const name = (this as any).name;

            if (direction === "read") {
              const actualRead = retval.toInt32();
              if (actualRead > 0) {
                len = actualRead;
              } else {
                return;
              }
            }

            if (len <= 0 || len > 100000) return;

            const data = readIl2CppByteArray(buf, offset, Math.min(len, MAX_CAPTURE_BYTES));
            if (!data) return;

            const ascii = toAscii(data);
            const arrow = direction === "write" ? "↑" : "↓";

            // Only log if we haven't seen this in TlsProtocol hooks
            // (to avoid duplicates)
            console.log(`${ts()} [TLS-STREAM] ${arrow} ${name} (${len}B)`);
          } catch {}
        },
      });

      console.log(`   ✓ ${hook.name} @ ${addr}`);
    } catch (e) {
      console.log(`   ✗ ${hook.name} failed: ${e}`);
    }
  }
}

// =============================================================================
// SslStream HOOKS (System.Net.Security)
// =============================================================================

function hookSslStream(): void {
  console.log(`\n${ts()} [HOOKS] Installing SslStream hooks...`);

  const libil2cpp = Process.getModuleByName("libil2cpp.so");

  // System.Net.Security.SslStream
  const sslStreamHooks = [
    { name: "SslStream.Write", offset: 0x7feec7c, direction: "write" as const },
    { name: "SslStream.Read", offset: 0x7feec28, direction: "read" as const },
  ];

  for (const hook of sslStreamHooks) {
    try {
      const addr = libil2cpp.base.add(hook.offset);

      Interceptor.attach(addr, {
        onEnter(args) {
          // void Write(SslStream* this, Byte[] buffer, int offset, int count)
          // int Read(SslStream* this, Byte[] buffer, int offset, int count)
          (this as any).buf = args[1];
          (this as any).offset = args[2].toInt32();
          (this as any).len = args[3].toInt32();
          (this as any).direction = hook.direction;
          (this as any).name = hook.name;
        },
        onLeave(retval) {
          try {
            const buf = (this as any).buf;
            const offset = (this as any).offset;
            let len = (this as any).len;
            const direction = (this as any).direction;
            const name = (this as any).name;

            if (direction === "read") {
              const actualRead = retval.toInt32();
              if (actualRead > 0) {
                len = actualRead;
              } else {
                return;
              }
            }

            if (len <= 0 || len > 100000) return;

            const data = readIl2CppByteArray(buf, offset, Math.min(len, MAX_CAPTURE_BYTES));
            if (!data) return;

            const hex = toHex(data);
            const ascii = toAscii(data);

            const arrow = direction === "write" ? "↑ SEND" : "↓ RECV";
            console.log(`\n${ts()} [SSL] ${arrow} (${len}B) via ${name}`);

            if (LOG_HEX_DUMP) {
              console.log(`        ${hex}`);
            }
            if (LOG_ASCII) {
              const preview = ascii.substring(0, 200);
              console.log(`        ASCII: "${preview}${ascii.length > 200 ? "..." : ""}"`);
            }

            tlsCaptures.push({
              t: elapsed(),
              direction,
              bytes: len,
              preview: ascii.substring(0, 500),
              hex: hex.substring(0, 500),
            });
          } catch {}
        },
      });

      console.log(`   ✓ ${hook.name} @ ${addr}`);
    } catch (e) {
      console.log(`   ✗ ${hook.name} failed: ${e}`);
    }
  }
}

// =============================================================================
// SUMMARY
// =============================================================================

function printSummary(): void {
  console.log("\n\n");
  console.log("╔══════════════════════════════════════════════════════════════╗");
  console.log("║               TLS TRAFFIC CAPTURE SUMMARY                    ║");
  console.log("╚══════════════════════════════════════════════════════════════╝");

  console.log(`\n📊 Session Statistics:`);
  console.log(`   Duration: ${elapsed().toFixed(1)}s`);
  console.log(`   DNS lookups: ${dnsLookups.size}`);
  console.log(`   TCP connections (443): ${connections.length}`);
  console.log(`   TLS captures: ${tlsCaptures.length}`);

  const totalSent = tlsCaptures
    .filter((c) => c.direction === "write")
    .reduce((sum, c) => sum + c.bytes, 0);
  const totalRecv = tlsCaptures
    .filter((c) => c.direction === "read")
    .reduce((sum, c) => sum + c.bytes, 0);

  console.log(`   Total plaintext sent: ${totalSent} bytes`);
  console.log(`   Total plaintext received: ${totalRecv} bytes`);

  // DNS lookups
  console.log(`\n🔍 DNS Lookups:`);
  console.log("─".repeat(66));
  for (const [hostname, t] of dnsLookups.entries()) {
    console.log(`   [${t.toFixed(2)}s] ${hostname}`);
  }

  // Connections
  console.log(`\n🔌 TLS Connections (port 443):`);
  console.log("─".repeat(66));
  for (const conn of connections) {
    console.log(`   [${conn.t.toFixed(2)}s] ${conn.ip}:${conn.port}`);
  }

  // Sample captures
  console.log(`\n📦 Sample TLS Captures (first 30):`);
  console.log("─".repeat(66));
  for (const cap of tlsCaptures.slice(0, 30)) {
    const arrow = cap.direction === "write" ? "↑" : "↓";
    console.log(`   [${cap.t.toFixed(2)}s] ${arrow} ${cap.bytes}B`);
    console.log(`      "${cap.preview.substring(0, 80)}${cap.preview.length > 80 ? "..." : ""}"`);
  }
  if (tlsCaptures.length > 30) {
    console.log(`   ... and ${tlsCaptures.length - 30} more captures`);
  }

  // JSON summary
  console.log(`\n📋 JSON Summary:`);
  console.log("─".repeat(66));
  const summary = {
    session: {
      duration: elapsed(),
      dnsLookups: dnsLookups.size,
      connections: connections.length,
      tlsCaptures: tlsCaptures.length,
      totalSent,
      totalRecv,
    },
    hostnames: Array.from(dnsLookups.keys()),
    ips: connections.map((c) => c.ip),
  };
  console.log(JSON.stringify(summary, null, 2));

  console.log("\n" + "═".repeat(66));
}

// =============================================================================
// MAIN
// =============================================================================

function main(): void {
  startTime = Date.now();

  hookNativeNetwork();
  hookTlsNative();
  hookSslStream();

  console.log(`\n${ts()} [READY] Capturing TLS traffic for ${DISCOVERY_DURATION_MS / 1000}s...`);
  console.log("═".repeat(66));

  setTimeout(() => printSummary(), DISCOVERY_DURATION_MS);
}

// Start after a short delay to let the process initialize
setTimeout(() => {
  main();
}, 500);
