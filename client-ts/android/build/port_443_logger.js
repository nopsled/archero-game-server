📦
14225 /android/loggers/port_443_logger.js
✄
// android/loggers/port_443_logger.ts
console.log("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
console.log("\u2551     ARCHERO TLS TRAFFIC LOGGER (Android)                     \u2551");
console.log("\u2551     Intercepts plaintext before/after TLS encryption         \u2551");
console.log("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");
var DISCOVERY_DURATION_MS = 6e4;
var MAX_CAPTURE_BYTES = 2048;
var LOG_HEX_DUMP = true;
var LOG_ASCII = true;
var startTime = 0;
function elapsed() {
  return startTime > 0 ? (Date.now() - startTime) / 1e3 : 0;
}
function ts() {
  return `[${elapsed().toFixed(2)}s]`;
}
var tlsCaptures = [];
var connections = [];
var dnsLookups = /* @__PURE__ */ new Map();
function toHex(buffer, maxBytes = MAX_CAPTURE_BYTES) {
  const bytes = new Uint8Array(buffer);
  const length = Math.min(bytes.length, maxBytes);
  let out = "";
  for (let i = 0; i < length; i++) {
    out += bytes[i].toString(16).padStart(2, "0") + " ";
    if ((i + 1) % 32 === 0)
      out += "\n                    ";
  }
  if (bytes.length > maxBytes)
    out += `...(+${bytes.length - maxBytes}B)`;
  return out.trim();
}
function toAscii(buffer, maxBytes = MAX_CAPTURE_BYTES) {
  const bytes = new Uint8Array(buffer);
  const length = Math.min(bytes.length, maxBytes);
  let out = "";
  for (let i = 0; i < length; i++) {
    const b = bytes[i];
    out += b >= 32 && b <= 126 ? String.fromCharCode(b) : ".";
  }
  if (bytes.length > maxBytes)
    out += `...(+${bytes.length - maxBytes}B)`;
  return out;
}
function readIl2CppByteArray(arrayPtr, offset, len) {
  try {
    if (arrayPtr.isNull())
      return null;
    const is64Bit = Process.pointerSize === 8;
    const dataOffset = is64Bit ? 32 : 16;
    const dataPtr = arrayPtr.add(dataOffset).add(offset);
    return dataPtr.readByteArray(len);
  } catch (e) {
    return null;
  }
}
function hookNativeNetwork() {
  console.log(`
${ts()} [HOOKS] Installing native network hooks...`);
  const libc = Process.getModuleByName("libc.so");
  try {
    const ptr = libc.findExportByName("getaddrinfo");
    if (ptr) {
      Interceptor.attach(ptr, {
        onEnter(args) {
          try {
            this.hostname = args[0].readUtf8String();
          } catch {
            this.hostname = null;
          }
        },
        onLeave(retval) {
          try {
            const hostname = this.hostname;
            if (hostname && retval.toInt32() === 0) {
              dnsLookups.set(hostname, elapsed());
              console.log(`${ts()} [DNS] \u{1F50D} ${hostname}`);
            }
          } catch {
          }
        }
      });
      console.log("   \u2713 getaddrinfo()");
    }
  } catch (e) {
    console.log(`   \u2717 getaddrinfo failed: ${e}`);
  }
  try {
    const ptr = libc.findExportByName("connect");
    if (ptr) {
      Interceptor.attach(ptr, {
        onEnter(args) {
          try {
            const sockaddr = args[1];
            const family = sockaddr.readU16();
            if (family === 2) {
              const portBE = sockaddr.add(2).readU16();
              const port = (portBE & 255) << 8 | portBE >> 8 & 255;
              const ip = sockaddr.add(4).readU8() + "." + sockaddr.add(5).readU8() + "." + sockaddr.add(6).readU8() + "." + sockaddr.add(7).readU8();
              if (port === 443) {
                console.log(`${ts()} [TCP] \u{1F50C} connect \u2192 ${ip}:${port}`);
                connections.push({ t: elapsed(), ip, port });
              }
            }
          } catch {
          }
        }
      });
      console.log("   \u2713 connect()");
    }
  } catch (e) {
    console.log(`   \u2717 connect failed: ${e}`);
  }
}
function hookTlsNative() {
  console.log(`
${ts()} [HOOKS] Installing native TLS hooks (BouncyCastle)...`);
  const libil2cpp = Process.getModuleByName("libil2cpp.so");
  console.log(`   libil2cpp.so base: ${libil2cpp.base}`);
  const hookPoints = [
    // BouncyCastle (Org.BouncyCastle.Crypto.Tls.TlsProtocol)
    { name: "TlsProtocol.WriteData", offset: 84792364, direction: "write" },
    { name: "TlsProtocol.ReadApplicationData", offset: 84790408, direction: "read" },
    // BestHTTP SecureProtocol version
    {
      name: "BestHTTP.TlsProtocol.WriteData",
      offset: 100720548,
      direction: "write"
    },
    {
      name: "BestHTTP.TlsProtocol.ReadApplicationData",
      offset: 100716108,
      direction: "read"
    }
  ];
  for (const hook of hookPoints) {
    try {
      const addr = libil2cpp.base.add(hook.offset);
      Interceptor.attach(addr, {
        onEnter(args) {
          this.buf = args[1];
          this.offset = args[2].toInt32();
          this.len = args[3].toInt32();
          this.direction = hook.direction;
          this.name = hook.name;
        },
        onLeave(retval) {
          try {
            const buf = this.buf;
            const offset = this.offset;
            let len = this.len;
            const direction = this.direction;
            const name = this.name;
            if (direction === "read") {
              const actualRead = retval.toInt32();
              if (actualRead > 0) {
                len = actualRead;
              } else {
                return;
              }
            }
            if (len <= 0)
              return;
            const data = readIl2CppByteArray(buf, offset, Math.min(len, MAX_CAPTURE_BYTES));
            if (!data)
              return;
            const hex = toHex(data);
            const ascii = toAscii(data);
            const arrow = direction === "write" ? "\u2191 SEND" : "\u2193 RECV";
            console.log(`
${ts()} [TLS] ${arrow} (${len}B) via ${name}`);
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
              hex: hex.substring(0, 500)
            });
          } catch (e) {
          }
        }
      });
      console.log(`   \u2713 ${hook.name} @ ${addr}`);
    } catch (e) {
      console.log(`   \u2717 ${hook.name} failed: ${e}`);
    }
  }
  const streamHooks = [
    { name: "TlsStream.Write (BC)", offset: 84845464, direction: "write" },
    { name: "TlsStream.Read (BC)", offset: 84845164, direction: "read" },
    { name: "TlsStream.Write (BestHTTP)", offset: 100778168, direction: "write" }
  ];
  for (const hook of streamHooks) {
    try {
      const addr = libil2cpp.base.add(hook.offset);
      Interceptor.attach(addr, {
        onEnter(args) {
          this.buf = args[1];
          this.offset = args[2].toInt32();
          this.len = args[3].toInt32();
          this.direction = hook.direction;
          this.name = hook.name;
        },
        onLeave(retval) {
          try {
            const buf = this.buf;
            const offset = this.offset;
            let len = this.len;
            const direction = this.direction;
            const name = this.name;
            if (direction === "read") {
              const actualRead = retval.toInt32();
              if (actualRead > 0) {
                len = actualRead;
              } else {
                return;
              }
            }
            if (len <= 0 || len > 1e5)
              return;
            const data = readIl2CppByteArray(buf, offset, Math.min(len, MAX_CAPTURE_BYTES));
            if (!data)
              return;
            const ascii = toAscii(data);
            const arrow = direction === "write" ? "\u2191" : "\u2193";
            console.log(`${ts()} [TLS-STREAM] ${arrow} ${name} (${len}B)`);
          } catch {
          }
        }
      });
      console.log(`   \u2713 ${hook.name} @ ${addr}`);
    } catch (e) {
      console.log(`   \u2717 ${hook.name} failed: ${e}`);
    }
  }
}
function hookSslStream() {
  console.log(`
${ts()} [HOOKS] Installing SslStream hooks...`);
  const libil2cpp = Process.getModuleByName("libil2cpp.so");
  const sslStreamHooks = [
    { name: "SslStream.Write", offset: 134147196, direction: "write" },
    { name: "SslStream.Read", offset: 134147112, direction: "read" }
  ];
  for (const hook of sslStreamHooks) {
    try {
      const addr = libil2cpp.base.add(hook.offset);
      Interceptor.attach(addr, {
        onEnter(args) {
          this.buf = args[1];
          this.offset = args[2].toInt32();
          this.len = args[3].toInt32();
          this.direction = hook.direction;
          this.name = hook.name;
        },
        onLeave(retval) {
          try {
            const buf = this.buf;
            const offset = this.offset;
            let len = this.len;
            const direction = this.direction;
            const name = this.name;
            if (direction === "read") {
              const actualRead = retval.toInt32();
              if (actualRead > 0) {
                len = actualRead;
              } else {
                return;
              }
            }
            if (len <= 0 || len > 1e5)
              return;
            const data = readIl2CppByteArray(buf, offset, Math.min(len, MAX_CAPTURE_BYTES));
            if (!data)
              return;
            const hex = toHex(data);
            const ascii = toAscii(data);
            const arrow = direction === "write" ? "\u2191 SEND" : "\u2193 RECV";
            console.log(`
${ts()} [SSL] ${arrow} (${len}B) via ${name}`);
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
              hex: hex.substring(0, 500)
            });
          } catch {
          }
        }
      });
      console.log(`   \u2713 ${hook.name} @ ${addr}`);
    } catch (e) {
      console.log(`   \u2717 ${hook.name} failed: ${e}`);
    }
  }
}
function printSummary() {
  console.log("\n\n");
  console.log("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
  console.log("\u2551               TLS TRAFFIC CAPTURE SUMMARY                    \u2551");
  console.log("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");
  console.log(`
\u{1F4CA} Session Statistics:`);
  console.log(`   Duration: ${elapsed().toFixed(1)}s`);
  console.log(`   DNS lookups: ${dnsLookups.size}`);
  console.log(`   TCP connections (443): ${connections.length}`);
  console.log(`   TLS captures: ${tlsCaptures.length}`);
  const totalSent = tlsCaptures.filter((c) => c.direction === "write").reduce((sum, c) => sum + c.bytes, 0);
  const totalRecv = tlsCaptures.filter((c) => c.direction === "read").reduce((sum, c) => sum + c.bytes, 0);
  console.log(`   Total plaintext sent: ${totalSent} bytes`);
  console.log(`   Total plaintext received: ${totalRecv} bytes`);
  console.log(`
\u{1F50D} DNS Lookups:`);
  console.log("\u2500".repeat(66));
  for (const [hostname, t] of dnsLookups.entries()) {
    console.log(`   [${t.toFixed(2)}s] ${hostname}`);
  }
  console.log(`
\u{1F50C} TLS Connections (port 443):`);
  console.log("\u2500".repeat(66));
  for (const conn of connections) {
    console.log(`   [${conn.t.toFixed(2)}s] ${conn.ip}:${conn.port}`);
  }
  console.log(`
\u{1F4E6} Sample TLS Captures (first 30):`);
  console.log("\u2500".repeat(66));
  for (const cap of tlsCaptures.slice(0, 30)) {
    const arrow = cap.direction === "write" ? "\u2191" : "\u2193";
    console.log(`   [${cap.t.toFixed(2)}s] ${arrow} ${cap.bytes}B`);
    console.log(`      "${cap.preview.substring(0, 80)}${cap.preview.length > 80 ? "..." : ""}"`);
  }
  if (tlsCaptures.length > 30) {
    console.log(`   ... and ${tlsCaptures.length - 30} more captures`);
  }
  console.log(`
\u{1F4CB} JSON Summary:`);
  console.log("\u2500".repeat(66));
  const summary = {
    session: {
      duration: elapsed(),
      dnsLookups: dnsLookups.size,
      connections: connections.length,
      tlsCaptures: tlsCaptures.length,
      totalSent,
      totalRecv
    },
    hostnames: Array.from(dnsLookups.keys()),
    ips: connections.map((c) => c.ip)
  };
  console.log(JSON.stringify(summary, null, 2));
  console.log("\n" + "\u2550".repeat(66));
}
function main() {
  startTime = Date.now();
  hookNativeNetwork();
  hookTlsNative();
  hookSslStream();
  console.log(`
${ts()} [READY] Capturing TLS traffic for ${DISCOVERY_DURATION_MS / 1e3}s...`);
  console.log("\u2550".repeat(66));
  setTimeout(() => printSummary(), DISCOVERY_DURATION_MS);
}
setTimeout(() => {
  main();
}, 500);
