📦
17230 /android/loggers/auth_connection_logger.js
✄
// android/loggers/auth_connection_logger.ts
console.log("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
console.log("\u2551     ARCHERO CONNECTION LOGGER (Android)                      \u2551");
console.log("\u2551     Discover IPs / hostnames / domains + Data Capture        \u2551");
console.log("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");
var DISCOVERY_DURATION_MS = 3e4;
var CAPTURE_DATA = true;
var MAX_CAPTURE_BYTES = 512;
var LOG_HEX_DUMP = true;
var startTime = 0;
function elapsed() {
  return startTime > 0 ? (Date.now() - startTime) / 1e3 : 0;
}
function ts() {
  return `[${elapsed().toFixed(2)}s]`;
}
var dnsLookups = [];
var connections = [];
var dataCaptures = [];
var socketInfo = /* @__PURE__ */ new Map();
var ipToHostname = /* @__PURE__ */ new Map();
function readIpv4(ptr) {
  try {
    const b0 = ptr.readU8();
    const b1 = ptr.add(1).readU8();
    const b2 = ptr.add(2).readU8();
    const b3 = ptr.add(3).readU8();
    return `${b0}.${b1}.${b2}.${b3}`;
  } catch {
    return "<error>";
  }
}
function toHex(buffer, maxBytes = MAX_CAPTURE_BYTES) {
  const bytes = new Uint8Array(buffer);
  const length = Math.min(bytes.length, maxBytes);
  let out = "";
  for (let i = 0; i < length; i++) {
    out += bytes[i].toString(16).padStart(2, "0") + " ";
    if ((i + 1) % 16 === 0)
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
function formatSocketLabel(fd) {
  const info = socketInfo.get(fd);
  if (info) {
    const hostname = ipToHostname.get(info.ip);
    if (hostname) {
      return `${hostname} (${info.ip}:${info.port})`;
    }
    return `${info.ip}:${info.port}`;
  }
  return `fd=${fd}`;
}
function installHooks() {
  startTime = Date.now();
  console.log(`
${ts()} [HOOKS] Installing connection + data capture hooks...
`);
  console.log(`   Data capture: ${CAPTURE_DATA ? "ENABLED" : "DISABLED"}`);
  console.log(`   Max capture bytes: ${MAX_CAPTURE_BYTES}
`);
  const libc = Process.getModuleByName("libc.so");
  console.log(`   libc.so base: ${libc.base}`);
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
              dnsLookups.push({ t: elapsed(), hostname });
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
              this.port = (portBE & 255) << 8 | portBE >> 8 & 255;
              this.ip = readIpv4(sockaddr.add(4));
              this.fd = args[0].toInt32();
            }
          } catch {
            this.ip = null;
          }
        },
        onLeave() {
          try {
            const ip = this.ip;
            const port = this.port;
            const fd = this.fd;
            if (ip && port > 0) {
              connections.push({ t: elapsed(), ip, port, fd });
              socketInfo.set(fd, { ip, port, bytesIn: 0, bytesOut: 0 });
              const hostname = ipToHostname.get(ip) || "";
              console.log(`${ts()} [TCP] \u{1F50C} connect(fd=${fd}) \u2192 ${ip}:${port}${hostname ? ` (${hostname})` : ""}`);
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
  if (CAPTURE_DATA) {
    try {
      const ptr = libc.findExportByName("send");
      if (ptr) {
        Interceptor.attach(ptr, {
          onEnter(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.len = args[2].toInt32();
          },
          onLeave(retval) {
            try {
              const fd = this.fd;
              const buf = this.buf;
              const len = this.len;
              const sent = retval.toInt32();
              if (sent > 0) {
                const info = socketInfo.get(fd);
                if (info) {
                  info.bytesOut += sent;
                  const captureLen = Math.min(sent, MAX_CAPTURE_BYTES);
                  const data = buf.readByteArray(captureLen);
                  if (data) {
                    const hex = toHex(data);
                    const ascii = toAscii(data);
                    dataCaptures.push({
                      t: elapsed(),
                      fd,
                      dir: "send",
                      bytes: sent,
                      preview: ascii,
                      hex
                    });
                    console.log(`${ts()} [SEND] \u2191 ${formatSocketLabel(fd)} (${sent}B)`);
                    if (LOG_HEX_DUMP) {
                      console.log(`                    ${hex}`);
                      console.log(`                    ASCII: "${ascii.substring(0, 80)}${ascii.length > 80 ? "..." : ""}"`);
                    }
                  }
                }
              }
            } catch {
            }
          }
        });
        console.log("   \u2713 send()");
      }
    } catch (e) {
      console.log(`   \u2717 send failed: ${e}`);
    }
    try {
      const ptr = libc.findExportByName("recv");
      if (ptr) {
        Interceptor.attach(ptr, {
          onEnter(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
          },
          onLeave(retval) {
            try {
              const fd = this.fd;
              const buf = this.buf;
              const received = retval.toInt32();
              if (received > 0) {
                const info = socketInfo.get(fd);
                if (info) {
                  info.bytesIn += received;
                  const captureLen = Math.min(received, MAX_CAPTURE_BYTES);
                  const data = buf.readByteArray(captureLen);
                  if (data) {
                    const hex = toHex(data);
                    const ascii = toAscii(data);
                    dataCaptures.push({
                      t: elapsed(),
                      fd,
                      dir: "recv",
                      bytes: received,
                      preview: ascii,
                      hex
                    });
                    console.log(`${ts()} [RECV] \u2193 ${formatSocketLabel(fd)} (${received}B)`);
                    if (LOG_HEX_DUMP) {
                      console.log(`                    ${hex}`);
                      console.log(`                    ASCII: "${ascii.substring(0, 80)}${ascii.length > 80 ? "..." : ""}"`);
                    }
                  }
                }
              }
            } catch {
            }
          }
        });
        console.log("   \u2713 recv()");
      }
    } catch (e) {
      console.log(`   \u2717 recv failed: ${e}`);
    }
    try {
      const ptr = libc.findExportByName("write");
      if (ptr) {
        Interceptor.attach(ptr, {
          onEnter(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.len = args[2].toInt32();
          },
          onLeave(retval) {
            try {
              const fd = this.fd;
              const buf = this.buf;
              const written = retval.toInt32();
              if (written > 0 && socketInfo.has(fd)) {
                const info = socketInfo.get(fd);
                info.bytesOut += written;
                const captureLen = Math.min(written, MAX_CAPTURE_BYTES);
                const data = buf.readByteArray(captureLen);
                if (data) {
                  const hex = toHex(data);
                  const ascii = toAscii(data);
                  dataCaptures.push({
                    t: elapsed(),
                    fd,
                    dir: "send",
                    bytes: written,
                    preview: ascii,
                    hex
                  });
                  console.log(`${ts()} [WRITE] \u2191 ${formatSocketLabel(fd)} (${written}B)`);
                  if (LOG_HEX_DUMP) {
                    console.log(`                    ${hex}`);
                    console.log(`                    ASCII: "${ascii.substring(0, 80)}${ascii.length > 80 ? "..." : ""}"`);
                  }
                }
              }
            } catch {
            }
          }
        });
        console.log("   \u2713 write()");
      }
    } catch (e) {
      console.log(`   \u2717 write failed: ${e}`);
    }
    try {
      const ptr = libc.findExportByName("read");
      if (ptr) {
        Interceptor.attach(ptr, {
          onEnter(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
          },
          onLeave(retval) {
            try {
              const fd = this.fd;
              const buf = this.buf;
              const readBytes = retval.toInt32();
              if (readBytes > 0 && socketInfo.has(fd)) {
                const info = socketInfo.get(fd);
                info.bytesIn += readBytes;
                const captureLen = Math.min(readBytes, MAX_CAPTURE_BYTES);
                const data = buf.readByteArray(captureLen);
                if (data) {
                  const hex = toHex(data);
                  const ascii = toAscii(data);
                  dataCaptures.push({
                    t: elapsed(),
                    fd,
                    dir: "recv",
                    bytes: readBytes,
                    preview: ascii,
                    hex
                  });
                  console.log(`${ts()} [READ] \u2193 ${formatSocketLabel(fd)} (${readBytes}B)`);
                  if (LOG_HEX_DUMP) {
                    console.log(`                    ${hex}`);
                    console.log(`                    ASCII: "${ascii.substring(0, 80)}${ascii.length > 80 ? "..." : ""}"`);
                  }
                }
              }
            } catch {
            }
          }
        });
        console.log("   \u2713 read()");
      }
    } catch (e) {
      console.log(`   \u2717 read failed: ${e}`);
    }
    try {
      const ptr = libc.findExportByName("close");
      if (ptr) {
        Interceptor.attach(ptr, {
          onEnter(args) {
            this.fd = args[0].toInt32();
          },
          onLeave() {
            const fd = this.fd;
            if (socketInfo.has(fd)) {
              const info = socketInfo.get(fd);
              console.log(`${ts()} [CLOSE] \u2716 ${formatSocketLabel(fd)} [in=${info.bytesIn}B, out=${info.bytesOut}B]`);
              socketInfo.delete(fd);
            }
          }
        });
        console.log("   \u2713 close()");
      }
    } catch (e) {
    }
  }
  console.log(`
${ts()} [READY] Capturing for ${DISCOVERY_DURATION_MS / 1e3}s...`);
  console.log("\u2550".repeat(66));
  setTimeout(() => printSummary(), DISCOVERY_DURATION_MS);
}
function printSummary() {
  console.log("\n\n");
  console.log("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
  console.log("\u2551               CONNECTION + DATA CAPTURE SUMMARY              \u2551");
  console.log("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");
  console.log(`
\u{1F4CA} Session Statistics:`);
  console.log(`   Duration: ${elapsed().toFixed(1)}s`);
  console.log(`   DNS lookups: ${dnsLookups.length}`);
  console.log(`   TCP connections: ${connections.length}`);
  console.log(`   Data captures: ${dataCaptures.length}`);
  const totalBytesIn = dataCaptures.filter((d) => d.dir === "recv").reduce((sum, d) => sum + d.bytes, 0);
  const totalBytesOut = dataCaptures.filter((d) => d.dir === "send").reduce((sum, d) => sum + d.bytes, 0);
  console.log(`   Total bytes sent: ${totalBytesOut}`);
  console.log(`   Total bytes received: ${totalBytesIn}`);
  const uniqueHostnames = [...new Set(dnsLookups.map((d) => d.hostname))];
  console.log(`
\u{1F50D} DNS Lookups (${uniqueHostnames.length} unique hostnames):`);
  console.log("\u2500".repeat(66));
  for (const hostname of uniqueHostnames.sort()) {
    console.log(`   \u2713 ${hostname}`);
  }
  const uniqueIps = [...new Set(connections.map((c) => c.ip))];
  console.log(`
\u{1F50C} TCP Connections (${uniqueIps.length} unique IPs):`);
  console.log("\u2500".repeat(66));
  for (const ip of uniqueIps.sort()) {
    const conns = connections.filter((c) => c.ip === ip);
    const ports = [...new Set(conns.map((c) => c.port))].sort((a, b) => a - b);
    const fds = conns.map((c) => c.fd);
    const captures = dataCaptures.filter((d) => fds.includes(d.fd));
    const bytesIn = captures.filter((d) => d.dir === "recv").reduce((sum, d) => sum + d.bytes, 0);
    const bytesOut = captures.filter((d) => d.dir === "send").reduce((sum, d) => sum + d.bytes, 0);
    const hostname = ipToHostname.get(ip) || "";
    console.log(`   ${ip}${hostname ? ` (${hostname})` : ""}`);
    console.log(`      Ports: ${ports.join(", ")}`);
    console.log(`      Traffic: \u2191${bytesOut}B \u2193${bytesIn}B`);
  }
  console.log(`
\u{1F4E1} Data by Port:`);
  console.log("\u2500".repeat(66));
  const portData = /* @__PURE__ */ new Map();
  for (const cap of dataCaptures) {
    const conn = connections.find((c) => c.fd === cap.fd);
    if (conn) {
      if (!portData.has(conn.port)) {
        portData.set(conn.port, { bytesIn: 0, bytesOut: 0, count: 0 });
      }
      const pd = portData.get(conn.port);
      pd.count++;
      if (cap.dir === "recv")
        pd.bytesIn += cap.bytes;
      else
        pd.bytesOut += cap.bytes;
    }
  }
  for (const [port, data] of [...portData.entries()].sort((a, b) => a[0] - b[0])) {
    console.log(`   Port ${port}: ${data.count} captures, \u2191${data.bytesOut}B \u2193${data.bytesIn}B`);
  }
  console.log(`
\u{1F4E6} Sample Data Captures (first 20):`);
  console.log("\u2500".repeat(66));
  for (const cap of dataCaptures.slice(0, 20)) {
    const conn = connections.find((c) => c.fd === cap.fd);
    const label = conn ? `${conn.ip}:${conn.port}` : `fd=${cap.fd}`;
    const arrow = cap.dir === "send" ? "\u2191" : "\u2193";
    console.log(`   [${cap.t.toFixed(2)}s] ${arrow} ${label} (${cap.bytes}B)`);
    console.log(`      "${cap.preview.substring(0, 60)}${cap.preview.length > 60 ? "..." : ""}"`);
  }
  if (dataCaptures.length > 20) {
    console.log(`   ... and ${dataCaptures.length - 20} more captures`);
  }
  console.log(`
\u{1F4CB} JSON Summary:`);
  console.log("\u2500".repeat(66));
  const summary = {
    session: {
      duration: elapsed(),
      dnsLookups: dnsLookups.length,
      tcpConnections: connections.length,
      dataCaptures: dataCaptures.length,
      totalBytesIn,
      totalBytesOut
    },
    hostnames: uniqueHostnames.sort(),
    ips: uniqueIps.sort(),
    portData: Object.fromEntries(portData)
  };
  console.log(JSON.stringify(summary, null, 2));
  console.log("\n" + "\u2550".repeat(66));
}
setTimeout(() => {
  installHooks();
}, 100);
