📦
10874 /android/loggers/port_443_logger.js
✄
// android/loggers/port_443_logger.ts
console.log("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
console.log("\u2551     ARCHERO TLS TRAFFIC LOGGER                               \u2551");
console.log("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");
var DISCOVERY_DURATION_MS = 9e4;
var MAX_CAPTURE_BYTES = 2048;
var startTime = 0;
function elapsed() {
  return startTime > 0 ? (Date.now() - startTime) / 1e3 : 0;
}
function ts() {
  return `[${elapsed().toFixed(2)}s]`;
}
var fdToAddr = /* @__PURE__ */ new Map();
var ipToHostname = /* @__PURE__ */ new Map();
var sslToFd = /* @__PURE__ */ new Map();
var sslToHostname = /* @__PURE__ */ new Map();
var hostnameToIPs = /* @__PURE__ */ new Map();
var SSL_get_fd = null;
var captures = [];
function toAscii(buffer, maxBytes = MAX_CAPTURE_BYTES) {
  const bytes = new Uint8Array(buffer);
  const length = Math.min(bytes.length, maxBytes);
  let out = "";
  for (let i = 0; i < length; i++) {
    const b = bytes[i];
    if (b === 13)
      out += "\\r";
    else if (b === 10)
      out += "\\n";
    else if (b >= 32 && b <= 126)
      out += String.fromCharCode(b);
    else
      out += ".";
  }
  return out;
}
function extractHostHeader(data) {
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
  } catch {
  }
  return null;
}
function getHostForFd(fd) {
  const addr = fdToAddr.get(fd);
  if (addr) {
    const hostname = ipToHostname.get(addr.ip) || addr.ip;
    return { host: hostname, port: addr.port };
  }
  return { host: "unknown", port: 443 };
}
function getHostForSSL(ssl, dataForHostExtract) {
  const sslKey = ssl.toString();
  const cachedHost = sslToHostname.get(sslKey);
  if (cachedHost) {
    const cachedFd = sslToFd.get(sslKey);
    if (cachedFd !== void 0) {
      const addr = fdToAddr.get(cachedFd);
      return { host: cachedHost, port: addr?.port || 443 };
    }
    return { host: cachedHost, port: 443 };
  }
  let fd = -1;
  if (SSL_get_fd) {
    try {
      fd = SSL_get_fd(ssl);
      if (fd >= 0) {
        sslToFd.set(sslKey, fd);
      }
    } catch {
    }
  }
  if (dataForHostExtract) {
    const hostFromHeader = extractHostHeader(dataForHostExtract);
    if (hostFromHeader) {
      sslToHostname.set(sslKey, hostFromHeader);
      if (fd >= 0) {
        const addr2 = fdToAddr.get(fd);
        if (addr2 && !ipToHostname.has(addr2.ip)) {
          ipToHostname.set(addr2.ip, hostFromHeader);
        }
      }
      const addr = fd >= 0 ? fdToAddr.get(fd) : void 0;
      return { host: hostFromHeader, port: addr?.port || 443 };
    }
  }
  if (fd >= 0) {
    return getHostForFd(fd);
  }
  return { host: "unknown", port: 443 };
}
function hookNetwork() {
  console.log(`
${ts()} [HOOKS] Installing hooks...`);
  const libc = Process.getModuleByName("libc.so");
  try {
    const ptr = libc.findExportByName("getaddrinfo");
    if (ptr) {
      Interceptor.attach(ptr, {
        onEnter(args) {
          try {
            this.hostname = args[0].readUtf8String();
            this.result = args[3];
          } catch {
            this.hostname = null;
          }
        },
        onLeave(retval) {
          try {
            const hostname = this.hostname;
            const resultPtr = this.result;
            if (hostname && retval.toInt32() === 0 && resultPtr) {
              let ai = resultPtr.readPointer();
              const ips = [];
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
          } catch {
          }
        }
      });
      console.log("   \u2713 getaddrinfo");
    }
  } catch {
  }
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
              const port = (portBE & 255) << 8 | portBE >> 8 & 255;
              const ip = `${sockaddr.add(4).readU8()}.${sockaddr.add(5).readU8()}.${sockaddr.add(6).readU8()}.${sockaddr.add(7).readU8()}`;
              fdToAddr.set(fd, { ip, port });
            }
          } catch {
          }
        }
      });
      console.log("   \u2713 connect");
    }
  } catch {
  }
  const modules = Process.enumerateModules();
  for (const mod of modules) {
    if (mod.name.toLowerCase().includes("ssl")) {
      try {
        const getFdPtr = mod.findExportByName("SSL_get_fd");
        if (getFdPtr) {
          SSL_get_fd = new NativeFunction(getFdPtr, "int", ["pointer"]);
          console.log(`   \u2713 SSL_get_fd`);
        }
      } catch {
      }
      try {
        const setFdPtr = mod.findExportByName("SSL_set_fd");
        if (setFdPtr) {
          Interceptor.attach(setFdPtr, {
            onEnter(args) {
              const ssl = args[0];
              const fd = args[1].toInt32();
              sslToFd.set(ssl.toString(), fd);
            }
          });
          console.log(`   \u2713 SSL_set_fd`);
        }
      } catch {
      }
      try {
        const sslRead = mod.findExportByName("SSL_read");
        if (sslRead) {
          Interceptor.attach(sslRead, {
            onEnter(args) {
              this.ssl = args[0];
              this.buf = args[1];
            },
            onLeave(retval) {
              const ret = retval.toInt32();
              if (ret > 0) {
                const data = this.buf.readByteArray(Math.min(ret, MAX_CAPTURE_BYTES));
                if (data) {
                  const { host, port } = getHostForSSL(this.ssl, void 0);
                  const ascii = toAscii(data);
                  console.log(`
${ts()} [RECV] \u2190 ${host}:${port} (${ret}B)`);
                  console.log(`   ${ascii.substring(0, 400)}${ascii.length > 400 ? "..." : ""}`);
                  captures.push({ t: elapsed(), direction: "recv", host, port, bytes: ret, ascii });
                }
              }
            }
          });
          console.log(`   \u2713 SSL_read`);
        }
      } catch {
      }
      try {
        const sslWrite = mod.findExportByName("SSL_write");
        if (sslWrite) {
          Interceptor.attach(sslWrite, {
            onEnter(args) {
              this.ssl = args[0];
              this.buf = args[1];
              this.num = args[2].toInt32();
            },
            onLeave(retval) {
              const ret = retval.toInt32();
              if (ret > 0) {
                const data = this.buf.readByteArray(Math.min(ret, MAX_CAPTURE_BYTES));
                if (data) {
                  const { host, port } = getHostForSSL(this.ssl, data);
                  const ascii = toAscii(data);
                  console.log(`
${ts()} [SEND] \u2192 ${host}:${port} (${ret}B)`);
                  console.log(`   ${ascii.substring(0, 400)}${ascii.length > 400 ? "..." : ""}`);
                  captures.push({ t: elapsed(), direction: "send", host, port, bytes: ret, ascii });
                }
              }
            }
          });
          console.log(`   \u2713 SSL_write`);
        }
      } catch {
      }
      break;
    }
  }
}
function printSummary() {
  console.log("\n\n");
  console.log("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
  console.log("\u2551               TLS TRAFFIC SUMMARY                            \u2551");
  console.log("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");
  const byHost = /* @__PURE__ */ new Map();
  for (const cap of captures) {
    const key = cap.host;
    const stats = byHost.get(key) || { send: 0, recv: 0, count: 0 };
    if (cap.direction === "send")
      stats.send += cap.bytes;
    else
      stats.recv += cap.bytes;
    stats.count++;
    byHost.set(key, stats);
  }
  console.log(`
\u{1F4CA} Traffic by host:`);
  for (const [host, stats] of byHost.entries()) {
    console.log(`   ${host}: ${stats.count} requests, \u2191${stats.send}B \u2193${stats.recv}B`);
  }
  console.log(`
\u{1F4CA} Total: ${captures.length} captures`);
  console.log(`
\u{1F4CA} Known IP \u2192 hostname mappings:`);
  for (const [ip, host] of ipToHostname.entries()) {
    console.log(`   ${ip} \u2192 ${host}`);
  }
  console.log(`
\u{1F4CA} Active SSL connections: ${sslToHostname.size}`);
}
function main() {
  startTime = Date.now();
  hookNetwork();
  console.log(`
${ts()} [READY] Capturing for ${DISCOVERY_DURATION_MS / 1e3}s...`);
  console.log("\u2550".repeat(66));
  setTimeout(() => printSummary(), DISCOVERY_DURATION_MS);
}
setTimeout(() => main(), 500);
