📦
19954 /android/loggers/port_443_logger_v2.js
✄
// android/loggers/port_443_logger_v2.ts
console.log("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
console.log("\u2551     ARCHERO TLS TRAFFIC LOGGER v2                           \u2551");
console.log("\u2551     Game-focused capture with filtering                      \u2551");
console.log("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");
var DISCOVERY_DURATION_MS = 9e4;
var MAX_CAPTURE_BYTES = 4096;
var FILTER_ADS = true;
var GAME_ONLY = false;
var SAVE_JSON = true;
var VERBOSE_HEADERS = false;
var GAME_HOSTS = [
  "habby.mobi",
  "habby.com",
  "archero"
];
var AD_HOSTS = [
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
  "app-measurement"
];
var ANALYTICS_HOSTS = [
  "receiver.habby.mobi",
  // ThinkingData analytics
  "adjust.com",
  "branch.io",
  "amplitude.com",
  "mixpanel.com",
  "segment.io",
  "firebase"
];
function classifyHost(hostname) {
  const lower = hostname.toLowerCase();
  for (const pattern of GAME_HOSTS) {
    if (lower.includes(pattern)) {
      if (lower.includes("receiver.habby.mobi"))
        return "analytics";
      return "game";
    }
  }
  for (const pattern of ANALYTICS_HOSTS) {
    if (lower.includes(pattern))
      return "analytics";
  }
  for (const pattern of AD_HOSTS) {
    if (lower.includes(pattern))
      return "ads";
  }
  return "unknown";
}
function shouldLog(classification) {
  if (GAME_ONLY && classification !== "game")
    return false;
  if (FILTER_ADS && classification === "ads")
    return false;
  return true;
}
var startTime = 0;
var captures = [];
var fdToAddr = /* @__PURE__ */ new Map();
var ipToHostname = /* @__PURE__ */ new Map();
var sslToFd = /* @__PURE__ */ new Map();
var sslToHostname = /* @__PURE__ */ new Map();
var hostnameToIPs = /* @__PURE__ */ new Map();
var SSL_get_fd = null;
var stats = {
  total: 0,
  game: 0,
  analytics: 0,
  ads: 0,
  unknown: 0,
  filtered: 0
};
function elapsed() {
  return startTime > 0 ? (Date.now() - startTime) / 1e3 : 0;
}
function ts() {
  return `[${elapsed().toFixed(2)}s]`;
}
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
function bufferToString(buffer, maxLen = 2048) {
  const bytes = new Uint8Array(buffer);
  const length = Math.min(bytes.length, maxLen);
  let str = "";
  for (let i = 0; i < length; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return str;
}
function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i2 = 0; i2 < bytes.length; i2++) {
    binary += String.fromCharCode(bytes[i2]);
  }
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  let i = 0;
  while (i < binary.length) {
    const a = binary.charCodeAt(i++);
    const b = i < binary.length ? binary.charCodeAt(i++) : 0;
    const c = i < binary.length ? binary.charCodeAt(i++) : 0;
    const triple = a << 16 | b << 8 | c;
    result += chars[triple >> 18 & 63];
    result += chars[triple >> 12 & 63];
    result += i > binary.length + 1 ? "=" : chars[triple >> 6 & 63];
    result += i > binary.length ? "=" : chars[triple & 63];
  }
  return result;
}
function parseHttpRequest(data) {
  try {
    const str = bufferToString(data, 2048);
    const lines = str.split("\r\n");
    if (lines.length < 1)
      return null;
    const requestLine = lines[0];
    const match = requestLine.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/);
    if (!match)
      return null;
    const headers = {};
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
      contentLength: headers["content-length"] ? parseInt(headers["content-length"]) : void 0
    };
  } catch {
    return null;
  }
}
function parseHttpResponse(data) {
  try {
    const str = bufferToString(data, 2048);
    const lines = str.split("\r\n");
    if (lines.length < 1)
      return null;
    const statusLine = lines[0];
    const match = statusLine.match(/^HTTP\/[\d.]+\s+(\d+)\s*(.*)/);
    if (!match)
      return null;
    const headers = {};
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
      contentLength: headers["content-length"] ? parseInt(headers["content-length"]) : void 0
    };
  } catch {
    return null;
  }
}
function extractHttpBody(data) {
  try {
    const str = bufferToString(data, 8192);
    const bodyStart = str.indexOf("\r\n\r\n");
    if (bodyStart < 0)
      return null;
    const bodyStr = str.substring(bodyStart + 4);
    if (bodyStr.length === 0)
      return null;
    const trimmed = bodyStr.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      return {
        type: "json",
        data: trimmed.substring(0, 4096),
        truncated: trimmed.length > 4096,
        originalSize: trimmed.length
      };
    }
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
        originalSize: bodyStr.length
      };
    }
    const bytes = new Uint8Array(data);
    const bodyBytes = bytes.slice(bodyStart + 4, Math.min(bytes.length, bodyStart + 4 + 1024));
    return {
      type: "binary",
      data: toBase64(bodyBytes.buffer),
      truncated: bytes.length > bodyStart + 4 + 1024,
      originalSize: bytes.length - bodyStart - 4
    };
  } catch {
    return null;
  }
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
function classTag(c) {
  switch (c) {
    case "game":
      return "\x1B[32m[GAME]\x1B[0m";
    case "analytics":
      return "\x1B[33m[ANLYT]\x1B[0m";
    case "ads":
      return "\x1B[90m[ADS]\x1B[0m";
    default:
      return "\x1B[36m[???]\x1B[0m";
  }
}
function logCapture(capture) {
  stats.total++;
  stats[capture.classification]++;
  if (!shouldLog(capture.classification)) {
    stats.filtered++;
    return;
  }
  captures.push(capture);
  const dir = capture.direction === "send" ? "\u2192" : "\u2190";
  const tag = classTag(capture.classification);
  console.log(`
${ts()} [${capture.direction.toUpperCase()}] ${dir} ${capture.host}:${capture.port} ${tag} (${capture.bytes}B)`);
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
                  const classification = classifyHost(host);
                  const capture = {
                    t: elapsed(),
                    direction: "recv",
                    host,
                    port,
                    classification,
                    bytes: ret,
                    raw: toAscii(data)
                  };
                  const httpInfo = parseHttpResponse(data);
                  if (httpInfo) {
                    capture.http = httpInfo;
                    const body = extractHttpBody(data);
                    if (body)
                      capture.body = body;
                  }
                  logCapture(capture);
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
                  const classification = classifyHost(host);
                  const capture = {
                    t: elapsed(),
                    direction: "send",
                    host,
                    port,
                    classification,
                    bytes: ret,
                    raw: toAscii(data)
                  };
                  const httpInfo = parseHttpRequest(data);
                  if (httpInfo) {
                    capture.http = httpInfo;
                    const body = extractHttpBody(data);
                    if (body)
                      capture.body = body;
                  }
                  logCapture(capture);
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
  console.log("\u2551               TLS TRAFFIC SUMMARY v2                         \u2551");
  console.log("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");
  console.log(`
\u{1F4CA} Classification breakdown:`);
  console.log(`   Total:     ${stats.total}`);
  console.log(`   Game:      ${stats.game}`);
  console.log(`   Analytics: ${stats.analytics}`);
  console.log(`   Ads:       ${stats.ads} (filtered: ${stats.filtered})`);
  console.log(`   Unknown:   ${stats.unknown}`);
  const byHost = /* @__PURE__ */ new Map();
  for (const cap of captures) {
    const key = cap.host;
    const existing = byHost.get(key) || { send: 0, recv: 0, count: 0, class: cap.classification };
    if (cap.direction === "send")
      existing.send += cap.bytes;
    else
      existing.recv += cap.bytes;
    existing.count++;
    byHost.set(key, existing);
  }
  console.log(`
\u{1F4CA} Traffic by host (logged only):`);
  for (const [host, s] of byHost.entries()) {
    const tag = s.class === "game" ? "\u{1F3AE}" : s.class === "analytics" ? "\u{1F4CA}" : "\u2753";
    console.log(`   ${tag} ${host}: ${s.count} req, \u2191${s.send}B \u2193${s.recv}B`);
  }
  console.log(`
\u{1F4CA} Logged captures: ${captures.length}`);
  console.log(`
\u{1F4CA} Known game host IPs:`);
  for (const [ip, host] of ipToHostname.entries()) {
    const cls = classifyHost(host);
    if (cls === "game" || cls === "analytics") {
      console.log(`   ${ip} \u2192 ${host}`);
    }
  }
  if (SAVE_JSON && captures.length > 0) {
    console.log(`
\u{1F4C1} Saving ${captures.length} captures to JSON...`);
    const jsonLines = captures.map((c) => JSON.stringify(c)).join("\n");
    console.log(`
=== JSON OUTPUT (copy to file) ===`);
    console.log(jsonLines);
    console.log(`=== END JSON OUTPUT ===`);
  }
}
function main() {
  startTime = Date.now();
  hookNetwork();
  console.log(`
${ts()} [CONFIG] FILTER_ADS=${FILTER_ADS}, GAME_ONLY=${GAME_ONLY}, SAVE_JSON=${SAVE_JSON}`);
  console.log(`${ts()} [READY] Capturing for ${DISCOVERY_DURATION_MS / 1e3}s...`);
  console.log("\u2550".repeat(66));
  setTimeout(() => printSummary(), DISCOVERY_DURATION_MS);
}
setTimeout(() => main(), 500);
