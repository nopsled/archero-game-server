📦
67797 /android/patchers/port12020_redirect.js
✄
// android/patchers/core/socket_patcher.ts
function findAnyExport(names) {
  const moduleApi = Module;
  const findOne = (exportName) => {
    if (typeof moduleApi.findExportByName === "function") {
      return moduleApi.findExportByName(null, exportName);
    }
    if (typeof moduleApi.findGlobalExportByName === "function") {
      return moduleApi.findGlobalExportByName(exportName);
    }
    return null;
  };
  for (const name of names) {
    const pointer = findOne(name);
    if (pointer != null)
      return pointer;
  }
  return null;
}
function ptrInfo(pointer) {
  return pointer == null ? "null" : pointer.toString();
}
function hostMatches(rule, host) {
  const r = rule.toLowerCase();
  const h = host.toLowerCase();
  if (r === "*")
    return true;
  if (r.startsWith("*.")) {
    const suffix = r.slice(1);
    return h.endsWith(suffix);
  }
  return h === r;
}
function matchesAny(rules, host) {
  for (const rule of rules) {
    if (hostMatches(rule, host))
      return true;
  }
  return false;
}
var getaddrinfoPtr = findAnyExport(["getaddrinfo"]);
var connectPtr = findAnyExport(["connect"]);
var __connectPtr = findAnyExport(["__connect"]);
var connect64Ptr = findAnyExport(["connect64"]);
var __connect64Ptr = findAnyExport(["__connect64"]);
var connectPtrs = Array.from(new Set([connectPtr, __connectPtr, connect64Ptr, __connect64Ptr].filter((p) => p != null).map((p) => p.toString()))).map((s) => ptr(s));
var sendPtr = findAnyExport(["send", "__send", "sendto", "__sendto"]);
var recvPtr = findAnyExport(["recv", "__recv", "recvfrom", "__recvfrom"]);
var sendtoPtr = findAnyExport(["sendto", "__sendto"]);
var recvfromPtr = findAnyExport(["recvfrom", "__recvfrom"]);
var writePtr = findAnyExport(["write", "__write"]);
var readPtr = findAnyExport(["read", "__read"]);
var writeChkPtr = findAnyExport(["__write_chk"]);
var readChkPtr = findAnyExport(["__read_chk"]);
var sendtoChkPtr = findAnyExport(["__sendto_chk"]);
var recvfromChkPtr = findAnyExport(["__recvfrom_chk"]);
var writevPtr = findAnyExport(["writev", "__writev"]);
var readvPtr = findAnyExport(["readv", "__readv"]);
var sendmsgPtr = findAnyExport(["sendmsg", "__sendmsg"]);
var recvmsgPtr = findAnyExport(["recvmsg", "__recvmsg"]);
var syscallPtr = findAnyExport(["syscall", "__syscall"]);
var socketPtr = findAnyExport(["socket", "__socket"]);
var closePtr = findAnyExport(["close", "__close"]);
var shutdownPtr = findAnyExport(["shutdown", "__shutdown"]);
var getsockoptPtr = findAnyExport(["getsockopt", "__getsockopt"]);
var pollPtr = findAnyExport(["poll", "__poll"]);
var ntohsPtr = findAnyExport(["ntohs"]);
var inet_addrPtr = findAnyExport(["inet_addr"]);
var errnoFnPtr = findAnyExport(["__errno", "__errno_location"]);
console.log(`[SocketPatcher] exports getaddrinfo=${ptrInfo(getaddrinfoPtr)} connect=${ptrInfo(connectPtr)} __connect=${ptrInfo(__connectPtr)} connect64=${ptrInfo(connect64Ptr)} __connect64=${ptrInfo(__connect64Ptr)} send=${ptrInfo(sendPtr)} recv=${ptrInfo(recvPtr)} sendto=${ptrInfo(sendtoPtr)} recvfrom=${ptrInfo(recvfromPtr)} write=${ptrInfo(writePtr)} read=${ptrInfo(readPtr)} __write_chk=${ptrInfo(writeChkPtr)} __read_chk=${ptrInfo(readChkPtr)} __sendto_chk=${ptrInfo(sendtoChkPtr)} __recvfrom_chk=${ptrInfo(recvfromChkPtr)} writev=${ptrInfo(writevPtr)} readv=${ptrInfo(readvPtr)} sendmsg=${ptrInfo(sendmsgPtr)} recvmsg=${ptrInfo(recvmsgPtr)} syscall=${ptrInfo(syscallPtr)} socket=${ptrInfo(socketPtr)} close=${ptrInfo(closePtr)} shutdown=${ptrInfo(shutdownPtr)} getsockopt=${ptrInfo(getsockoptPtr)} poll=${ptrInfo(pollPtr)} ntohs=${ptrInfo(ntohsPtr)} inet_addr=${ptrInfo(inet_addrPtr)} errno_fn=${ptrInfo(errnoFnPtr)}`);
var trackedSockets = /* @__PURE__ */ new Set();
var trafficHooksInstalled = false;
var connectHookInstalled = false;
var lifecycleHooksInstalled = false;
var sendHookInstalled = false;
var recvHookInstalled = false;
var sendtoHookInstalled = false;
var recvfromHookInstalled = false;
var writeHookInstalled = false;
var readHookInstalled = false;
var writeChkHookInstalled = false;
var readChkHookInstalled = false;
var sendtoChkHookInstalled = false;
var recvfromChkHookInstalled = false;
var writevHookInstalled = false;
var readvHookInstalled = false;
var sendmsgHookInstalled = false;
var recvmsgHookInstalled = false;
var syscallHookInstalled = false;
var socketHookInstalled = false;
var closeHookInstalled = false;
var shutdownHookInstalled = false;
var getsockoptHookInstalled = false;
var pollHookInstalled = false;
var connectDebug = false;
var socketMeta = /* @__PURE__ */ new Map();
var pendingConnect = /* @__PURE__ */ new Map();
var seenHostnames = /* @__PURE__ */ new Set();
var hostnamesByIpv4 = /* @__PURE__ */ new Map();
var hostnamesByIpv6 = /* @__PURE__ */ new Map();
var ipsByHostname = /* @__PURE__ */ new Map();
var recentWatchedHostByTid = /* @__PURE__ */ new Map();
var captureConfig = {
  enabled: false,
  maxBytes: 2048,
  onlyPatched: true,
  onlyTracked: false,
  ports: null,
  emitConsole: true,
  emitMessages: false,
  captureReadWrite: true,
  captureSyscalls: true,
  decodeEnabled: false,
  decodePorts: [12020],
  decodeMaxChunkBytes: 65536,
  decodeMaxFrameBytes: 256 * 1024,
  decodeMaxFramesPerSocket: 50,
  decodeLogPayloadBytes: 256
};
var tlsRemap = {
  enabled: false,
  matchIp: "127.0.0.2",
  targetIp: "127.0.0.1",
  fromPort: 443,
  toPort: 8443,
  maxAgeMs: 1e4
};
var connectRedirect = {
  enabled: false,
  targetIp: "127.0.0.1",
  ports: [],
  allowlistHosts: [],
  allowlistIps: []
};
var sendDebug = false;
var sendOnlyTracked = false;
var recvDebug = false;
var recvOnlyTracked = false;
function shouldEmitForFd(fd) {
  const meta = socketMeta.get(fd);
  if (captureConfig.enabled) {
    if (captureConfig.onlyTracked && !trackedSockets.has(fd))
      return false;
    if (captureConfig.onlyPatched && !meta?.patched)
      return false;
    if (captureConfig.ports) {
      if (meta?.port == null)
        return false;
      if (!captureConfig.ports.includes(meta.port))
        return false;
    }
    return true;
  }
  if (sendDebug || recvDebug) {
    if ((sendOnlyTracked || recvOnlyTracked) && !trackedSockets.has(fd))
      return false;
    return true;
  }
  return false;
}
var decodeStateByKey = /* @__PURE__ */ new Map();
function decodeKey(fd, dir) {
  return `${fd}:${dir}`;
}
function effectivePort(meta) {
  return meta?.patchedPort ?? meta?.port;
}
function u16le(b, off) {
  return (b[off] | b[off + 1] << 8) & 65535;
}
function u32le(b, off) {
  return (b[off] | b[off + 1] << 8 | b[off + 2] << 16 | b[off + 3] << 24) >>> 0;
}
function concatBytes(a, b) {
  if (a.length === 0)
    return b;
  if (b.length === 0)
    return a;
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
function maybeDecodePortStream(fd, dir, chunk) {
  if (!captureConfig.enabled || !captureConfig.decodeEnabled)
    return;
  if (chunk.length === 0)
    return;
  const meta = socketMeta.get(fd);
  const port = effectivePort(meta);
  if (port == null)
    return;
  if (captureConfig.decodePorts && !captureConfig.decodePorts.includes(port))
    return;
  const key = decodeKey(fd, dir);
  const prev = decodeStateByKey.get(key) ?? { mode: "unknown", buffer: new Uint8Array(0), frames: 0 };
  const merged = concatBytes(prev.buffer, chunk);
  if (merged.length > captureConfig.decodeMaxFrameBytes * 2) {
    decodeStateByKey.set(key, {
      mode: "unknown",
      buffer: chunk.slice(0, captureConfig.decodeMaxFrameBytes),
      frames: prev.frames
    });
    console.log(`[${Utilities.now()}] [proto] fd=${fd} dir=${dir} port=${port} reset-buffer reason=overflow size=${merged.length}`);
    return;
  }
  const state = { ...prev, buffer: merged };
  if (state.mode === "unknown") {
    if (state.buffer.length >= 3 && state.buffer[0] === 22 && state.buffer[1] === 3) {
      state.mode = "tls";
      const previewLen = Math.min(state.buffer.length, 64);
      console.log(`[${Utilities.now()}] [proto] fd=${fd} dir=${dir} port=${port} detected=tls ${Utilities.dump(state.buffer.slice(0, previewLen).buffer, previewLen)}`);
    } else if (state.buffer.length >= 4) {
      const b0 = state.buffer[0];
      const b1 = state.buffer[1];
      const b2 = state.buffer[2];
      const b3 = state.buffer[3];
      const looksHttp = b0 === 71 && b1 === 69 && b2 === 84 && b3 === 32 || // "GET "
      b0 === 80 && b1 === 79 && b2 === 83 && b3 === 84 || // "POST"
      b0 === 72 && b1 === 84 && b2 === 84 && b3 === 80;
      if (looksHttp) {
        const previewLen = Math.min(state.buffer.length, 256);
        console.log(`[${Utilities.now()}] [proto] fd=${fd} dir=${dir} port=${port} detected=http ${Utilities.dump(state.buffer.slice(0, previewLen).buffer, previewLen)}`);
      } else {
        state.mode = "lengthpref";
      }
    }
  }
  if (state.mode !== "lengthpref") {
    decodeStateByKey.set(key, state);
    return;
  }
  while (state.frames < captureConfig.decodeMaxFramesPerSocket && state.buffer.length >= 4) {
    const frameLen = u32le(state.buffer, 0);
    if (frameLen < 2 || frameLen > captureConfig.decodeMaxFrameBytes) {
      console.log(`[${Utilities.now()}] [proto] fd=${fd} dir=${dir} port=${port} invalid-frame-len=${frameLen} buffer=${state.buffer.length} (giving up)`);
      state.mode = "unknown";
      break;
    }
    if (state.buffer.length < 4 + frameLen)
      break;
    const msgType = u16le(state.buffer, 4);
    const payload = state.buffer.slice(6, 4 + frameLen);
    const logLen = Math.min(payload.length, captureConfig.decodeLogPayloadBytes);
    const payloadPreview = payload.slice(0, logLen);
    console.log(`[${Utilities.now()}] [proto] fd=${fd} dir=${dir} port=${port} frameLen=${frameLen} msg=0x${msgType.toString(16).padStart(4, "0")} payloadLen=${payload.length} ${Utilities.dump(payloadPreview.buffer, logLen)}`);
    try {
      if (payload.length >= 6) {
        let off = 0;
        const platform = payload[off] | payload[off + 1] << 8 | payload[off + 2] << 16 | payload[off + 3] << 24 | 0;
        off += 4;
        const readStr = () => {
          if (off + 2 > payload.length)
            return null;
          const n = u16le(payload, off);
          off += 2;
          if (off + n > payload.length)
            return null;
          const s = new TextDecoder("utf-8", { fatal: false }).decode(payload.slice(off, off + n));
          off += n;
          return s;
        };
        const version = readStr();
        const deviceId = readStr();
        const language = readStr();
        if (version != null && deviceId != null && language != null && off + 8 <= payload.length) {
          const lo = u32le(payload, off);
          const hi = u32le(payload, off + 4);
          off += 8;
          const userId = hi === 0 ? String(lo) : `${hi.toString(16)}${lo.toString(16).padStart(8, "0")}`;
          const token = readStr();
          if (token != null) {
            console.log(`[${Utilities.now()}] [proto] fd=${fd} dir=${dir} port=${port} guess=login platform=${platform} version=${JSON.stringify(version)} deviceId=${JSON.stringify(deviceId)} lang=${JSON.stringify(language)} userId=${JSON.stringify(userId)} tokenLen=${token.length}`);
          }
        }
      }
    } catch {
    }
    state.frames += 1;
    state.buffer = state.buffer.slice(4 + frameLen);
  }
  decodeStateByKey.set(key, state);
}
var getaddrinfoFunction = getaddrinfoPtr != null ? new NativeFunction(getaddrinfoPtr, "int", ["pointer", "pointer", "pointer", "pointer"]) : null;
var sendFunction = sendPtr != null ? new NativeFunction(sendPtr, "int", ["int", "pointer", "int", "int"]) : null;
var recvFunction = recvPtr != null ? new NativeFunction(recvPtr, "int", ["int", "pointer", "int", "int"]) : null;
var writeFunction = writePtr != null ? new NativeFunction(writePtr, "int", ["int", "pointer", "int"]) : null;
var readFunction = readPtr != null ? new NativeFunction(readPtr, "int", ["int", "pointer", "int"]) : null;
var ntohs = ntohsPtr != null ? new NativeFunction(ntohsPtr, "uint16", ["uint16"]) : null;
var inet_addr = inet_addrPtr != null ? new NativeFunction(inet_addrPtr, "int", ["pointer"]) : null;
var errnoFn = errnoFnPtr != null ? new NativeFunction(errnoFnPtr, "pointer", []) : null;
function readErrno() {
  if (errnoFn == null)
    return null;
  try {
    const p = errnoFn();
    return p.readS32();
  } catch {
    return null;
  }
}
function errnoName(code) {
  switch (code) {
    case 11:
      return "EAGAIN";
    case 32:
      return "EPIPE";
    case 101:
      return "ENETUNREACH";
    case 103:
      return "ECONNABORTED";
    case 104:
      return "ECONNRESET";
    case 106:
      return "EISCONN";
    case 111:
      return "ECONNREFUSED";
    case 114:
      return "EALREADY";
    case 113:
      return "EHOSTUNREACH";
    case 115:
      return "EINPROGRESS";
    case 107:
      return "ENOTCONN";
    case 110:
      return "ETIMEDOUT";
    default:
      return `errno_${code}`;
  }
}
function updateSocketMeta(fd, patch) {
  const prev = socketMeta.get(fd) ?? {};
  socketMeta.set(fd, { ...prev, ...patch });
}
function errnoSuffix(errno) {
  if (errno == null || errno === 0)
    return "";
  return ` (${errnoName(errno)})`;
}
function shouldLogLifecycle(fd) {
  return socketMeta.has(fd) || trackedSockets.has(fd) || pendingConnect.has(fd);
}
function readSizeT(pointer) {
  try {
    return Process.pointerSize === 8 ? Number(pointer.readU64()) : pointer.readU32();
  } catch {
    return 0;
  }
}
function swap16(n) {
  return (n & 255) << 8 | n >> 8 & 255;
}
function addIpv4Host(ip, host) {
  let set = hostnamesByIpv4.get(ip);
  if (!set) {
    set = /* @__PURE__ */ new Set();
    hostnamesByIpv4.set(ip, set);
  }
  set.add(host);
}
function addHostnameIp(host, ip) {
  let set = ipsByHostname.get(host);
  if (!set) {
    set = /* @__PURE__ */ new Set();
    ipsByHostname.set(host, set);
  }
  set.add(ip);
}
function getHostsForIpv4(ip) {
  const set = hostnamesByIpv4.get(ip);
  if (!set)
    return [];
  return Array.from(set.values());
}
function addIpv6Host(ip, host) {
  let set = hostnamesByIpv6.get(ip);
  if (!set) {
    set = /* @__PURE__ */ new Set();
    hostnamesByIpv6.set(ip, set);
  }
  set.add(host);
}
function getHostsForIpv6(ip) {
  const set = hostnamesByIpv6.get(ip);
  if (!set)
    return [];
  return Array.from(set.values());
}
var Utilities = class _Utilities {
  static now() {
    return (/* @__PURE__ */ new Date()).toISOString();
  }
  static toHex(buffer, maxBytes = 256) {
    const bytes = new Uint8Array(buffer);
    const length = Math.min(bytes.length, maxBytes);
    let out = "";
    for (let i = 0; i < length; i++)
      out += bytes[i].toString(16).padStart(2, "0");
    if (bytes.length > maxBytes)
      out += `\u2026(+${bytes.length - maxBytes}b)`;
    return out;
  }
  static toAscii(buffer, maxBytes = 256) {
    const bytes = new Uint8Array(buffer);
    const length = Math.min(bytes.length, maxBytes);
    let out = "";
    for (let i = 0; i < length; i++) {
      const b = bytes[i];
      out += b >= 32 && b <= 126 ? String.fromCharCode(b) : ".";
    }
    if (bytes.length > maxBytes)
      out += `\u2026(+${bytes.length - maxBytes}b)`;
    return out;
  }
  static dump(buffer, maxBytes = 256) {
    if (buffer == null)
      return "null";
    return `hex=${_Utilities.toHex(buffer, maxBytes)} ascii="${_Utilities.toAscii(buffer, maxBytes)}"`;
  }
  static formatFunction(functionName, params, retval) {
    const joinedParams = params.map(String).join(", ");
    const returnPart = retval === void 0 ? "" : ` -> ${String(retval)}`;
    return `${functionName}(${joinedParams})${returnPart}`;
  }
  static readIpv4String(ipPtr) {
    try {
      const b0 = ipPtr.readU8();
      const b1 = ipPtr.add(1).readU8();
      const b2 = ipPtr.add(2).readU8();
      const b3 = ipPtr.add(3).readU8();
      return `${b0}.${b1}.${b2}.${b3}`;
    } catch {
      return "<unknown-ip>";
    }
  }
  static readIpv6String(ipPtr) {
    try {
      const parts = [];
      for (let i = 0; i < 16; i += 2) {
        const hi = ipPtr.add(i).readU8();
        const lo = ipPtr.add(i + 1).readU8();
        const v = (hi << 8 | lo) & 65535;
        parts.push(v.toString(16).padStart(4, "0"));
      }
      return parts.join(":");
    } catch {
      return "<unknown-ip6>";
    }
  }
};
var Patcher = class _Patcher {
  static ConfigureTlsRemap(config = {}) {
    tlsRemap = { ...tlsRemap, ...config, enabled: config.enabled ?? true };
    console.log(`[${Utilities.now()}] tlsRemap enabled=${tlsRemap.enabled} matchIp=${tlsRemap.matchIp} targetIp=${tlsRemap.targetIp} fromPort=${tlsRemap.fromPort} toPort=${tlsRemap.toPort} maxAgeMs=${tlsRemap.maxAgeMs}`);
  }
  static ConfigureConnectRedirect(config = {}) {
    connectRedirect = { ...connectRedirect, ...config, enabled: config.enabled ?? true };
    console.log(`[${Utilities.now()}] connectRedirect enabled=${connectRedirect.enabled} targetIp=${connectRedirect.targetIp} ports=${JSON.stringify(connectRedirect.ports)} allowlistHosts=${JSON.stringify(connectRedirect.allowlistHosts)} allowlistIps=${JSON.stringify(connectRedirect.allowlistIps)}`);
  }
  static EnableCapture(config = {}) {
    captureConfig = {
      ...captureConfig,
      ...config,
      enabled: config.enabled ?? true
    };
    if (captureConfig.enabled) {
      _Patcher.PatchLifecycleDiagnostics(false);
      _Patcher.PatchSend(false, false);
      _Patcher.PatchRecv(false, false);
      if (captureConfig.captureReadWrite) {
        _Patcher.PatchWrite(false, false);
        _Patcher.PatchRead(false, false);
      }
      if (captureConfig.captureSyscalls)
        _Patcher.PatchSyscalls(false);
    }
    console.log(`[${Utilities.now()}] capture enabled=${captureConfig.enabled} onlyPatched=${captureConfig.onlyPatched} ports=${JSON.stringify(captureConfig.ports)} maxBytes=${captureConfig.maxBytes} emitMessages=${captureConfig.emitMessages} captureReadWrite=${captureConfig.captureReadWrite} captureSyscalls=${captureConfig.captureSyscalls}`);
  }
  static PatchLifecycleDiagnostics(isDebugging = false) {
    if (!lifecycleHooksInstalled) {
      lifecycleHooksInstalled = true;
      _Patcher.PatchSocket(isDebugging);
      _Patcher.PatchClose(isDebugging);
      _Patcher.PatchShutdown(isDebugging);
      _Patcher.PatchGetsockopt(isDebugging);
    } else {
      _Patcher.PatchSocket(isDebugging);
      _Patcher.PatchClose(isDebugging);
      _Patcher.PatchShutdown(isDebugging);
      _Patcher.PatchGetsockopt(isDebugging);
    }
    if (isDebugging)
      _Patcher.PatchPoll(isDebugging);
  }
  static PatchGadp(addrInfo) {
    if (getaddrinfoFunction == null || getaddrinfoPtr == null) {
      console.log(`[${Utilities.now()}] getaddrinfo export not found; skipping hook`);
      return;
    }
    console.log(`[${Utilities.now()}] Installing getaddrinfo hook -> "${addrInfo}"`);
    Interceptor.replace(getaddrinfoPtr, new NativeCallback((name, service, req, pai) => {
      const nameStr = name.readUtf8String();
      const newNamePtr = Memory.allocUtf8String(addrInfo);
      console.log(`[${Utilities.now()}] ${Utilities.formatFunction("getaddrinfo", [
        nameStr ?? "<null>",
        String(service)
      ])} -> "${addrInfo}"`);
      return getaddrinfoFunction(newNamePtr, service, req, pai);
    }, "int", ["pointer", "pointer", "pointer", "pointer"]));
  }
  static PatchGetaddrinfoAllowlist(allowlist, newIp, isDebugging = false, watchlist = []) {
    if (getaddrinfoFunction == null || getaddrinfoPtr == null) {
      console.log(`[${Utilities.now()}] getaddrinfo export not found; skipping hook`);
      return;
    }
    const shouldRedirect = (host) => matchesAny(allowlist, host);
    const shouldWatch = (host) => matchesAny(watchlist, host);
    console.log(`[${Utilities.now()}] Installing getaddrinfo allowlist hook -> "${newIp}" allowlist=${JSON.stringify(allowlist)}`);
    Interceptor.replace(getaddrinfoPtr, new NativeCallback((name, service, req, pai) => {
      const nameStr = name.readUtf8String() ?? "<null>";
      const doWatch = nameStr !== "<null>" && shouldWatch(nameStr);
      const doRedirect = nameStr !== "<null>" && shouldRedirect(nameStr);
      const targetName = doRedirect ? Memory.allocUtf8String(newIp) : name;
      const result = getaddrinfoFunction(targetName, service, req, pai);
      if (result === 0 && doWatch) {
        const ips = [];
        try {
          const listPtr = pai.readPointer();
          if (Process.pointerSize !== 8) {
          } else {
            const ai_family_off = 4;
            const ai_addr_off = 24;
            const ai_next_off = 40;
            let cur = listPtr;
            let safety = 0;
            while (!cur.isNull() && safety++ < 32) {
              const ai_family = cur.add(ai_family_off).readS32();
              if (ai_family === 2) {
                const ai_addr = cur.add(ai_addr_off).readPointer();
                if (!ai_addr.isNull()) {
                  const ipPtr = ai_addr.add(4);
                  const ip = Utilities.readIpv4String(ipPtr);
                  addIpv4Host(ip, nameStr);
                  addHostnameIp(nameStr, ip);
                  ips.push(ip);
                }
              } else if (ai_family === 10) {
                const ai_addr = cur.add(ai_addr_off).readPointer();
                if (!ai_addr.isNull()) {
                  const ip6Ptr = ai_addr.add(8);
                  const ip6 = Utilities.readIpv6String(ip6Ptr);
                  addIpv6Host(ip6, nameStr);
                  addHostnameIp(nameStr, ip6);
                  ips.push(ip6);
                }
              }
              cur = cur.add(ai_next_off).readPointer();
            }
          }
        } catch {
        }
        if (!seenHostnames.has(nameStr)) {
          seenHostnames.add(nameStr);
          const unique = Array.from(new Set(ips));
          console.log(`[${Utilities.now()}] getaddrinfo watch host="${nameStr}" ips=${JSON.stringify(unique)}`);
        }
        try {
          const tid = Process.getCurrentThreadId();
          recentWatchedHostByTid.set(tid, { ts: Date.now(), host: nameStr });
        } catch {
        }
      }
      if (doRedirect) {
        const newNamePtr = Memory.allocUtf8String(newIp);
        if (isDebugging) {
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("getaddrinfo", [
            nameStr,
            String(service)
          ])} -> "${newIp}"`);
        } else if (!seenHostnames.has(nameStr)) {
          seenHostnames.add(nameStr);
          console.log(`[${Utilities.now()}] getaddrinfo allowlisted host="${nameStr}" -> "${newIp}"`);
        }
        return result;
      }
      if (isDebugging && nameStr !== "<null>" && !seenHostnames.has(nameStr)) {
        seenHostnames.add(nameStr);
        console.log(`[${Utilities.now()}] getaddrinfo passthrough host="${nameStr}"`);
      }
      return result;
    }, "int", ["pointer", "pointer", "pointer", "pointer"]));
  }
  static PatchConnect(newIP, ports = [443], isDebugging = false) {
    if (connectPtrs.length === 0 || ntohs == null || inet_addr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] connect export not found; skipping hook`);
      return;
    }
    connectDebug = connectDebug || isDebugging;
    if (connectDebug) {
      console.log(`[${Utilities.now()}] Installing connect hook -> ${newIP} ports=${JSON.stringify(ports)}`);
    }
    if (connectDebug && !trafficHooksInstalled) {
      trafficHooksInstalled = true;
      _Patcher.PatchLifecycleDiagnostics(true);
      _Patcher.PatchSend(true, true);
      _Patcher.PatchRecv(true, true);
    }
    if (connectHookInstalled)
      return;
    connectHookInstalled = true;
    for (const hookPtr of connectPtrs) {
      Interceptor.attach(hookPtr, {
        onEnter(args) {
          try {
            const fd = args[0].toInt32();
            const address = args[1];
            const addressLen = args[2].toInt32();
            this.fd = fd;
            this.addressLen = addressLen;
            if (address.isNull())
              return;
            const family = address.readU16();
            this.family = family;
            updateSocketMeta(fd, { family, ts: Utilities.now() });
            const trackWithHost = (ip, port, host, reason) => {
              trackedSockets.add(fd);
              updateSocketMeta(fd, {
                family,
                ip,
                port,
                patched: false,
                allowlistedHost: host,
                ts: Utilities.now()
              });
              console.log(`[${Utilities.now()}] track(fd=${fd}) host=${host} ${ip}:${port}${reason ? ` (${reason})` : ""}`);
            };
            const tryTidFallback = (ip, port) => {
              const tid = Process.getCurrentThreadId();
              const mark = recentWatchedHostByTid.get(tid);
              if (mark && Date.now() - mark.ts <= tlsRemap.maxAgeMs) {
                trackWithHost(ip, port, mark.host, "byTid");
              }
            };
            if (family === 2) {
              const portPtr = address.add(2);
              const ipPtr = address.add(4);
              const port = ntohs(portPtr.readU16()) | 0;
              const originalIp = Utilities.readIpv4String(ipPtr);
              const resolvedHosts = getHostsForIpv4(originalIp);
              const logPort = captureConfig.enabled && captureConfig.ports != null && captureConfig.ports.includes(port);
              this.logPort = logPort;
              updateSocketMeta(fd, {
                family,
                ip: originalIp,
                port,
                patched: false,
                ts: Utilities.now()
              });
              if (resolvedHosts.length > 0) {
                trackWithHost(originalIp, port, resolvedHosts[0]);
              } else {
                tryTidFallback(originalIp, port);
              }
              const allowlistedHost = socketMeta.get(fd)?.allowlistedHost;
              const hasHostAllowlist = connectRedirect.allowlistHosts.length > 0;
              const hasIpAllowlist = connectRedirect.allowlistIps.length > 0;
              const hostAllowed = hasHostAllowlist && (allowlistedHost != null && matchesAny(connectRedirect.allowlistHosts, allowlistedHost) || resolvedHosts.some((host) => matchesAny(connectRedirect.allowlistHosts, host)));
              const ipAllowed = hasIpAllowlist && connectRedirect.allowlistIps.includes(originalIp);
              const allowAll = !hasHostAllowlist && !hasIpAllowlist;
              let didRedirect = false;
              if (connectRedirect.enabled && connectRedirect.ports.includes(port) && (allowAll || hostAllowed || ipAllowed)) {
                const reason = allowAll ? "all" : hostAllowed ? "host" : "ip";
                ipPtr.writeInt(inet_addr(Memory.allocUtf8String(connectRedirect.targetIp)));
                trackedSockets.add(fd);
                updateSocketMeta(fd, {
                  family,
                  ip: originalIp,
                  port,
                  patched: true,
                  patchedIp: connectRedirect.targetIp,
                  patchedPort: port,
                  ts: Utilities.now()
                });
                didRedirect = true;
                if (connectDebug) {
                  console.log(`[${Utilities.now()}] connect(fd=${fd}) ${originalIp}:${port} -> ${connectRedirect.targetIp}:${port} (redirect:${reason})`);
                }
              }
              if (!didRedirect) {
                if (tlsRemap.enabled && port === tlsRemap.fromPort && originalIp === tlsRemap.matchIp) {
                  ipPtr.writeInt(inet_addr(Memory.allocUtf8String(tlsRemap.targetIp)));
                  portPtr.writeU16(swap16(tlsRemap.toPort));
                  trackedSockets.add(fd);
                  updateSocketMeta(fd, {
                    family,
                    ip: originalIp,
                    port,
                    patched: true,
                    patchedIp: tlsRemap.targetIp,
                    patchedPort: tlsRemap.toPort,
                    ts: Utilities.now()
                  });
                  if (connectDebug) {
                    console.log(`[${Utilities.now()}] connect(fd=${fd}) ${originalIp}:${port} -> ${tlsRemap.targetIp}:${tlsRemap.toPort} (tlsRemap)`);
                  }
                }
                if (ports.includes(port)) {
                  ipPtr.writeInt(inet_addr(Memory.allocUtf8String(newIP)));
                  trackedSockets.add(fd);
                  updateSocketMeta(fd, {
                    family,
                    ip: originalIp,
                    port,
                    patched: true,
                    patchedIp: newIP,
                    patchedPort: port,
                    ts: Utilities.now()
                  });
                  if (connectDebug) {
                    console.log(`[${Utilities.now()}] connect(fd=${fd}) ${originalIp}:${port} -> ${newIP}:${port} (patched)`);
                  }
                } else if (connectDebug || logPort) {
                  console.log(`[${Utilities.now()}] connect(fd=${fd}) ${originalIp}:${port} len=${addressLen}`);
                }
              }
            } else if (family === 10) {
              const portPtr = address.add(2);
              const port = ntohs(portPtr.readU16()) | 0;
              const ip6Ptr = address.add(8);
              const originalIp6 = Utilities.readIpv6String(ip6Ptr);
              const resolvedHosts = getHostsForIpv6(originalIp6);
              const logPort = captureConfig.enabled && captureConfig.ports != null && captureConfig.ports.includes(port);
              this.logPort = logPort;
              updateSocketMeta(fd, {
                family,
                ip: originalIp6,
                port,
                patched: false,
                ts: Utilities.now()
              });
              if (resolvedHosts.length > 0) {
                trackWithHost(originalIp6, port, resolvedHosts[0]);
              } else {
                tryTidFallback(originalIp6, port);
              }
              if (connectDebug || logPort) {
                console.log(`[${Utilities.now()}] connect(fd=${fd}) ${originalIp6}:${port} len=${addressLen}`);
              }
            } else if (connectDebug) {
              console.log(`[${Utilities.now()}] connect(fd=${fd}) family=${family} len=${addressLen}`);
            }
          } catch (err) {
            if (connectDebug)
              console.log(`[${Utilities.now()}] connect hook error: ${String(err)}`);
          }
        },
        onLeave(retval) {
          const fd = this.fd;
          const result = retval.toInt32();
          const errno = result === -1 ? readErrno() : null;
          const logPort = Boolean(this.logPort);
          if (connectDebug || logPort) {
            if (result === -1) {
              console.log(`[${Utilities.now()}] connect(fd=${fd}) => -1${errnoSuffix(errno)}`);
            } else {
              console.log(`[${Utilities.now()}] connect(fd=${fd}) => ${result}`);
            }
          }
          if (errno === 115 || errno === 114) {
            const meta = socketMeta.get(fd);
            pendingConnect.set(fd, { ts: Utilities.now(), ip: meta?.ip, port: meta?.port });
          } else if (result === 0) {
            pendingConnect.delete(fd);
          }
          if (captureConfig.enabled && captureConfig.emitMessages && shouldEmitForFd(fd)) {
            const meta = socketMeta.get(fd) ?? {};
            send({
              type: "connect",
              ts: Utilities.now(),
              fd,
              result,
              errno,
              meta
            });
          }
        }
      });
    }
  }
  static PatchSend(isDebugging = false, onlyTracked = false) {
    if (sendFunction == null || sendPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] send export not found; skipping hook`);
      return;
    }
    sendDebug = sendDebug || isDebugging;
    sendOnlyTracked = sendOnlyTracked || onlyTracked;
    if (sendHookInstalled)
      return;
    sendHookInstalled = true;
    Interceptor.replace(sendPtr, new NativeCallback((fd, buf, len, flags) => {
      const result = sendFunction(fd, buf, len, flags);
      const errno = result === -1 ? readErrno() : null;
      const meta = socketMeta.get(fd);
      const shouldEmit = shouldEmitForFd(fd);
      if (shouldEmit && captureConfig.emitConsole) {
        if (sendDebug || captureConfig.enabled) {
          const snippetLen = Math.min(len, captureConfig.maxBytes);
          const buffer = buf.readByteArray(snippetLen);
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("send", [fd, `len=${len}`, `flags=${flags}`], result)}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
        }
      }
      if (captureConfig.enabled && captureConfig.emitMessages && shouldEmit) {
        const snippetLen = Math.min(len, captureConfig.maxBytes);
        const buffer = buf.readByteArray(snippetLen);
        send({
          type: "packet",
          ts: Utilities.now(),
          dir: "send",
          fd,
          totalLen: len,
          truncated: snippetLen < len,
          flags,
          meta: meta ?? {}
        }, buffer ?? new ArrayBuffer(0));
      }
      if (shouldEmit && captureConfig.decodeEnabled && result > 0) {
        const sent = Math.min(result, len);
        const decodeLen = Math.min(sent, captureConfig.decodeMaxChunkBytes);
        const decodeBuffer = buf.readByteArray(decodeLen);
        if (decodeBuffer)
          maybeDecodePortStream(fd, "c2s", new Uint8Array(decodeBuffer));
      }
      return result;
    }, "int", ["int", "pointer", "int", "int"]));
  }
  static PatchRecv(isDebugging = false, onlyTracked = false) {
    if (recvFunction == null || recvPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] recv export not found; skipping hook`);
      return;
    }
    recvDebug = recvDebug || isDebugging;
    recvOnlyTracked = recvOnlyTracked || onlyTracked;
    if (recvHookInstalled)
      return;
    recvHookInstalled = true;
    Interceptor.replace(recvPtr, new NativeCallback((fd, buf, len, flags) => {
      const result = recvFunction(fd, buf, len, flags);
      const errno = result === -1 ? readErrno() : null;
      const meta = socketMeta.get(fd);
      const shouldEmit = shouldEmitForFd(fd);
      if (shouldEmit && captureConfig.emitConsole) {
        if ((recvDebug || captureConfig.enabled) && result > 0) {
          const snippetLen = Math.min(result, captureConfig.maxBytes);
          const buffer = buf.readByteArray(snippetLen);
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("recv", [fd, `len=${len}`, `flags=${flags}`], result)} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
        } else if (recvDebug || captureConfig.enabled) {
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("recv", [fd, `len=${len}`, `flags=${flags}`], result)}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})}`);
        }
      }
      if (captureConfig.enabled && captureConfig.emitMessages && shouldEmit && result > 0) {
        const snippetLen = Math.min(result, captureConfig.maxBytes);
        const buffer = buf.readByteArray(snippetLen);
        send({
          type: "packet",
          ts: Utilities.now(),
          dir: "recv",
          fd,
          totalLen: result,
          truncated: snippetLen < result,
          flags,
          meta: meta ?? {}
        }, buffer ?? new ArrayBuffer(0));
      }
      if (shouldEmit && captureConfig.decodeEnabled && result > 0) {
        const decodeLen = Math.min(result, captureConfig.decodeMaxChunkBytes);
        const decodeBuffer = buf.readByteArray(decodeLen);
        if (decodeBuffer)
          maybeDecodePortStream(fd, "s2c", new Uint8Array(decodeBuffer));
      }
      return result;
    }, "int", ["int", "pointer", "int", "int"]));
  }
  static PatchSendto(isDebugging = false) {
    if (sendtoPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] sendto export not found; skipping hook`);
      return;
    }
    if (sendtoHookInstalled)
      return;
    sendtoHookInstalled = true;
    Interceptor.attach(sendtoPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
        this.flags = args[3].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd;
        const len = this.len;
        const flags = this.flags;
        const result = retval.toInt32();
        const errno = result === -1 ? readErrno() : null;
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (!shouldEmit || !captureConfig.emitConsole)
          return;
        const snippetLen = Math.min(len, captureConfig.maxBytes);
        const buffer = this.buf.readByteArray(snippetLen);
        console.log(`[${Utilities.now()}] ${Utilities.formatFunction("sendto", [fd, `len=${len}`, `flags=${flags}`], result)}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
      }
    });
  }
  static PatchRecvfrom(isDebugging = false) {
    if (recvfromPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] recvfrom export not found; skipping hook`);
      return;
    }
    if (recvfromHookInstalled)
      return;
    recvfromHookInstalled = true;
    Interceptor.attach(recvfromPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
        this.flags = args[3].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd;
        const flags = this.flags;
        const result = retval.toInt32();
        const errno = result === -1 ? readErrno() : null;
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (!shouldEmit || !captureConfig.emitConsole)
          return;
        if (result > 0) {
          const snippetLen = Math.min(result, captureConfig.maxBytes);
          const buffer = this.buf.readByteArray(snippetLen);
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("recvfrom", [fd, `len=${this.len}`, `flags=${flags}`], result)} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
        } else {
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("recvfrom", [fd, `len=${this.len}`, `flags=${flags}`], result)}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})}`);
        }
      }
    });
  }
  static PatchWrite(isDebugging = false, onlyTracked = false) {
    if (writeFunction == null || writePtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] write export not found; skipping hook`);
      return;
    }
    if (writeHookInstalled)
      return;
    writeHookInstalled = true;
    Interceptor.replace(writePtr, new NativeCallback((fd, buf, len) => {
      const result = writeFunction(fd, buf, len);
      const errno = result === -1 ? readErrno() : null;
      const meta = socketMeta.get(fd);
      const shouldEmit = shouldEmitForFd(fd);
      if (shouldEmit && captureConfig.emitConsole) {
        const snippetLen = Math.min(len, captureConfig.maxBytes);
        const buffer = buf.readByteArray(snippetLen);
        console.log(`[${Utilities.now()}] ${Utilities.formatFunction("write", [fd, `len=${len}`], result)}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
      }
      if (captureConfig.enabled && captureConfig.emitMessages && shouldEmit) {
        const snippetLen = Math.min(len, captureConfig.maxBytes);
        const buffer = buf.readByteArray(snippetLen);
        send({
          type: "packet",
          ts: Utilities.now(),
          dir: "write",
          fd,
          totalLen: len,
          truncated: snippetLen < len,
          meta: meta ?? {}
        }, buffer ?? new ArrayBuffer(0));
      }
      if (shouldEmit && captureConfig.decodeEnabled && result > 0) {
        const written = Math.min(result, len);
        const decodeLen = Math.min(written, captureConfig.decodeMaxChunkBytes);
        const decodeBuffer = buf.readByteArray(decodeLen);
        if (decodeBuffer)
          maybeDecodePortStream(fd, "c2s", new Uint8Array(decodeBuffer));
      }
      return result;
    }, "int", ["int", "pointer", "int"]));
  }
  static PatchRead(isDebugging = false, onlyTracked = false) {
    if (readFunction == null || readPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] read export not found; skipping hook`);
      return;
    }
    if (readHookInstalled)
      return;
    readHookInstalled = true;
    Interceptor.replace(readPtr, new NativeCallback((fd, buf, len) => {
      const result = readFunction(fd, buf, len);
      const errno = result === -1 ? readErrno() : null;
      const meta = socketMeta.get(fd);
      const shouldEmit = shouldEmitForFd(fd);
      if (shouldEmit && captureConfig.emitConsole) {
        if (result > 0) {
          const snippetLen = Math.min(result, captureConfig.maxBytes);
          const buffer = buf.readByteArray(snippetLen);
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("read", [fd, `len=${len}`], result)} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
        } else {
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("read", [fd, `len=${len}`], result)}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})}`);
        }
      }
      if (captureConfig.enabled && captureConfig.emitMessages && shouldEmit && result > 0) {
        const snippetLen = Math.min(result, captureConfig.maxBytes);
        const buffer = buf.readByteArray(snippetLen);
        send({
          type: "packet",
          ts: Utilities.now(),
          dir: "read",
          fd,
          totalLen: result,
          truncated: snippetLen < result,
          meta: meta ?? {}
        }, buffer ?? new ArrayBuffer(0));
      }
      if (shouldEmit && captureConfig.decodeEnabled && result > 0) {
        const decodeLen = Math.min(result, captureConfig.decodeMaxChunkBytes);
        const decodeBuffer = buf.readByteArray(decodeLen);
        if (decodeBuffer)
          maybeDecodePortStream(fd, "s2c", new Uint8Array(decodeBuffer));
      }
      return result;
    }, "int", ["int", "pointer", "int"]));
  }
  static PatchWriteChk(isDebugging = false) {
    if (writeChkPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] __write_chk export not found; skipping`);
      return;
    }
    if (writeChkHookInstalled)
      return;
    writeChkHookInstalled = true;
    Interceptor.attach(writeChkPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd;
        const len = this.len;
        const result = retval.toInt32();
        const errno = result === -1 ? readErrno() : null;
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (shouldEmit && captureConfig.emitConsole) {
          const snippetLen = Math.min(len, captureConfig.maxBytes);
          const buffer = this.buf.readByteArray(snippetLen);
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("__write_chk", [fd, `len=${len}`], result)}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
        }
      }
    });
  }
  static PatchReadChk(isDebugging = false) {
    if (readChkPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] __read_chk export not found; skipping`);
      return;
    }
    if (readChkHookInstalled)
      return;
    readChkHookInstalled = true;
    Interceptor.attach(readChkPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd;
        const result = retval.toInt32();
        const errno = result === -1 ? readErrno() : null;
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (shouldEmit && captureConfig.emitConsole) {
          if (result > 0) {
            const snippetLen = Math.min(result, captureConfig.maxBytes);
            const buffer = this.buf.readByteArray(snippetLen);
            console.log(`[${Utilities.now()}] ${Utilities.formatFunction("__read_chk", [fd, `len=${this.len}`], result)} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
          } else {
            console.log(`[${Utilities.now()}] ${Utilities.formatFunction("__read_chk", [fd, `len=${this.len}`], result)}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})}`);
          }
        }
      }
    });
  }
  static PatchSendtoChk(isDebugging = false) {
    if (sendtoChkPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] __sendto_chk export not found; skipping`);
      return;
    }
    if (sendtoChkHookInstalled)
      return;
    sendtoChkHookInstalled = true;
    Interceptor.attach(sendtoChkPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
        this.flags = args[3].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd;
        const len = this.len;
        const flags = this.flags;
        const result = retval.toInt32();
        const errno = result === -1 ? readErrno() : null;
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (shouldEmit && captureConfig.emitConsole) {
          const snippetLen = Math.min(len, captureConfig.maxBytes);
          const buffer = this.buf.readByteArray(snippetLen);
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("__sendto_chk", [fd, `len=${len}`, `flags=${flags}`], result)}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
        }
      }
    });
  }
  static PatchRecvfromChk(isDebugging = false) {
    if (recvfromChkPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] __recvfrom_chk export not found; skipping`);
      return;
    }
    if (recvfromChkHookInstalled)
      return;
    recvfromChkHookInstalled = true;
    Interceptor.attach(recvfromChkPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
        this.flags = args[3].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd;
        const result = retval.toInt32();
        const flags = this.flags;
        const errno = result === -1 ? readErrno() : null;
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (shouldEmit && captureConfig.emitConsole) {
          if (result > 0) {
            const snippetLen = Math.min(result, captureConfig.maxBytes);
            const buffer = this.buf.readByteArray(snippetLen);
            console.log(`[${Utilities.now()}] ${Utilities.formatFunction("__recvfrom_chk", [fd, `len=${this.len}`, `flags=${flags}`], result)} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
          } else {
            console.log(`[${Utilities.now()}] ${Utilities.formatFunction("__recvfrom_chk", [fd, `len=${this.len}`, `flags=${flags}`], result)}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})}`);
          }
        }
      }
    });
  }
  static PatchWritev(isDebugging = false) {
    if (writevPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] writev export not found; skipping`);
      return;
    }
    if (writevHookInstalled)
      return;
    writevHookInstalled = true;
    Interceptor.attach(writevPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.iov = args[1];
        this.iovcnt = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd;
        const iov = this.iov;
        const iovcnt = this.iovcnt;
        const result = retval.toInt32();
        const errno = result === -1 ? readErrno() : null;
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (!shouldEmit || !captureConfig.emitConsole)
          return;
        if (iovcnt <= 0) {
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("writev", [fd, `iovcnt=${iovcnt}`], result)} meta=${JSON.stringify(meta ?? {})}`);
          return;
        }
        const base = iov.readPointer();
        const len = readSizeT(iov.add(Process.pointerSize));
        const snippetLen = Math.min(len, captureConfig.maxBytes);
        const buffer = base.readByteArray(snippetLen);
        console.log(`[${Utilities.now()}] ${Utilities.formatFunction("writev", [fd, `iovcnt=${iovcnt}`, `first_len=${len}`], result)}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
      }
    });
  }
  static PatchReadv(isDebugging = false) {
    if (readvPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] readv export not found; skipping`);
      return;
    }
    if (readvHookInstalled)
      return;
    readvHookInstalled = true;
    Interceptor.attach(readvPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.iov = args[1];
        this.iovcnt = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd;
        const iov = this.iov;
        const iovcnt = this.iovcnt;
        const result = retval.toInt32();
        const errno = result === -1 ? readErrno() : null;
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (!shouldEmit || !captureConfig.emitConsole)
          return;
        if (result <= 0 || iovcnt <= 0) {
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("readv", [fd, `iovcnt=${iovcnt}`], result)} meta=${JSON.stringify(meta ?? {})}`);
          return;
        }
        const base = iov.readPointer();
        const len = readSizeT(iov.add(Process.pointerSize));
        const snippetLen = Math.min(Math.min(result, len), captureConfig.maxBytes);
        const buffer = base.readByteArray(snippetLen);
        console.log(`[${Utilities.now()}] ${Utilities.formatFunction("readv", [fd, `iovcnt=${iovcnt}`, `first_len=${len}`], result)}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
      }
    });
  }
  static PatchSendmsg(isDebugging = false) {
    if (sendmsgPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] sendmsg export not found; skipping`);
      return;
    }
    if (sendmsgHookInstalled)
      return;
    sendmsgHookInstalled = true;
    Interceptor.attach(sendmsgPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.msg = args[1];
        this.flags = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd;
        const msg = this.msg;
        const flags = this.flags;
        const result = retval.toInt32();
        const errno = result === -1 ? readErrno() : null;
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (!shouldEmit || !captureConfig.emitConsole)
          return;
        if (Process.pointerSize !== 8) {
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("sendmsg", [fd, `flags=${flags}`], result)} meta=${JSON.stringify(meta ?? {})} (unsupported ptrSize=${Process.pointerSize})`);
          return;
        }
        const iov = msg.add(16).readPointer();
        const iovlen = readSizeT(msg.add(24));
        if (iov.isNull() || iovlen <= 0) {
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("sendmsg", [fd, `iovlen=${iovlen}`, `flags=${flags}`], result)} meta=${JSON.stringify(meta ?? {})}`);
          return;
        }
        const base = iov.readPointer();
        const len = readSizeT(iov.add(Process.pointerSize));
        const snippetLen = Math.min(len, captureConfig.maxBytes);
        const buffer = base.readByteArray(snippetLen);
        console.log(`[${Utilities.now()}] ${Utilities.formatFunction("sendmsg", [fd, `iovlen=${iovlen}`, `first_len=${len}`, `flags=${flags}`], result)}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
      }
    });
  }
  static PatchRecvmsg(isDebugging = false) {
    if (recvmsgPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] recvmsg export not found; skipping`);
      return;
    }
    if (recvmsgHookInstalled)
      return;
    recvmsgHookInstalled = true;
    Interceptor.attach(recvmsgPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.msg = args[1];
        this.flags = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd;
        const msg = this.msg;
        const flags = this.flags;
        const result = retval.toInt32();
        const errno = result === -1 ? readErrno() : null;
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (!shouldEmit || !captureConfig.emitConsole)
          return;
        if (Process.pointerSize !== 8) {
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("recvmsg", [fd, `flags=${flags}`], result)} meta=${JSON.stringify(meta ?? {})} (unsupported ptrSize=${Process.pointerSize})`);
          return;
        }
        const iov = msg.add(16).readPointer();
        const iovlen = readSizeT(msg.add(24));
        if (iov.isNull() || iovlen <= 0) {
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("recvmsg", [fd, `iovlen=${iovlen}`, `flags=${flags}`], result)} meta=${JSON.stringify(meta ?? {})}`);
          return;
        }
        if (result > 0) {
          const base = iov.readPointer();
          const len = readSizeT(iov.add(Process.pointerSize));
          const snippetLen = Math.min(Math.min(result, len), captureConfig.maxBytes);
          const buffer = base.readByteArray(snippetLen);
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("recvmsg", [fd, `iovlen=${iovlen}`, `first_len=${len}`, `flags=${flags}`], result)} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
        } else {
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction("recvmsg", [fd, `iovlen=${iovlen}`, `flags=${flags}`], result)}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})}`);
        }
      }
    });
  }
  static PatchSocket(isDebugging = false) {
    if (socketPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] socket export not found; skipping hook`);
      return;
    }
    if (socketHookInstalled)
      return;
    socketHookInstalled = true;
    Interceptor.attach(socketPtr, {
      onEnter(args) {
        this.domain = args[0].toInt32();
        this.type = args[1].toInt32();
        this.protocol = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = retval.toInt32();
        const domain = this.domain;
        const type = this.type;
        const protocol = this.protocol;
        const errno = fd === -1 ? readErrno() : null;
        if (fd >= 0) {
          updateSocketMeta(fd, {
            sockDomain: domain,
            sockType: type,
            sockProtocol: protocol,
            ts: Utilities.now()
          });
        }
        if (isDebugging) {
          console.log(`[${Utilities.now()}] socket(domain=${domain}, type=${type}, protocol=${protocol}) -> ${fd}${fd === -1 ? errnoSuffix(errno) : ""}`);
        }
      }
    });
  }
  static PatchClose(isDebugging = false) {
    if (closePtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] close export not found; skipping hook`);
      return;
    }
    if (closeHookInstalled)
      return;
    closeHookInstalled = true;
    Interceptor.attach(closePtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd;
        const result = retval.toInt32();
        const errno = result === -1 ? readErrno() : null;
        const meta = socketMeta.get(fd);
        if (isDebugging || shouldLogLifecycle(fd)) {
          console.log(`[${Utilities.now()}] close(${fd}) -> ${result}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})}`);
        }
        if (result === 0) {
          trackedSockets.delete(fd);
          socketMeta.delete(fd);
          pendingConnect.delete(fd);
        }
      }
    });
  }
  static PatchShutdown(isDebugging = false) {
    if (shutdownPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] shutdown export not found; skipping hook`);
      return;
    }
    if (shutdownHookInstalled)
      return;
    shutdownHookInstalled = true;
    Interceptor.attach(shutdownPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.how = args[1].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd;
        const how = this.how;
        const result = retval.toInt32();
        const errno = result === -1 ? readErrno() : null;
        const meta = socketMeta.get(fd);
        if (isDebugging || shouldLogLifecycle(fd)) {
          console.log(`[${Utilities.now()}] shutdown(${fd}, how=${how}) -> ${result}${result === -1 ? errnoSuffix(errno) : ""} meta=${JSON.stringify(meta ?? {})}`);
        }
      }
    });
  }
  static PatchGetsockopt(isDebugging = false) {
    if (getsockoptPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] getsockopt export not found; skipping hook`);
      return;
    }
    if (getsockoptHookInstalled)
      return;
    getsockoptHookInstalled = true;
    const SOL_SOCKET = 1;
    const SO_ERROR = 4;
    Interceptor.attach(getsockoptPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.level = args[1].toInt32();
        this.optname = args[2].toInt32();
        this.optval = args[3];
        this.optlen = args[4];
      },
      onLeave(retval) {
        const fd = this.fd;
        const level = this.level;
        const optname = this.optname;
        const result = retval.toInt32();
        const errno = result === -1 ? readErrno() : null;
        if (level !== SOL_SOCKET || optname !== SO_ERROR)
          return;
        if (!shouldLogLifecycle(fd) && !isDebugging)
          return;
        let soError = null;
        try {
          const optval = this.optval;
          if (!optval.isNull())
            soError = optval.readS32();
        } catch {
          soError = null;
        }
        const meta = socketMeta.get(fd);
        console.log(`[${Utilities.now()}] getsockopt(fd=${fd}, SO_ERROR) -> ${result}${result === -1 ? errnoSuffix(errno) : ""} so_error=${soError ?? "null"}${soError != null ? errnoSuffix(soError) : ""} meta=${JSON.stringify(meta ?? {})}`);
        if (pendingConnect.has(fd) && soError != null) {
          pendingConnect.delete(fd);
        }
      }
    });
  }
  static PatchPoll(isDebugging = false) {
    if (pollPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] poll export not found; skipping hook`);
      return;
    }
    if (pollHookInstalled)
      return;
    pollHookInstalled = true;
    const stride = 8;
    const POLLIN = 1;
    const POLLOUT = 4;
    const POLLERR = 8;
    const POLLHUP = 16;
    const POLLNVAL = 32;
    const describeEvents = (mask) => {
      const out = [];
      if (mask & POLLIN)
        out.push("IN");
      if (mask & POLLOUT)
        out.push("OUT");
      if (mask & POLLERR)
        out.push("ERR");
      if (mask & POLLHUP)
        out.push("HUP");
      if (mask & POLLNVAL)
        out.push("NVAL");
      return out.length ? out.join("|") : "0";
    };
    Interceptor.attach(pollPtr, {
      onEnter(args) {
        const fds = args[0];
        const nfds = args[1].toInt32();
        const timeout = args[2].toInt32();
        this.fds = fds;
        this.nfds = nfds;
        this.timeout = timeout;
        if (fds.isNull() || nfds <= 0) {
          this.matches = [];
          return;
        }
        const matches = [];
        const limit = Math.min(nfds, 256);
        for (let i = 0; i < limit; i++) {
          try {
            const fd = fds.add(i * stride).readS32();
            if (pendingConnect.has(fd))
              matches.push(i);
          } catch {
            break;
          }
        }
        this.matches = matches;
      },
      onLeave(retval) {
        const matches = this.matches ?? [];
        if (matches.length === 0)
          return;
        const fds = this.fds;
        const nfds = this.nfds;
        const timeout = this.timeout;
        const result = retval.toInt32();
        const errno = result === -1 ? readErrno() : null;
        const details = [];
        for (const i of matches) {
          try {
            const base = fds.add(i * stride);
            const fd = base.readS32();
            const events = base.add(4).readS16() & 65535;
            const revents = base.add(6).readS16() & 65535;
            details.push({
              fd,
              events: describeEvents(events),
              revents: describeEvents(revents),
              meta: socketMeta.get(fd)
            });
          } catch {
          }
        }
        console.log(`[${Utilities.now()}] poll(nfds=${nfds}, timeout=${timeout}) -> ${result}${result === -1 ? errnoSuffix(errno) : ""} pending=${JSON.stringify(details)}`);
      }
    });
  }
  static PatchSyscalls(isDebugging = false) {
    if (syscallPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] syscall export not found; skipping`);
      return;
    }
    if (syscallHookInstalled)
      return;
    syscallHookInstalled = true;
    if (Process.arch !== "arm64") {
      console.log(`[${Utilities.now()}] [SocketPatcher] syscall capture only implemented for arm64 (arch=${Process.arch}); skipping`);
      return;
    }
    const NR_READ = 63;
    const NR_WRITE = 64;
    const NR_CONNECT = 203;
    const NR_SENDTO = 206;
    const NR_RECVFROM = 207;
    const shouldLogFd = (fd) => trackedSockets.has(fd) || socketMeta.has(fd);
    Interceptor.attach(syscallPtr, {
      onEnter(args) {
        const nr = args[0].toInt32();
        this.nr = nr;
        if (nr !== NR_READ && nr !== NR_WRITE && nr !== NR_CONNECT && nr !== NR_SENDTO && nr !== NR_RECVFROM) {
          this.skip = true;
          return;
        }
        const fd = args[1].toInt32();
        if (!shouldLogFd(fd)) {
          this.skip = true;
          return;
        }
        this.skip = false;
        this.fd = fd;
        this.buf = args[2];
        this.len = args[3].toInt32();
      },
      onLeave(retval) {
        if (this.skip)
          return;
        const nr = this.nr;
        const fd = this.fd;
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (!shouldEmit || !captureConfig.emitConsole)
          return;
        const result = retval.toInt32();
        const name = nr === NR_READ ? "sys_read" : nr === NR_WRITE ? "sys_write" : nr === NR_CONNECT ? "sys_connect" : nr === NR_SENDTO ? "sys_sendto" : "sys_recvfrom";
        if (nr === NR_WRITE || nr === NR_SENDTO) {
          const len = this.len;
          const snippetLen = Math.min(len, captureConfig.maxBytes);
          const buffer = this.buf.readByteArray(snippetLen);
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction(name, [fd, `len=${len}`], result)} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
        } else if (nr === NR_READ || nr === NR_RECVFROM) {
          if (result > 0) {
            const snippetLen = Math.min(result, captureConfig.maxBytes);
            const buffer = this.buf.readByteArray(snippetLen);
            console.log(`[${Utilities.now()}] ${Utilities.formatFunction(name, [fd, `len=${this.len}`], result)} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`);
          } else {
            console.log(`[${Utilities.now()}] ${Utilities.formatFunction(name, [fd, `len=${this.len}`], result)} meta=${JSON.stringify(meta ?? {})}`);
          }
        } else {
          console.log(`[${Utilities.now()}] ${Utilities.formatFunction(name, [fd], result)} meta=${JSON.stringify(meta ?? {})}`);
        }
      }
    });
  }
  static IsTracked(fd) {
    return trackedSockets.has(fd);
  }
  static GetTrackedHost(fd) {
    const host = socketMeta.get(fd)?.allowlistedHost;
    return host ?? null;
  }
};

// android/patchers/port12020_redirect.ts
var SANDBOX_IP = "10.0.1.22";
var GAME_PORT = 12020;
console.log("");
console.log("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
console.log("\u2551   \u{1F3AE} Port 12020 Redirect to Python Server                \u2551");
console.log("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");
console.log("");
console.log(`[Port12020] Target: ${SANDBOX_IP}:${GAME_PORT}`);
console.log("");
Patcher.ConfigureConnectRedirect({
  enabled: true,
  targetIp: SANDBOX_IP,
  ports: [12020],
  allowlistHosts: [],
  // No allowlist - redirect ALL 12020 traffic
  allowlistIps: []
});
Patcher.EnableCapture({
  enabled: true,
  onlyPatched: true,
  ports: [12020],
  maxBytes: 4096,
  emitConsole: true,
  decodeEnabled: true,
  decodePorts: [12020],
  decodeMaxChunkBytes: 65536,
  decodeMaxFrameBytes: 256 * 1024,
  decodeMaxFramesPerSocket: 100,
  decodeLogPayloadBytes: 256
});
console.log("");
console.log("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
console.log("\u2551   \u2705 Port 12020 Redirect Active                          \u2551");
console.log("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D");
console.log("");
