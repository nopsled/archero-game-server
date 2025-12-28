/// <reference path="../frida.d.ts" />

function findAnyExport(names: string[]): NativePointer | null {
  const moduleApi = Module as unknown as {
    findExportByName?: (moduleName: string | null, exportName: string) => NativePointer | null;
    findGlobalExportByName?: (exportName: string) => NativePointer | null;
  };

  const findOne = (exportName: string) => {
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
    if (pointer != null) return pointer;
  }
  return null;
}

function ptrInfo(pointer: NativePointer | null) {
  return pointer == null ? "null" : pointer.toString();
}

function hostMatches(rule: string, host: string) {
  const r = rule.toLowerCase();
  const h = host.toLowerCase();
  if (r.startsWith("*.")) {
    const suffix = r.slice(1);
    return h.endsWith(suffix);
  }
  return h === r;
}

function matchesAny(rules: string[], host: string) {
  for (const rule of rules) {
    if (hostMatches(rule, host)) return true;
  }
  return false;
}

const getaddrinfoPtr = findAnyExport(["getaddrinfo"]);
const connectPtr = findAnyExport(["connect"]);
const __connectPtr = findAnyExport(["__connect"]);
const connect64Ptr = findAnyExport(["connect64"]);
const __connect64Ptr = findAnyExport(["__connect64"]);
const connectPtrs = Array.from(
  new Set(
    [connectPtr, __connectPtr, connect64Ptr, __connect64Ptr]
      .filter((p): p is NativePointer => p != null)
      .map((p) => p.toString())
  )
).map((s) => ptr(s));
const sendPtr = findAnyExport(["send", "__send", "sendto", "__sendto"]);
const recvPtr = findAnyExport(["recv", "__recv", "recvfrom", "__recvfrom"]);
const sendtoPtr = findAnyExport(["sendto", "__sendto"]);
const recvfromPtr = findAnyExport(["recvfrom", "__recvfrom"]);
const writePtr = findAnyExport(["write", "__write"]);
const readPtr = findAnyExport(["read", "__read"]);
const writeChkPtr = findAnyExport(["__write_chk"]);
const readChkPtr = findAnyExport(["__read_chk"]);
const sendtoChkPtr = findAnyExport(["__sendto_chk"]);
const recvfromChkPtr = findAnyExport(["__recvfrom_chk"]);
const writevPtr = findAnyExport(["writev", "__writev"]);
const readvPtr = findAnyExport(["readv", "__readv"]);
const sendmsgPtr = findAnyExport(["sendmsg", "__sendmsg"]);
const recvmsgPtr = findAnyExport(["recvmsg", "__recvmsg"]);
const syscallPtr = findAnyExport(["syscall", "__syscall"]);
const ntohsPtr = findAnyExport(["ntohs"]);
const inet_addrPtr = findAnyExport(["inet_addr"]);
const errnoFnPtr = findAnyExport(["__errno", "__errno_location"]);

console.log(
  `[SocketPatcher] exports getaddrinfo=${ptrInfo(getaddrinfoPtr)} connect=${ptrInfo(
    connectPtr
  )} __connect=${ptrInfo(__connectPtr)} connect64=${ptrInfo(connect64Ptr)} __connect64=${ptrInfo(
    __connect64Ptr
  )} send=${ptrInfo(sendPtr)} recv=${ptrInfo(recvPtr)} sendto=${ptrInfo(sendtoPtr)} recvfrom=${ptrInfo(
    recvfromPtr
  )} write=${ptrInfo(writePtr)} read=${ptrInfo(readPtr)} __write_chk=${ptrInfo(
    writeChkPtr
  )} __read_chk=${ptrInfo(readChkPtr)} __sendto_chk=${ptrInfo(sendtoChkPtr)} __recvfrom_chk=${ptrInfo(
    recvfromChkPtr
  )} writev=${ptrInfo(writevPtr)} readv=${ptrInfo(readvPtr)} sendmsg=${ptrInfo(
    sendmsgPtr
  )} recvmsg=${ptrInfo(recvmsgPtr)} syscall=${ptrInfo(
    syscallPtr
  )} ntohs=${ptrInfo(
    ntohsPtr
  )} inet_addr=${ptrInfo(inet_addrPtr)} errno_fn=${ptrInfo(errnoFnPtr)}`
);

const trackedSockets = new Set<number>();
let trafficHooksInstalled = false;
let connectHookInstalled = false;
let sendHookInstalled = false;
let recvHookInstalled = false;
let sendtoHookInstalled = false;
let recvfromHookInstalled = false;
let writeHookInstalled = false;
let readHookInstalled = false;
let writeChkHookInstalled = false;
let readChkHookInstalled = false;
let sendtoChkHookInstalled = false;
let recvfromChkHookInstalled = false;
let writevHookInstalled = false;
let readvHookInstalled = false;
let sendmsgHookInstalled = false;
let recvmsgHookInstalled = false;
let syscallHookInstalled = false;
let connectDebug = false;

type SocketMeta = {
  family?: number;
  ip?: string;
  port?: number;
  patched?: boolean;
  patchedIp?: string;
  patchedPort?: number;
  allowlistedHost?: string;
  ts?: string;
};

const socketMeta = new Map<number, SocketMeta>();

const seenHostnames = new Set<string>();
const hostnamesByIpv4 = new Map<string, Set<string>>();
const hostnamesByIpv6 = new Map<string, Set<string>>();
const recentWatchedHostByTid = new Map<number, { ts: number; host: string }>();

type CaptureConfig = {
  enabled: boolean;
  maxBytes: number;
  onlyPatched: boolean;
  onlyTracked: boolean;
  ports: number[] | null;
  emitConsole: boolean;
  emitMessages: boolean;
  captureReadWrite: boolean;
  captureSyscalls: boolean;
};

let captureConfig: CaptureConfig = {
  enabled: false,
  maxBytes: 2048,
  onlyPatched: true,
  onlyTracked: false,
  ports: null,
  emitConsole: true,
  emitMessages: false,
  captureReadWrite: true,
  captureSyscalls: true,
};

type TlsRemapConfig = {
  enabled: boolean;
  matchIp: string;
  targetIp: string;
  fromPort: number;
  toPort: number;
  maxAgeMs: number;
};

let tlsRemap: TlsRemapConfig = {
  enabled: false,
  matchIp: "127.0.0.2",
  targetIp: "127.0.0.1",
  fromPort: 443,
  toPort: 8443,
  maxAgeMs: 10000,
};

let sendDebug = false;
let sendOnlyTracked = false;
let recvDebug = false;
let recvOnlyTracked = false;

function shouldEmitForFd(fd: number) {
  const meta = socketMeta.get(fd);

  if (captureConfig.enabled) {
    if (captureConfig.onlyTracked && !trackedSockets.has(fd)) return false;
    if (captureConfig.onlyPatched && !meta?.patched) return false;
    if (captureConfig.ports) {
      if (meta?.port == null) return false;
      if (!captureConfig.ports.includes(meta.port)) return false;
    }
    return true;
  }

  if (sendDebug || recvDebug) {
    if ((sendOnlyTracked || recvOnlyTracked) && !trackedSockets.has(fd)) return false;
    return true;
  }

  return false;
}

const getaddrinfoFunction =
  getaddrinfoPtr != null
    ? new NativeFunction(getaddrinfoPtr, "int", ["pointer", "pointer", "pointer", "pointer"])
    : null;

const sendFunction =
  sendPtr != null ? new NativeFunction(sendPtr, "int", ["int", "pointer", "int", "int"]) : null;

const recvFunction =
  recvPtr != null ? new NativeFunction(recvPtr, "int", ["int", "pointer", "int", "int"]) : null;

const writeFunction =
  writePtr != null ? new NativeFunction(writePtr, "int", ["int", "pointer", "int"]) : null;

const readFunction =
  readPtr != null ? new NativeFunction(readPtr, "int", ["int", "pointer", "int"]) : null;

const ntohs = ntohsPtr != null ? new NativeFunction(ntohsPtr, "uint16", ["uint16"]) : null;

const inet_addr =
  inet_addrPtr != null ? new NativeFunction(inet_addrPtr, "int", ["pointer"]) : null;

const errnoFn = errnoFnPtr != null ? new NativeFunction(errnoFnPtr, "pointer", []) : null;

function readErrno(): number | null {
  if (errnoFn == null) return null;
  try {
    const p = errnoFn() as NativePointer;
    return p.readS32();
  } catch {
    return null;
  }
}

function errnoName(code: number) {
  switch (code) {
    case 11:
      return "EAGAIN";
    case 111:
      return "ECONNREFUSED";
    case 113:
      return "EHOSTUNREACH";
    case 115:
      return "EINPROGRESS";
    default:
      return `errno_${code}`;
  }
}

function readSizeT(pointer: NativePointer): number {
  try {
    return Process.pointerSize === 8 ? Number(pointer.readU64()) : pointer.readU32();
  } catch {
    return 0;
  }
}

function swap16(n: number) {
  return ((n & 0xff) << 8) | ((n >> 8) & 0xff);
}

function addIpv4Host(ip: string, host: string) {
  let set = hostnamesByIpv4.get(ip);
  if (!set) {
    set = new Set<string>();
    hostnamesByIpv4.set(ip, set);
  }
  set.add(host);
}

function getHostsForIpv4(ip: string): string[] {
  const set = hostnamesByIpv4.get(ip);
  if (!set) return [];
  return Array.from(set.values());
}

function addIpv6Host(ip: string, host: string) {
  let set = hostnamesByIpv6.get(ip);
  if (!set) {
    set = new Set<string>();
    hostnamesByIpv6.set(ip, set);
  }
  set.add(host);
}

function getHostsForIpv6(ip: string): string[] {
  const set = hostnamesByIpv6.get(ip);
  if (!set) return [];
  return Array.from(set.values());
}

export class Utilities {
  static now() {
    return new Date().toISOString();
  }

  static toHex(buffer: ArrayBuffer, maxBytes = 256) {
    const bytes = new Uint8Array(buffer);
    const length = Math.min(bytes.length, maxBytes);
    let out = "";
    for (let i = 0; i < length; i++) out += bytes[i].toString(16).padStart(2, "0");
    if (bytes.length > maxBytes) out += `…(+${bytes.length - maxBytes}b)`;
    return out;
  }

  static toAscii(buffer: ArrayBuffer, maxBytes = 256) {
    const bytes = new Uint8Array(buffer);
    const length = Math.min(bytes.length, maxBytes);
    let out = "";
    for (let i = 0; i < length; i++) {
      const b = bytes[i];
      out += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
    }
    if (bytes.length > maxBytes) out += `…(+${bytes.length - maxBytes}b)`;
    return out;
  }

  static dump(buffer: ArrayBuffer | null, maxBytes = 256) {
    if (buffer == null) return "null";
    return `hex=${Utilities.toHex(buffer, maxBytes)} ascii="${Utilities.toAscii(buffer, maxBytes)}"`;
  }

  static formatFunction(functionName: string, params: Array<string | number>, retval?: unknown) {
    const joinedParams = params.map(String).join(", ");
    const returnPart = retval === undefined ? "" : ` -> ${String(retval)}`;
    return `${functionName}(${joinedParams})${returnPart}`;
  }

  static readIpv4String(ipPtr: NativePointer) {
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

  static readIpv6String(ipPtr: NativePointer) {
    try {
      const parts: string[] = [];
      for (let i = 0; i < 16; i += 2) {
        const hi = ipPtr.add(i).readU8();
        const lo = ipPtr.add(i + 1).readU8();
        const v = ((hi << 8) | lo) & 0xffff;
        parts.push(v.toString(16).padStart(4, "0"));
      }
      return parts.join(":");
    } catch {
      return "<unknown-ip6>";
    }
  }
}

export class Patcher {
  public static ConfigureTlsRemap(config: Partial<TlsRemapConfig> = {}) {
    tlsRemap = { ...tlsRemap, ...config, enabled: config.enabled ?? true };
    console.log(
      `[${Utilities.now()}] tlsRemap enabled=${tlsRemap.enabled} matchIp=${tlsRemap.matchIp} targetIp=${tlsRemap.targetIp} fromPort=${tlsRemap.fromPort} toPort=${tlsRemap.toPort} maxAgeMs=${tlsRemap.maxAgeMs}`
    );
  }

  public static EnableCapture(config: Partial<CaptureConfig> = {}) {
    captureConfig = {
      ...captureConfig,
      ...config,
      enabled: config.enabled ?? true,
    };

    if (captureConfig.enabled && !trafficHooksInstalled) {
      trafficHooksInstalled = true;
      Patcher.PatchSend(false, false);
      Patcher.PatchRecv(false, false);
      if (captureConfig.captureReadWrite) {
        Patcher.PatchSendto(false);
        Patcher.PatchRecvfrom(false);
        Patcher.PatchWrite(false, false);
        Patcher.PatchRead(false, false);
        Patcher.PatchWriteChk(false);
        Patcher.PatchReadChk(false);
        Patcher.PatchSendtoChk(false);
        Patcher.PatchRecvfromChk(false);
        Patcher.PatchWritev(false);
        Patcher.PatchReadv(false);
        Patcher.PatchSendmsg(false);
        Patcher.PatchRecvmsg(false);
      }
      if (captureConfig.captureSyscalls) {
        Patcher.PatchSyscalls(false);
      }
    }

    console.log(
      `[${Utilities.now()}] capture enabled=${captureConfig.enabled} onlyPatched=${captureConfig.onlyPatched} ports=${JSON.stringify(
        captureConfig.ports
      )} maxBytes=${captureConfig.maxBytes} emitMessages=${captureConfig.emitMessages} captureReadWrite=${captureConfig.captureReadWrite} captureSyscalls=${captureConfig.captureSyscalls}`
    );
  }

  public static PatchGadp(addrInfo: string) {
    if (getaddrinfoFunction == null || getaddrinfoPtr == null) {
      console.log(`[${Utilities.now()}] getaddrinfo export not found; skipping hook`);
      return;
    }

    console.log(`[${Utilities.now()}] Installing getaddrinfo hook -> "${addrInfo}"`);
    Interceptor.replace(
      getaddrinfoPtr,
      new NativeCallback(
        (name, service, req, pai) => {
          const nameStr = name.readUtf8String();
          const newNamePtr = Memory.allocUtf8String(addrInfo);
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction("getaddrinfo", [
              nameStr ?? "<null>",
              String(service),
            ])} -> "${addrInfo}"`
          );
          return getaddrinfoFunction(newNamePtr, service, req, pai) as number;
        },
        "int",
        ["pointer", "pointer", "pointer", "pointer"]
      )
    );
  }

  public static PatchGetaddrinfoAllowlist(
    allowlist: string[],
    newIp: string,
    isDebugging = false,
    watchlist: string[] = []
  ) {
    if (getaddrinfoFunction == null || getaddrinfoPtr == null) {
      console.log(`[${Utilities.now()}] getaddrinfo export not found; skipping hook`);
      return;
    }

    const shouldRedirect = (host: string) => matchesAny(allowlist, host);
    const shouldWatch = (host: string) => matchesAny(watchlist, host);

    console.log(
      `[${Utilities.now()}] Installing getaddrinfo allowlist hook -> "${newIp}" allowlist=${JSON.stringify(
        allowlist
      )}`
    );

    Interceptor.replace(
      getaddrinfoPtr,
      new NativeCallback(
        (name, service, req, pai) => {
          const nameStr = name.readUtf8String() ?? "<null>";
          const doWatch = nameStr !== "<null>" && shouldWatch(nameStr);
          const doRedirect = nameStr !== "<null>" && shouldRedirect(nameStr);

          const targetName = doRedirect ? Memory.allocUtf8String(newIp) : name;
          const result = getaddrinfoFunction(targetName, service, req, pai) as number;

          if (result === 0 && doWatch) {
            const ips: string[] = [];
            try {
              const listPtr = (pai as NativePointer).readPointer();

              if (Process.pointerSize !== 8) {
                // Not implemented for 32-bit.
              } else {

              // struct addrinfo layout (bionic 64-bit)
              const ai_family_off = 4;
              const ai_addr_off = 24; // after 5 ints + padding
              const ai_next_off = 40;
              let cur = listPtr;
              let safety = 0;
              while (!cur.isNull() && safety++ < 32) {
                const ai_family = cur.add(ai_family_off).readS32();
                if (ai_family === 2 /* AF_INET */) {
                  const ai_addr = cur.add(ai_addr_off).readPointer();
                  if (!ai_addr.isNull()) {
                    const ipPtr = ai_addr.add(4);
                    const ip = Utilities.readIpv4String(ipPtr);
                    addIpv4Host(ip, nameStr);
                    ips.push(ip);
                  }
                } else if (ai_family === 10 /* AF_INET6 */) {
                  const ai_addr = cur.add(ai_addr_off).readPointer();
                  if (!ai_addr.isNull()) {
                    const ip6Ptr = ai_addr.add(8);
                    const ip6 = Utilities.readIpv6String(ip6Ptr);
                    addIpv6Host(ip6, nameStr);
                    ips.push(ip6);
                  }
                }
                cur = cur.add(ai_next_off).readPointer();
              }
              }
            } catch {
              // ignore parse failures
            }

            if (!seenHostnames.has(nameStr)) {
              seenHostnames.add(nameStr);
              const unique = Array.from(new Set(ips));
              console.log(
                `[${Utilities.now()}] getaddrinfo watch host="${nameStr}" ips=${JSON.stringify(unique)}`
              );
            }

            // Fallback correlation for tracking sockets even if addrinfo parsing fails.
            try {
              const tid = Process.getCurrentThreadId();
              recentWatchedHostByTid.set(tid, { ts: Date.now(), host: nameStr });
            } catch {
              // ignore
            }
          }

          if (doRedirect) {
            const newNamePtr = Memory.allocUtf8String(newIp);
            if (isDebugging) {
              console.log(
                `[${Utilities.now()}] ${Utilities.formatFunction("getaddrinfo", [
                  nameStr,
                  String(service),
                ])} -> "${newIp}"`
              );
            } else if (!seenHostnames.has(nameStr)) {
              seenHostnames.add(nameStr);
              console.log(`[${Utilities.now()}] getaddrinfo allowlisted host="${nameStr}" -> "${newIp}"`);
            }
            // (actual resolution already done above)
            return result;
          }

          if (isDebugging && nameStr !== "<null>" && !seenHostnames.has(nameStr)) {
            seenHostnames.add(nameStr);
            console.log(`[${Utilities.now()}] getaddrinfo passthrough host="${nameStr}"`);
          }

          return result;
        },
        "int",
        ["pointer", "pointer", "pointer", "pointer"]
      )
    );
  }

  public static PatchConnect(newIP: string, ports = [443], isDebugging = false) {
    if (connectPtrs.length === 0 || ntohs == null || inet_addr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] connect export not found; skipping hook`);
      return;
    }

    connectDebug = connectDebug || isDebugging;

    if (connectDebug) {
      console.log(
        `[${Utilities.now()}] Installing connect hook -> ${newIP} ports=${JSON.stringify(ports)}`
      );
    }

    if (connectDebug && !trafficHooksInstalled) {
      trafficHooksInstalled = true;
      Patcher.PatchSend(true, true);
      Patcher.PatchRecv(true, true);
    }

    if (connectHookInstalled) return;
    connectHookInstalled = true;

    for (const hookPtr of connectPtrs) {
      Interceptor.attach(hookPtr, {
        onEnter(args) {
          try {
            const fd = args[0].toInt32();
            const address = args[1] as NativePointer;
            const addressLen = args[2].toInt32();
            (this as any).fd = fd;
            (this as any).addressLen = addressLen;

            if (address.isNull()) return;

            const family = address.readU16();
            (this as any).family = family;

            socketMeta.set(fd, { family, ts: Utilities.now() });

            const trackWithHost = (ip: string, port: number, host: string, reason?: string) => {
              trackedSockets.add(fd);
              socketMeta.set(fd, {
                family,
                ip,
                port,
                patched: false,
                allowlistedHost: host,
                ts: Utilities.now(),
              });
              console.log(
                `[${Utilities.now()}] track(fd=${fd}) host=${host} ${ip}:${port}${reason ? ` (${reason})` : ""}`
              );
            };

            const tryTidFallback = (ip: string, port: number) => {
              const tid = Process.getCurrentThreadId();
              const mark = recentWatchedHostByTid.get(tid);
              if (mark && Date.now() - mark.ts <= tlsRemap.maxAgeMs) {
                trackWithHost(ip, port, mark.host, "byTid");
              }
            };

            if (family === 2 /* AF_INET */) {
              const portPtr = address.add(2);
              const ipPtr = address.add(4);
              const port = (ntohs(portPtr.readU16()) as number) | 0;
              const originalIp = Utilities.readIpv4String(ipPtr);
              const resolvedHosts = getHostsForIpv4(originalIp);

              socketMeta.set(fd, { family, ip: originalIp, port, patched: false, ts: Utilities.now() });

              if (resolvedHosts.length > 0) {
                trackWithHost(originalIp, port, resolvedHosts[0]);
              } else {
                tryTidFallback(originalIp, port);
              }

              // TLS remap (default 127.0.0.2:443 -> 127.0.0.1:18443) for allowlisted DNS results.
              if (tlsRemap.enabled && port === tlsRemap.fromPort && originalIp === tlsRemap.matchIp) {
                ipPtr.writeInt(inet_addr(Memory.allocUtf8String(tlsRemap.targetIp)) as number);
                portPtr.writeU16(swap16(tlsRemap.toPort));
                trackedSockets.add(fd);
                socketMeta.set(fd, {
                  family,
                  ip: originalIp,
                  port,
                  patched: true,
                  patchedIp: tlsRemap.targetIp,
                  patchedPort: tlsRemap.toPort,
                  ts: Utilities.now(),
                });
                if (connectDebug) {
                  console.log(
                    `[${Utilities.now()}] connect(fd=${fd}) ${originalIp}:${port} -> ${tlsRemap.targetIp}:${tlsRemap.toPort} (tlsRemap)`
                  );
                }
              }

              if (ports.includes(port)) {
                ipPtr.writeInt(inet_addr(Memory.allocUtf8String(newIP)) as number);
                trackedSockets.add(fd);
                socketMeta.set(fd, {
                  family,
                  ip: originalIp,
                  port,
                  patched: true,
                  patchedIp: newIP,
                  patchedPort: port,
                  ts: Utilities.now(),
                });
                if (connectDebug) {
                  console.log(
                    `[${Utilities.now()}] connect(fd=${fd}) ${originalIp}:${port} -> ${newIP}:${port} (patched)`
                  );
                }
              } else if (connectDebug) {
                console.log(`[${Utilities.now()}] connect(fd=${fd}) ${originalIp}:${port} len=${addressLen}`);
              }
            } else if (family === 10 /* AF_INET6 */) {
              const portPtr = address.add(2);
              const port = (ntohs(portPtr.readU16()) as number) | 0;
              const ip6Ptr = address.add(8);
              const originalIp6 = Utilities.readIpv6String(ip6Ptr);
              const resolvedHosts = getHostsForIpv6(originalIp6);

              socketMeta.set(fd, { family, ip: originalIp6, port, patched: false, ts: Utilities.now() });

              if (resolvedHosts.length > 0) {
                trackWithHost(originalIp6, port, resolvedHosts[0]);
              } else {
                tryTidFallback(originalIp6, port);
              }

              if (connectDebug) {
                console.log(`[${Utilities.now()}] connect(fd=${fd}) ${originalIp6}:${port} len=${addressLen}`);
              }
            } else if (connectDebug) {
              console.log(`[${Utilities.now()}] connect(fd=${fd}) family=${family} len=${addressLen}`);
            }
          } catch (err) {
            if (connectDebug) console.log(`[${Utilities.now()}] connect hook error: ${String(err)}`);
          }
        },
        onLeave(retval) {
          const fd = (this as any).fd as number;
          const result = retval.toInt32();

          if (connectDebug) {
            if (result === -1) {
              const e = readErrno();
              if (e != null) {
                console.log(`[${Utilities.now()}] connect(fd=${fd}) => -1 (${errnoName(e)})`);
              } else {
                console.log(`[${Utilities.now()}] connect(fd=${fd}) => -1`);
              }
            } else {
              console.log(`[${Utilities.now()}] connect(fd=${fd}) => ${result}`);
            }
          }

          if (captureConfig.enabled && captureConfig.emitMessages && shouldEmitForFd(fd)) {
            const meta = socketMeta.get(fd) ?? {};
            send({
              type: "connect",
              ts: Utilities.now(),
              fd,
              result,
              errno: result === -1 ? readErrno() : null,
              meta,
            });
          }
        },
      });
    }
  }

  public static PatchSend(isDebugging = false, onlyTracked = false) {
    if (sendFunction == null || sendPtr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] send export not found; skipping hook`);
      return;
    }

    sendDebug = sendDebug || isDebugging;
    sendOnlyTracked = sendOnlyTracked || onlyTracked;

    if (sendHookInstalled) return;
    sendHookInstalled = true;

    Interceptor.replace(
      sendPtr,
      new NativeCallback(
        (fd, buf, len, flags) => {
          const result = sendFunction(fd, buf, len, flags) as number;
          const meta = socketMeta.get(fd);
          const shouldEmit = shouldEmitForFd(fd);

          if (shouldEmit && captureConfig.emitConsole) {
            if (sendDebug || captureConfig.enabled) {
              const snippetLen = Math.min(len, captureConfig.maxBytes);
              const buffer = buf.readByteArray(snippetLen) as ArrayBuffer | null;
              console.log(
                `[${Utilities.now()}] ${Utilities.formatFunction(
                  "send",
                  [fd, `len=${len}`, `flags=${flags}`],
                  result
                )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
              );
            }
          }

          if (captureConfig.enabled && captureConfig.emitMessages && shouldEmit) {
            const snippetLen = Math.min(len, captureConfig.maxBytes);
            const buffer = buf.readByteArray(snippetLen) as ArrayBuffer | null;
            send(
              {
                type: "packet",
                ts: Utilities.now(),
                dir: "send",
                fd,
                totalLen: len,
                truncated: snippetLen < len,
                flags,
                meta: meta ?? {},
              },
              (buffer ?? (new ArrayBuffer(0) as ArrayBuffer)) as ArrayBuffer
            );
          }
          return result;
        },
        "int",
        ["int", "pointer", "int", "int"]
      )
    );
  }

  public static PatchRecv(isDebugging = false, onlyTracked = false) {
    if (recvFunction == null || recvPtr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] recv export not found; skipping hook`);
      return;
    }

    recvDebug = recvDebug || isDebugging;
    recvOnlyTracked = recvOnlyTracked || onlyTracked;

    if (recvHookInstalled) return;
    recvHookInstalled = true;

    Interceptor.replace(
      recvPtr,
      new NativeCallback(
        (fd, buf, len, flags) => {
          const result = recvFunction(fd, buf, len, flags) as number;
          const meta = socketMeta.get(fd);
          const shouldEmit = shouldEmitForFd(fd);

          if (shouldEmit && captureConfig.emitConsole) {
            if ((recvDebug || captureConfig.enabled) && result > 0) {
              const snippetLen = Math.min(result, captureConfig.maxBytes);
              const buffer = buf.readByteArray(snippetLen) as ArrayBuffer | null;
              console.log(
                `[${Utilities.now()}] ${Utilities.formatFunction(
                  "recv",
                  [fd, `len=${len}`, `flags=${flags}`],
                  result
                )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
              );
            } else if (recvDebug || captureConfig.enabled) {
              console.log(
                `[${Utilities.now()}] ${Utilities.formatFunction(
                  "recv",
                  [fd, `len=${len}`, `flags=${flags}`],
                  result
                )} meta=${JSON.stringify(meta ?? {})}`
              );
            }
          }

          if (captureConfig.enabled && captureConfig.emitMessages && shouldEmit && result > 0) {
            const snippetLen = Math.min(result, captureConfig.maxBytes);
            const buffer = buf.readByteArray(snippetLen) as ArrayBuffer | null;
            send(
              {
                type: "packet",
                ts: Utilities.now(),
                dir: "recv",
                fd,
                totalLen: result,
                truncated: snippetLen < result,
                flags,
                meta: meta ?? {},
              },
              (buffer ?? (new ArrayBuffer(0) as ArrayBuffer)) as ArrayBuffer
            );
          }
          return result;
        },
        "int",
        ["int", "pointer", "int", "int"]
      )
    );
  }

  public static PatchSendto(isDebugging = false) {
    if (sendtoPtr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] sendto export not found; skipping hook`);
      return;
    }
    if (sendtoHookInstalled) return;
    sendtoHookInstalled = true;

    Interceptor.attach(sendtoPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
        this.flags = args[3].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd as number;
        const len = this.len as number;
        const flags = this.flags as number;
        const result = retval.toInt32();
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (!shouldEmit || !captureConfig.emitConsole) return;

        const snippetLen = Math.min(len, captureConfig.maxBytes);
        const buffer = (this.buf as NativePointer).readByteArray(snippetLen) as ArrayBuffer | null;
        console.log(
          `[${Utilities.now()}] ${Utilities.formatFunction(
            "sendto",
            [fd, `len=${len}`, `flags=${flags}`],
            result
          )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
        );
      },
    });
  }

  public static PatchRecvfrom(isDebugging = false) {
    if (recvfromPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] recvfrom export not found; skipping hook`);
      return;
    }
    if (recvfromHookInstalled) return;
    recvfromHookInstalled = true;

    Interceptor.attach(recvfromPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
        this.flags = args[3].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd as number;
        const flags = this.flags as number;
        const result = retval.toInt32();
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (!shouldEmit || !captureConfig.emitConsole) return;

        if (result > 0) {
          const snippetLen = Math.min(result, captureConfig.maxBytes);
          const buffer = (this.buf as NativePointer).readByteArray(snippetLen) as ArrayBuffer | null;
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction(
              "recvfrom",
              [fd, `len=${this.len}`, `flags=${flags}`],
              result
            )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
          );
        } else {
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction(
              "recvfrom",
              [fd, `len=${this.len}`, `flags=${flags}`],
              result
            )} meta=${JSON.stringify(meta ?? {})}`
          );
        }
      },
    });
  }

  public static PatchWrite(isDebugging = false, onlyTracked = false) {
    if (writeFunction == null || writePtr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] write export not found; skipping hook`);
      return;
    }

    if (writeHookInstalled) return;
    writeHookInstalled = true;

    Interceptor.replace(
      writePtr,
      new NativeCallback(
        (fd, buf, len) => {
          const result = writeFunction(fd, buf, len) as number;
          const meta = socketMeta.get(fd);
          const shouldEmit = shouldEmitForFd(fd);

          if (shouldEmit && captureConfig.emitConsole) {
            const snippetLen = Math.min(len, captureConfig.maxBytes);
            const buffer = buf.readByteArray(snippetLen) as ArrayBuffer | null;
            console.log(
              `[${Utilities.now()}] ${Utilities.formatFunction(
                "write",
                [fd, `len=${len}`],
                result
              )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
            );
          }

          if (captureConfig.enabled && captureConfig.emitMessages && shouldEmit) {
            const snippetLen = Math.min(len, captureConfig.maxBytes);
            const buffer = buf.readByteArray(snippetLen) as ArrayBuffer | null;
            send(
              {
                type: "packet",
                ts: Utilities.now(),
                dir: "write",
                fd,
                totalLen: len,
                truncated: snippetLen < len,
                meta: meta ?? {},
              },
              (buffer ?? (new ArrayBuffer(0) as ArrayBuffer)) as ArrayBuffer
            );
          }

          return result;
        },
        "int",
        ["int", "pointer", "int"]
      )
    );
  }

  public static PatchRead(isDebugging = false, onlyTracked = false) {
    if (readFunction == null || readPtr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] read export not found; skipping hook`);
      return;
    }

    if (readHookInstalled) return;
    readHookInstalled = true;

    Interceptor.replace(
      readPtr,
      new NativeCallback(
        (fd, buf, len) => {
          const result = readFunction(fd, buf, len) as number;
          const meta = socketMeta.get(fd);
          const shouldEmit = shouldEmitForFd(fd);

          if (shouldEmit && captureConfig.emitConsole) {
            if (result > 0) {
              const snippetLen = Math.min(result, captureConfig.maxBytes);
              const buffer = buf.readByteArray(snippetLen) as ArrayBuffer | null;
              console.log(
                `[${Utilities.now()}] ${Utilities.formatFunction(
                  "read",
                  [fd, `len=${len}`],
                  result
                )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
              );
            } else {
              console.log(
                `[${Utilities.now()}] ${Utilities.formatFunction(
                  "read",
                  [fd, `len=${len}`],
                  result
                )} meta=${JSON.stringify(meta ?? {})}`
              );
            }
          }

          if (captureConfig.enabled && captureConfig.emitMessages && shouldEmit && result > 0) {
            const snippetLen = Math.min(result, captureConfig.maxBytes);
            const buffer = buf.readByteArray(snippetLen) as ArrayBuffer | null;
            send(
              {
                type: "packet",
                ts: Utilities.now(),
                dir: "read",
                fd,
                totalLen: result,
                truncated: snippetLen < result,
                meta: meta ?? {},
              },
              (buffer ?? (new ArrayBuffer(0) as ArrayBuffer)) as ArrayBuffer
            );
          }

          return result;
        },
        "int",
        ["int", "pointer", "int"]
      )
    );
  }

  public static PatchWriteChk(isDebugging = false) {
    if (writeChkPtr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] __write_chk export not found; skipping`);
      return;
    }
    if (writeChkHookInstalled) return;
    writeChkHookInstalled = true;

    Interceptor.attach(writeChkPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd as number;
        const len = this.len as number;
        const result = retval.toInt32();
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);

        if (shouldEmit && captureConfig.emitConsole) {
          const snippetLen = Math.min(len, captureConfig.maxBytes);
          const buffer = (this.buf as NativePointer).readByteArray(snippetLen) as ArrayBuffer | null;
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction(
              "__write_chk",
              [fd, `len=${len}`],
              result
            )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
          );
        }
      },
    });
  }

  public static PatchReadChk(isDebugging = false) {
    if (readChkPtr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] __read_chk export not found; skipping`);
      return;
    }
    if (readChkHookInstalled) return;
    readChkHookInstalled = true;

    Interceptor.attach(readChkPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd as number;
        const result = retval.toInt32();
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);

        if (shouldEmit && captureConfig.emitConsole) {
          if (result > 0) {
            const snippetLen = Math.min(result, captureConfig.maxBytes);
            const buffer = (this.buf as NativePointer).readByteArray(snippetLen) as ArrayBuffer | null;
            console.log(
              `[${Utilities.now()}] ${Utilities.formatFunction(
                "__read_chk",
                [fd, `len=${this.len}`],
                result
              )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
            );
          } else {
            console.log(
              `[${Utilities.now()}] ${Utilities.formatFunction(
                "__read_chk",
                [fd, `len=${this.len}`],
                result
              )} meta=${JSON.stringify(meta ?? {})}`
            );
          }
        }
      },
    });
  }

  public static PatchSendtoChk(isDebugging = false) {
    if (sendtoChkPtr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] __sendto_chk export not found; skipping`);
      return;
    }
    if (sendtoChkHookInstalled) return;
    sendtoChkHookInstalled = true;

    Interceptor.attach(sendtoChkPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
        this.flags = args[3].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd as number;
        const len = this.len as number;
        const flags = this.flags as number;
        const result = retval.toInt32();
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);

        if (shouldEmit && captureConfig.emitConsole) {
          const snippetLen = Math.min(len, captureConfig.maxBytes);
          const buffer = (this.buf as NativePointer).readByteArray(snippetLen) as ArrayBuffer | null;
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction(
              "__sendto_chk",
              [fd, `len=${len}`, `flags=${flags}`],
              result
            )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
          );
        }
      },
    });
  }

  public static PatchRecvfromChk(isDebugging = false) {
    if (recvfromChkPtr == null) {
      if (isDebugging)
        console.log(`[${Utilities.now()}] __recvfrom_chk export not found; skipping`);
      return;
    }
    if (recvfromChkHookInstalled) return;
    recvfromChkHookInstalled = true;

    Interceptor.attach(recvfromChkPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
        this.flags = args[3].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd as number;
        const result = retval.toInt32();
        const flags = this.flags as number;
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);

        if (shouldEmit && captureConfig.emitConsole) {
          if (result > 0) {
            const snippetLen = Math.min(result, captureConfig.maxBytes);
            const buffer = (this.buf as NativePointer).readByteArray(snippetLen) as ArrayBuffer | null;
            console.log(
              `[${Utilities.now()}] ${Utilities.formatFunction(
                "__recvfrom_chk",
                [fd, `len=${this.len}`, `flags=${flags}`],
                result
              )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
            );
          } else {
            console.log(
              `[${Utilities.now()}] ${Utilities.formatFunction(
                "__recvfrom_chk",
                [fd, `len=${this.len}`, `flags=${flags}`],
                result
              )} meta=${JSON.stringify(meta ?? {})}`
            );
          }
        }
      },
    });
  }

  public static PatchWritev(isDebugging = false) {
    if (writevPtr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] writev export not found; skipping`);
      return;
    }
    if (writevHookInstalled) return;
    writevHookInstalled = true;

    Interceptor.attach(writevPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.iov = args[1];
        this.iovcnt = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd as number;
        const iov = this.iov as NativePointer;
        const iovcnt = this.iovcnt as number;
        const result = retval.toInt32();
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);

        if (!shouldEmit || !captureConfig.emitConsole) return;
        if (iovcnt <= 0) {
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction("writev", [fd, `iovcnt=${iovcnt}`], result)} meta=${JSON.stringify(
              meta ?? {}
            )}`
          );
          return;
        }

        // struct iovec { void *iov_base; size_t iov_len; }
        const base = iov.readPointer();
        const len = readSizeT(iov.add(Process.pointerSize));
        const snippetLen = Math.min(len, captureConfig.maxBytes);
        const buffer = base.readByteArray(snippetLen) as ArrayBuffer | null;
        console.log(
          `[${Utilities.now()}] ${Utilities.formatFunction(
            "writev",
            [fd, `iovcnt=${iovcnt}`, `first_len=${len}`],
            result
          )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
        );
      },
    });
  }

  public static PatchReadv(isDebugging = false) {
    if (readvPtr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] readv export not found; skipping`);
      return;
    }
    if (readvHookInstalled) return;
    readvHookInstalled = true;

    Interceptor.attach(readvPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.iov = args[1];
        this.iovcnt = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd as number;
        const iov = this.iov as NativePointer;
        const iovcnt = this.iovcnt as number;
        const result = retval.toInt32();
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);

        if (!shouldEmit || !captureConfig.emitConsole) return;
        if (result <= 0 || iovcnt <= 0) {
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction("readv", [fd, `iovcnt=${iovcnt}`], result)} meta=${JSON.stringify(
              meta ?? {}
            )}`
          );
          return;
        }

        const base = iov.readPointer();
        const len = readSizeT(iov.add(Process.pointerSize));
        const snippetLen = Math.min(Math.min(result, len), captureConfig.maxBytes);
        const buffer = base.readByteArray(snippetLen) as ArrayBuffer | null;
        console.log(
          `[${Utilities.now()}] ${Utilities.formatFunction(
            "readv",
            [fd, `iovcnt=${iovcnt}`, `first_len=${len}`],
            result
          )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
        );
      },
    });
  }

  public static PatchSendmsg(isDebugging = false) {
    if (sendmsgPtr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] sendmsg export not found; skipping`);
      return;
    }
    if (sendmsgHookInstalled) return;
    sendmsgHookInstalled = true;

    Interceptor.attach(sendmsgPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.msg = args[1];
        this.flags = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd as number;
        const msg = this.msg as NativePointer;
        const flags = this.flags as number;
        const result = retval.toInt32();
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (!shouldEmit || !captureConfig.emitConsole) return;

        if (Process.pointerSize !== 8) {
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction(
              "sendmsg",
              [fd, `flags=${flags}`],
              result
            )} meta=${JSON.stringify(meta ?? {})} (unsupported ptrSize=${Process.pointerSize})`
          );
          return;
        }

        // struct msghdr (arm64): msg_iov at +16, msg_iovlen at +24
        const iov = msg.add(16).readPointer();
        const iovlen = readSizeT(msg.add(24));
        if (iov.isNull() || iovlen <= 0) {
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction(
              "sendmsg",
              [fd, `iovlen=${iovlen}`, `flags=${flags}`],
              result
            )} meta=${JSON.stringify(meta ?? {})}`
          );
          return;
        }

        const base = iov.readPointer();
        const len = readSizeT(iov.add(Process.pointerSize));
        const snippetLen = Math.min(len, captureConfig.maxBytes);
        const buffer = base.readByteArray(snippetLen) as ArrayBuffer | null;
        console.log(
          `[${Utilities.now()}] ${Utilities.formatFunction(
            "sendmsg",
            [fd, `iovlen=${iovlen}`, `first_len=${len}`, `flags=${flags}`],
            result
          )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
        );
      },
    });
  }

  public static PatchRecvmsg(isDebugging = false) {
    if (recvmsgPtr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] recvmsg export not found; skipping`);
      return;
    }
    if (recvmsgHookInstalled) return;
    recvmsgHookInstalled = true;

    Interceptor.attach(recvmsgPtr, {
      onEnter(args) {
        this.fd = args[0].toInt32();
        this.msg = args[1];
        this.flags = args[2].toInt32();
      },
      onLeave(retval) {
        const fd = this.fd as number;
        const msg = this.msg as NativePointer;
        const flags = this.flags as number;
        const result = retval.toInt32();
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (!shouldEmit || !captureConfig.emitConsole) return;

        if (Process.pointerSize !== 8) {
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction(
              "recvmsg",
              [fd, `flags=${flags}`],
              result
            )} meta=${JSON.stringify(meta ?? {})} (unsupported ptrSize=${Process.pointerSize})`
          );
          return;
        }

        // struct msghdr (arm64): msg_iov at +16, msg_iovlen at +24
        const iov = msg.add(16).readPointer();
        const iovlen = readSizeT(msg.add(24));
        if (iov.isNull() || iovlen <= 0) {
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction(
              "recvmsg",
              [fd, `iovlen=${iovlen}`, `flags=${flags}`],
              result
            )} meta=${JSON.stringify(meta ?? {})}`
          );
          return;
        }

        if (result > 0) {
          const base = iov.readPointer();
          const len = readSizeT(iov.add(Process.pointerSize));
          const snippetLen = Math.min(Math.min(result, len), captureConfig.maxBytes);
          const buffer = base.readByteArray(snippetLen) as ArrayBuffer | null;
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction(
              "recvmsg",
              [fd, `iovlen=${iovlen}`, `first_len=${len}`, `flags=${flags}`],
              result
            )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
          );
        } else {
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction(
              "recvmsg",
              [fd, `iovlen=${iovlen}`, `flags=${flags}`],
              result
            )} meta=${JSON.stringify(meta ?? {})}`
          );
        }
      },
    });
  }

  public static PatchSyscalls(isDebugging = false) {
    if (syscallPtr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] syscall export not found; skipping`);
      return;
    }
    if (syscallHookInstalled) return;
    syscallHookInstalled = true;

    if (Process.arch !== "arm64") {
      console.log(
        `[${Utilities.now()}] [SocketPatcher] syscall capture only implemented for arm64 (arch=${Process.arch}); skipping`
      );
      return;
    }

    // aarch64 Linux syscall numbers
    const NR_READ = 63;
    const NR_WRITE = 64;
    const NR_CONNECT = 203;
    const NR_SENDTO = 206;
    const NR_RECVFROM = 207;

    const shouldLogFd = (fd: number) => trackedSockets.has(fd) || socketMeta.has(fd);

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
        if (this.skip) return;
        const nr = this.nr as number;
        const fd = this.fd as number;
        const meta = socketMeta.get(fd);
        const shouldEmit = shouldEmitForFd(fd);
        if (!shouldEmit || !captureConfig.emitConsole) return;

        const result = retval.toInt32();
        const name =
          nr === NR_READ
            ? "sys_read"
            : nr === NR_WRITE
              ? "sys_write"
              : nr === NR_CONNECT
                ? "sys_connect"
                : nr === NR_SENDTO
                  ? "sys_sendto"
                  : "sys_recvfrom";

        if (nr === NR_WRITE || nr === NR_SENDTO) {
          const len = this.len as number;
          const snippetLen = Math.min(len, captureConfig.maxBytes);
          const buffer = (this.buf as NativePointer).readByteArray(snippetLen) as ArrayBuffer | null;
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction(
              name,
              [fd, `len=${len}`],
              result
            )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
          );
        } else if (nr === NR_READ || nr === NR_RECVFROM) {
          if (result > 0) {
            const snippetLen = Math.min(result, captureConfig.maxBytes);
            const buffer = (this.buf as NativePointer).readByteArray(snippetLen) as ArrayBuffer | null;
            console.log(
              `[${Utilities.now()}] ${Utilities.formatFunction(
                name,
                [fd, `len=${this.len}`],
                result
              )} meta=${JSON.stringify(meta ?? {})} ${Utilities.dump(buffer, snippetLen)}`
            );
          } else {
            console.log(
              `[${Utilities.now()}] ${Utilities.formatFunction(
                name,
                [fd, `len=${this.len}`],
                result
              )} meta=${JSON.stringify(meta ?? {})}`
            );
          }
        } else {
          console.log(
            `[${Utilities.now()}] ${Utilities.formatFunction(name, [fd], result)} meta=${JSON.stringify(
              meta ?? {}
            )}`
          );
        }
      },
    });
  }

  public static IsTracked(fd: number) {
    return trackedSockets.has(fd);
  }

  public static GetTrackedHost(fd: number): string | null {
    const host = socketMeta.get(fd)?.allowlistedHost;
    return host ?? null;
  }
}
