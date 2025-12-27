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

const getaddrinfoPtr = findAnyExport(["getaddrinfo"]);
const connectPtr = findAnyExport(["connect", "__connect", "connect64", "__connect64"]);
const sendPtr = findAnyExport(["send", "__send", "sendto", "__sendto"]);
const recvPtr = findAnyExport(["recv", "__recv", "recvfrom", "__recvfrom"]);
const ntohsPtr = findAnyExport(["ntohs"]);
const inet_addrPtr = findAnyExport(["inet_addr"]);
const errnoFnPtr = findAnyExport(["__errno", "__errno_location"]);

console.log(
  `[SocketPatcher] exports getaddrinfo=${ptrInfo(getaddrinfoPtr)} connect=${ptrInfo(
    connectPtr
  )} send=${ptrInfo(sendPtr)} recv=${ptrInfo(recvPtr)} ntohs=${ptrInfo(ntohsPtr)} inet_addr=${ptrInfo(
    inet_addrPtr
  )} errno_fn=${ptrInfo(errnoFnPtr)}`
);

const trackedSockets = new Set<number>();
let trafficHooksInstalled = false;

const getaddrinfoFunction =
  getaddrinfoPtr != null
    ? new NativeFunction(getaddrinfoPtr, "int", ["pointer", "pointer", "pointer", "pointer"])
    : null;

const connectFunction =
  connectPtr != null ? new NativeFunction(connectPtr, "int", ["int", "pointer", "int"]) : null;

const sendFunction =
  sendPtr != null ? new NativeFunction(sendPtr, "int", ["int", "pointer", "int", "int"]) : null;

const recvFunction =
  recvPtr != null ? new NativeFunction(recvPtr, "int", ["int", "pointer", "int", "int"]) : null;

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
}

export class Patcher {
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

  public static PatchConnect(newIP: string, ports = [443], isDebugging = false) {
    if (connectFunction == null || connectPtr == null || ntohs == null || inet_addr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] connect export not found; skipping hook`);
      return;
    }

    if (isDebugging) {
      console.log(
        `[${Utilities.now()}] Installing connect hook -> ${newIP} ports=${JSON.stringify(ports)}`
      );
    }

    if (isDebugging && !trafficHooksInstalled) {
      trafficHooksInstalled = true;
      Patcher.PatchSend(true, true);
      Patcher.PatchRecv(true, true);
    }

    Interceptor.replace(
      connectPtr,
      new NativeCallback(
        (fd, address, addressLen) => {
          try {
            // struct sockaddr: sa_family at offset 0 (u16)
            const family = address.readU16();
            if (family !== 2 /* AF_INET */) {
              const result = connectFunction(fd, address, addressLen) as number;
              if (isDebugging) {
                console.log(
                  `[${Utilities.now()}] connect(fd=${fd}) family=${family} len=${addressLen} => ${result}`
                );
              }
              return result;
            }

            const portPtr = address.add(2);
            const ipPtr = address.add(4);
            const port = (ntohs(portPtr.readU16()) as number) | 0;
            const originalIp = Utilities.readIpv4String(ipPtr);

            if (ports.includes(port)) {
              ipPtr.writeInt(inet_addr(Memory.allocUtf8String(newIP)) as number);
              trackedSockets.add(fd);
              if (isDebugging) {
                console.log(
                  `[${Utilities.now()}] connect(fd=${fd}) ${originalIp}:${port} -> ${newIP}:${port} (patched)`
                );
              }
            } else if (isDebugging) {
              console.log(`[${Utilities.now()}] connect(fd=${fd}) ${originalIp}:${port}`);
            }

            const result = connectFunction(fd, address, addressLen) as number;
            if (isDebugging) {
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
            return result;
          } catch (err) {
            const result = connectFunction(fd, address, addressLen) as number;
            if (isDebugging) console.log(`[${Utilities.now()}] connect(fd=${fd}) error=${err}`);
            return result;
          }
        },
        "int",
        ["int", "pointer", "int"]
      )
    );
  }

  public static PatchSend(isDebugging = false, onlyTracked = false) {
    if (sendFunction == null || sendPtr == null) {
      if (isDebugging) console.log(`[${Utilities.now()}] send export not found; skipping hook`);
      return;
    }

    if (isDebugging) {
      console.log(
        `[${Utilities.now()}] Installing send hook (onlyTracked=${onlyTracked}, trackedFds=${trackedSockets.size})`
      );
    }

    Interceptor.replace(
      sendPtr,
      new NativeCallback(
        (fd, buf, len, flags) => {
          const result = sendFunction(fd, buf, len, flags) as number;
          if (isDebugging && (!onlyTracked || trackedSockets.has(fd))) {
            const buffer = buf.readByteArray(len) as ArrayBuffer | null;
            console.log(
              `[${Utilities.now()}] ${Utilities.formatFunction(
                "send",
                [fd, `len=${len}`, `flags=${flags}`],
                result
              )} ${Utilities.dump(buffer, 512)}`
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

    if (isDebugging) {
      console.log(
        `[${Utilities.now()}] Installing recv hook (onlyTracked=${onlyTracked}, trackedFds=${trackedSockets.size})`
      );
    }

    Interceptor.replace(
      recvPtr,
      new NativeCallback(
        (fd, buf, len, flags) => {
          const result = recvFunction(fd, buf, len, flags) as number;
          if (isDebugging && (!onlyTracked || trackedSockets.has(fd))) {
            if (result > 0) {
              const buffer = buf.readByteArray(result) as ArrayBuffer | null;
              console.log(
                `[${Utilities.now()}] ${Utilities.formatFunction(
                  "recv",
                  [fd, `len=${len}`, `flags=${flags}`],
                  result
                )} ${Utilities.dump(buffer, 512)}`
              );
            } else {
              console.log(
                `[${Utilities.now()}] ${Utilities.formatFunction(
                  "recv",
                  [fd, `len=${len}`, `flags=${flags}`],
                  result
                )}`
              );
            }
          }
          return result;
        },
        "int",
        ["int", "pointer", "int", "int"]
      )
    );
  }
}
