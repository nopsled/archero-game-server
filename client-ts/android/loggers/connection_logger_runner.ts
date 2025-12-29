/// <reference path="../../frida.d.ts" />

/**
 * Connection Logger Runner
 *
 * Hooks getaddrinfo() + connect() at the socket layer and feeds results into
 * `ConnectionLogger`, then prints a structured JSON report after 30 seconds.
 *
 * Build:
 *   cd client
 *   bun run build:connection-logger
 *
 * Run:
 *   frida -D <device> -W com.habby.archero -l android/build/connection_logger.js
 */

import { ConnectionLogger } from "./connection_logger";

console.log("[ConnectionLoggerRunner] loaded");

const DURATION_MS = 30_000;

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

const getaddrinfoPtr = findAnyExport(["getaddrinfo"]);
const ntohsPtr = findAnyExport(["ntohs"]);
const connectPtrs = [
  findAnyExport(["connect"]),
  findAnyExport(["__connect"]),
  findAnyExport(["connect64"]),
  findAnyExport(["__connect64"]),
].filter((p): p is NativePointer => p != null);

const ntohs = ntohsPtr != null ? new NativeFunction(ntohsPtr, "uint16", ["uint16"]) : null;
const getaddrinfoFn =
  getaddrinfoPtr != null
    ? new NativeFunction(getaddrinfoPtr, "int", ["pointer", "pointer", "pointer", "pointer"])
    : null;

function readIpv4String(ipPtr: NativePointer) {
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

function readIpv6String(ipPtr: NativePointer) {
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

function snapshot() {
  const dns: Record<string, string[]> = {};
  for (const [host, ips] of ConnectionLogger.getDnsLookups().entries()) {
    dns[host] = Array.from(ips.values()).sort();
  }

  const conns: Record<string, number[]> = {};
  for (const [ip, ports] of ConnectionLogger.getConnections().entries()) {
    conns[ip] = Array.from(ports.values()).sort((a, b) => a - b);
  }

  return {
    ts: new Date().toISOString(),
    durationMs: DURATION_MS,
    totalEvents: ConnectionLogger.getConnectionLog().length,
    dnsLookups: dns,
    connections: conns,
    uniqueEndpoints: Array.from(ConnectionLogger.getUniqueEndpoints().values()).sort(),
  };
}

ConnectionLogger.start(DURATION_MS);

if (getaddrinfoPtr != null && getaddrinfoFn != null) {
  Interceptor.replace(
    getaddrinfoPtr,
    new NativeCallback(
      (name, service, hints, res) => {
        const hostname = name.readUtf8String() ?? "<null>";
        const result = getaddrinfoFn(name, service, hints, res) as number;

        if (result === 0 && hostname !== "<null>") {
          try {
            const list = (res as NativePointer).readPointer();
            if (!list.isNull() && Process.pointerSize === 8) {
              let cur = list;
              let safety = 0;
              while (!cur.isNull() && safety++ < 64) {
                const family = cur.add(4).readS32();
                const aiAddr = cur.add(24).readPointer();

                if (family === 2 /* AF_INET */ && !aiAddr.isNull()) {
                  const ip = readIpv4String(aiAddr.add(4));
                  ConnectionLogger.logDns(hostname, ip, "ipv4");
                } else if (family === 10 /* AF_INET6 */ && !aiAddr.isNull()) {
                  const ip6 = readIpv6String(aiAddr.add(8));
                  ConnectionLogger.logDns(hostname, ip6, "ipv6");
                }

                cur = cur.add(40).readPointer();
              }
            }
          } catch {
            // ignore
          }
        }

        return result;
      },
      "int",
      ["pointer", "pointer", "pointer", "pointer"]
    )
  );

  console.log("[ConnectionLoggerRunner] getaddrinfo hook installed");
} else {
  console.log("[ConnectionLoggerRunner] getaddrinfo export not found; DNS logging disabled");
}

if (connectPtrs.length > 0 && ntohs != null) {
  for (const connectPtr of connectPtrs) {
    Interceptor.attach(connectPtr, {
      onEnter(args) {
        const addr = args[1] as NativePointer;
        if (addr.isNull()) return;
        const family = addr.readU16();

        if (family === 2 /* AF_INET */) {
          (this as any).ip = readIpv4String(addr.add(4));
          (this as any).port = (ntohs(addr.add(2).readU16()) as number) | 0;
        } else if (family === 10 /* AF_INET6 */) {
          (this as any).ip = readIpv6String(addr.add(8));
          (this as any).port = (ntohs(addr.add(2).readU16()) as number) | 0;
        }
      },
      onLeave(retval) {
        const ip = (this as any).ip as string | undefined;
        const port = (this as any).port as number | undefined;
        if (ip && port != null) {
          ConnectionLogger.logConnect(ip, port, retval.toInt32());
        }
      },
    });
  }

  console.log(`[ConnectionLoggerRunner] connect hooks installed (${connectPtrs.length} variants)`);
} else {
  console.log("[ConnectionLoggerRunner] connect export not found; connect logging disabled");
}

setTimeout(() => {
  console.log("CONNECTION_LOGGER_LOG_START");
  console.log(JSON.stringify(snapshot(), null, 2));
  console.log("CONNECTION_LOGGER_LOG_END");
}, DURATION_MS + 250);

