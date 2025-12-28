/**
 * Minimal network discovery agent.
 *
 * Logs unique remote endpoints (ip:port) that the client connects to,
 * without any TLS or Il2Cpp hooks.
 */

function findExport(name: string): NativePointer | null {
  const moduleApi = Module as unknown as {
    findExportByName?: (moduleName: string | null, exportName: string) => NativePointer | null;
    findGlobalExportByName?: (exportName: string) => NativePointer | null;
  };
  if (typeof moduleApi.findExportByName === "function")
    return moduleApi.findExportByName(null, name);
  if (typeof moduleApi.findGlobalExportByName === "function")
    return moduleApi.findGlobalExportByName(name);
  return null;
}

const connectPtr = findExport("connect");
const ntohsPtr = findExport("ntohs");
const errnoFnPtr = findExport("__errno") ?? findExport("__errno_location");
const ntohs = ntohsPtr ? new NativeFunction(ntohsPtr, "uint16", ["uint16"]) : null;
const errnoFn = errnoFnPtr ? new NativeFunction(errnoFnPtr, "pointer", []) : null;

function now() {
  return new Date().toISOString();
}

function readErrno(): number | null {
  if (!errnoFn) return null;
  try {
    return (errnoFn() as NativePointer).readS32();
  } catch {
    return null;
  }
}

function errnoName(code: number) {
  switch (code) {
    case 115:
      return "EINPROGRESS";
    case 114:
      return "EALREADY";
    case 111:
      return "ECONNREFUSED";
    case 110:
      return "ETIMEDOUT";
    default:
      return `errno_${code}`;
  }
}

function readIpv4(ipPtr: NativePointer) {
  return `${ipPtr.readU8()}.${ipPtr.add(1).readU8()}.${ipPtr.add(2).readU8()}.${ipPtr.add(3).readU8()}`;
}

function readIpv6(ipPtr: NativePointer) {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    const hi = ipPtr.add(i).readU8();
    const lo = ipPtr.add(i + 1).readU8();
    parts.push((((hi << 8) | lo) & 0xffff).toString(16));
  }
  return parts.join(":");
}

type EndpointKey = string;
const endpoints = new Map<EndpointKey, number>(); // endpoint -> count
const ports = new Map<number, number>(); // port -> count

function bumpEndpoint(endpoint: string) {
  endpoints.set(endpoint, (endpoints.get(endpoint) ?? 0) + 1);
  const portStr = endpoint.split(":").slice(-1)[0] ?? "";
  const port = Number.parseInt(portStr, 10);
  if (!Number.isNaN(port)) ports.set(port, (ports.get(port) ?? 0) + 1);
}

function printSummary() {
  const topPorts = [...ports.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20);
  console.log(`\n[${now()}] ===== CONNECT SUMMARY =====`);
  console.log(`[${now()}] unique_endpoints=${endpoints.size} unique_ports=${ports.size}`);
  console.log(`[${now()}] top_ports=${JSON.stringify(topPorts)}`);
  console.log(`[${now()}] ===========================\n`);
}

console.log(`[DiscoverConnect] loaded connect=${connectPtr} ntohs=${ntohsPtr}`);

if (!connectPtr || !ntohs) {
  console.log("[DiscoverConnect] missing connect/ntohs; nothing to do");
} else {
  Interceptor.attach(connectPtr, {
    onEnter(args) {
      const fd = args[0].toInt32();
      const addr = args[1] as NativePointer;
      const addrLen = args[2].toInt32();
      (this as any).fd = fd;
      (this as any).addrLen = addrLen;

      if (addr.isNull()) return;
      const family = addr.readU16();
      (this as any).family = family;

      try {
        if (family === 2 /* AF_INET */) {
          const port = (ntohs(addr.add(2).readU16()) as number) | 0;
          const ip = readIpv4(addr.add(4));
          const ep = `${ip}:${port}`;
          (this as any).ep = ep;
          bumpEndpoint(ep);
          if ((endpoints.get(ep) ?? 0) === 1)
            console.log(`[${now()}] connect(fd=${fd}) ${ep} len=${addrLen}`);
        } else if (family === 10 /* AF_INET6 */) {
          const port = (ntohs(addr.add(2).readU16()) as number) | 0;
          const ip6 = readIpv6(addr.add(8));
          const ep = `${ip6}:${port}`;
          (this as any).ep = ep;
          bumpEndpoint(ep);
          if ((endpoints.get(ep) ?? 0) === 1)
            console.log(`[${now()}] connect(fd=${fd}) ${ep} len=${addrLen}`);
        }
      } catch {
        // ignore
      }
    },
    onLeave(retval) {
      const result = retval.toInt32();
      if (result !== -1) return;
      const errno = readErrno();
      const ep = (this as any).ep as string | undefined;
      if (ep && errno != null && errno !== 115 /* EINPROGRESS */ && errno !== 114 /* EALREADY */) {
        console.log(`[${now()}] connect ${ep} => -1 (${errnoName(errno)})`);
      }
    },
  });

  setTimeout(printSummary, 60000);
}
