/**
 * Network Discovery Mode
 *
 * This is a simplified script focused on discovering all network connections
 * the game makes during startup. It captures ALL DNS lookups and connect() calls
 * without any filtering, and writes a summary after 60 seconds.
 *
 * Usage: frida -U -l discovery.js -f com.habby.archero
 */

import "frida-il2cpp-bridge";
import { FridaMultipleUnpinning } from "../patchers/multiple_unpinning";
import { NativeTlsBypass } from "../patchers/native_tls_bypass";

console.log("[Discovery] Script loaded - Network Discovery Mode");

// Bypass SSL for observation
FridaMultipleUnpinning.bypass(true);
try {
  NativeTlsBypass.enable(true);
  console.log("[Discovery] SSL bypass enabled");
} catch (e) {
  console.log(`[Discovery] SSL bypass failed: ${e}`);
}

// Discovery data storage
interface ConnectionData {
  timestamp: string;
  type: "dns" | "connect";
  hostname?: string;
  ip: string;
  port?: number;
  family?: string;
}

const allConnections: ConnectionData[] = [];
const dnsLookups = new Map<string, Set<string>>(); // hostname -> IPs
const connections = new Map<string, Set<number>>(); // IP -> ports
const startTime = Date.now();

function now(): string {
  return new Date().toISOString();
}

function logDns(hostname: string, ip: string, family: string) {
  const entry: ConnectionData = { timestamp: now(), type: "dns", hostname, ip, family };
  allConnections.push(entry);

  let ips = dnsLookups.get(hostname);
  if (!ips) {
    ips = new Set();
    dnsLookups.set(hostname, ips);
  }
  if (!ips.has(ip)) {
    ips.add(ip);
    console.log(`[DNS] ${hostname} -> ${ip} (${family})`);
  }
}

function logConnect(ip: string, port: number, family: number) {
  const entry: ConnectionData = {
    timestamp: now(),
    type: "connect",
    ip,
    port,
    family: family === 2 ? "ipv4" : "ipv6",
  };
  allConnections.push(entry);

  let ports = connections.get(ip);
  if (!ports) {
    ports = new Set();
    connections.set(ip, ports);
  }
  if (!ports.has(port)) {
    ports.add(port);
    // Try to find hostname for this IP
    let hostname = "";
    for (const [host, ips] of dnsLookups.entries()) {
      if (ips.has(ip)) {
        hostname = ` (${host})`;
        break;
      }
    }
    console.log(`[CONNECT] ${ip}:${port}${hostname}`);
  }
}

function printSummary() {
  const elapsed = (Date.now() - startTime) / 1000;
  console.log("\n" + "=".repeat(60));
  console.log("   NETWORK DISCOVERY SUMMARY");
  console.log("=".repeat(60));
  console.log(`Duration: ${elapsed.toFixed(1)}s | Total events: ${allConnections.length}`);

  console.log("\n--- DNS Lookups (" + dnsLookups.size + " unique hosts) ---");
  const sortedHosts = [...dnsLookups.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  for (const [hostname, ips] of sortedHosts) {
    console.log(`  ${hostname}`);
    for (const ip of ips) {
      console.log(`    -> ${ip}`);
    }
  }

  console.log("\n--- Connections by IP (" + connections.size + " unique IPs) ---");
  const sortedConns = [...connections.entries()].sort((a, b) => {
    const portsA = [...a[1]];
    const portsB = [...b[1]];
    // Sort by most interesting ports first (12020, 443, etc.)
    const hasGamePort = (ports: number[]) => (ports.includes(12020) ? 0 : 1);
    return hasGamePort(portsA) - hasGamePort(portsB) || a[0].localeCompare(b[0]);
  });
  for (const [ip, ports] of sortedConns) {
    let hostname = "";
    for (const [host, ips] of dnsLookups.entries()) {
      if (ips.has(ip)) {
        hostname = ` (${host})`;
        break;
      }
    }
    const sortedPorts = [...ports].sort((a, b) => a - b);
    console.log(`  ${ip}${hostname}: [${sortedPorts.join(", ")}]`);
  }

  console.log("\n--- Game-Related (likely) ---");
  const gameKeywords = ["habby", "archero", "game", "unity"];
  for (const hostname of dnsLookups.keys()) {
    if (gameKeywords.some((kw) => hostname.toLowerCase().includes(kw))) {
      const ips = dnsLookups.get(hostname);
      const ipList = ips ? [...ips].join(", ") : "";
      console.log(`  ${hostname}: ${ipList}`);
    }
  }

  console.log("\n--- Non-443 Ports (interesting) ---");
  for (const [ip, ports] of connections.entries()) {
    const nonStd = [...ports].filter((p) => p !== 443 && p !== 80);
    if (nonStd.length > 0) {
      let hostname = "";
      for (const [host, ips] of dnsLookups.entries()) {
        if (ips.has(ip)) {
          hostname = ` (${host})`;
          break;
        }
      }
      console.log(`  ${ip}${hostname}: [${nonStd.join(", ")}]`);
    }
  }

  console.log("=".repeat(60) + "\n");
}

// Hook getaddrinfo to capture ALL DNS lookups
const getaddrinfoPtr = Module.findExportByName(null, "getaddrinfo");
const ntohsPtr = Module.findExportByName(null, "ntohs");

const ntohs = ntohsPtr ? new NativeFunction(ntohsPtr, "uint16", ["uint16"]) : null;

if (getaddrinfoPtr) {
  const getaddrinfoFn = new NativeFunction(getaddrinfoPtr, "int", [
    "pointer",
    "pointer",
    "pointer",
    "pointer",
  ]);

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
              while (!cur.isNull() && safety++ < 32) {
                const family = cur.add(4).readS32();
                const aiAddr = cur.add(24).readPointer();

                if (family === 2 /* AF_INET */ && !aiAddr.isNull()) {
                  const ipBytes = aiAddr.add(4);
                  const ip = `${ipBytes.readU8()}.${ipBytes.add(1).readU8()}.${ipBytes.add(2).readU8()}.${ipBytes.add(3).readU8()}`;
                  logDns(hostname, ip, "ipv4");
                } else if (family === 10 /* AF_INET6 */ && !aiAddr.isNull()) {
                  const ip6Bytes = aiAddr.add(8);
                  const parts: string[] = [];
                  for (let i = 0; i < 16; i += 2) {
                    const v = (ip6Bytes.add(i).readU8() << 8) | ip6Bytes.add(i + 1).readU8();
                    parts.push(v.toString(16));
                  }
                  logDns(hostname, parts.join(":"), "ipv6");
                }
                cur = cur.add(40).readPointer();
              }
            }
          } catch (e) {
            // Ignore parse errors
          }
        }
        return result;
      },
      "int",
      ["pointer", "pointer", "pointer", "pointer"]
    )
  );
  console.log("[Discovery] getaddrinfo hook installed");
}

// Hook connect() to capture ALL connections
const connectPtrs = [
  Module.findExportByName(null, "connect"),
  Module.findExportByName(null, "__connect"),
].filter((p): p is NativePointer => p !== null);

for (const ptr of connectPtrs) {
  Interceptor.attach(ptr, {
    onEnter(args) {
      try {
        const fd = args[0].toInt32();
        const addr = args[1] as NativePointer;
        if (addr.isNull()) return;

        const family = addr.readU16();
        (this as any).fd = fd;
        (this as any).family = family;

        if (family === 2 /* AF_INET */ && ntohs) {
          const port = (ntohs(addr.add(2).readU16()) as number) | 0;
          const ipBytes = addr.add(4);
          const ip = `${ipBytes.readU8()}.${ipBytes.add(1).readU8()}.${ipBytes.add(2).readU8()}.${ipBytes.add(3).readU8()}`;
          logConnect(ip, port, family);
        } else if (family === 10 /* AF_INET6 */ && ntohs) {
          const port = (ntohs(addr.add(2).readU16()) as number) | 0;
          const ip6Bytes = addr.add(8);
          const parts: string[] = [];
          for (let i = 0; i < 16; i += 2) {
            const v = (ip6Bytes.add(i).readU8() << 8) | ip6Bytes.add(i + 1).readU8();
            parts.push(v.toString(16));
          }
          logConnect(parts.join(":"), port, family);
        }
      } catch (e) {
        // Ignore errors
      }
    },
  });
}
console.log(`[Discovery] connect hooks installed (${connectPtrs.length} variants)`);

// Print summary after 60 seconds
console.log("[Discovery] Will print summary in 60 seconds...");
setTimeout(() => {
  printSummary();
}, 60000);

// Also print partial summary after 30 seconds
setTimeout(() => {
  console.log(
    "\n[Discovery] 30s checkpoint - " + allConnections.length + " events captured so far"
  );
  console.log("[Discovery] DNS hosts: " + dnsLookups.size + ", Unique IPs: " + connections.size);
}, 30000);
