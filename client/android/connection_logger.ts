/**
 * Connection Logger for Network Discovery
 * 
 * Captures all DNS lookups and TCP connections during startup
 * to discover which endpoints the game client communicates with.
 */

interface ConnectionEntry {
  timestamp: string;
  type: "dns" | "connect";
  hostname?: string;
  ip?: string;
  port?: number;
  family?: string;
  result?: number;
}

const connectionLog: ConnectionEntry[] = [];
const dnsLookups = new Map<string, Set<string>>(); // hostname -> IPs
const connections = new Map<string, Set<number>>(); // IP -> ports
const uniqueEndpoints = new Set<string>(); // "hostname:port" or "ip:port"

let discoveryStartTime: number | null = null;
let discoveryDurationMs = 60000; // 60 seconds default

function now(): string {
  return new Date().toISOString();
}

function isDiscoveryActive(): boolean {
  if (discoveryStartTime === null) return false;
  return Date.now() - discoveryStartTime < discoveryDurationMs;
}

function logEntry(entry: ConnectionEntry): void {
  connectionLog.push(entry);
  
  // Track unique endpoints
  if (entry.type === "dns" && entry.hostname && entry.ip) {
    let ips = dnsLookups.get(entry.hostname);
    if (!ips) {
      ips = new Set();
      dnsLookups.set(entry.hostname, ips);
    }
    ips.add(entry.ip);
    uniqueEndpoints.add(`${entry.hostname}:443`); // Assume HTTPS
  }
  
  if (entry.type === "connect" && entry.ip && entry.port) {
    let ports = connections.get(entry.ip);
    if (!ports) {
      ports = new Set();
      connections.set(entry.ip, ports);
    }
    ports.add(entry.port);
    uniqueEndpoints.add(`${entry.ip}:${entry.port}`);
  }
}

function logDns(hostname: string, ip: string, family: string): void {
  if (!isDiscoveryActive()) return;
  
  const entry: ConnectionEntry = {
    timestamp: now(),
    type: "dns",
    hostname,
    ip,
    family,
  };
  logEntry(entry);
  console.log(`[Discovery:DNS] ${hostname} -> ${ip} (${family})`);
}

function logConnect(ip: string, port: number, result: number): void {
  if (!isDiscoveryActive()) return;
  
  const entry: ConnectionEntry = {
    timestamp: now(),
    type: "connect",
    ip,
    port,
    result,
  };
  logEntry(entry);
  console.log(`[Discovery:Connect] ${ip}:${port} (result=${result})`);
}

function printSummary(): void {
  console.log("\n========== NETWORK DISCOVERY SUMMARY ==========");
  console.log(`Duration: ${(Date.now() - (discoveryStartTime || 0)) / 1000}s`);
  console.log(`Total events: ${connectionLog.length}`);
  
  console.log("\n--- DNS Lookups ---");
  dnsLookups.forEach((ips, hostname) => {
    console.log(`  ${hostname}: ${[...ips].join(", ")}`);
  });
  
  console.log("\n--- Connections by IP ---");
  connections.forEach((ports, ip) => {
    // Try to find hostname for this IP
    let hostname = "";
    dnsLookups.forEach((ips, host) => {
      if (ips.has(ip)) hostname = ` (${host})`;
    });
    console.log(`  ${ip}${hostname}: ports [${[...ports].sort((a, b) => a - b).join(", ")}]`);
  });
  
  console.log("\n--- Unique Endpoints ---");
  [...uniqueEndpoints].sort().forEach(ep => {
    console.log(`  ${ep}`);
  });
  
  console.log("\n--- Game-Related Endpoints (likely) ---");
  const gameKeywords = ["habby", "archero", "game", "12020", "443"];
  [...uniqueEndpoints].filter(ep => 
    gameKeywords.some(kw => ep.toLowerCase().includes(kw))
  ).forEach(ep => {
    console.log(`  ${ep}`);
  });
  
  console.log("================================================\n");
}

function getReport(): string {
  const lines: string[] = [];
  lines.push("# Network Discovery Report");
  lines.push(`Generated: ${now()}`);
  lines.push(`Duration: ${(Date.now() - (discoveryStartTime || 0)) / 1000}s`);
  lines.push(`Total events: ${connectionLog.length}`);
  lines.push("");
  
  lines.push("## DNS Lookups");
  dnsLookups.forEach((ips, hostname) => {
    lines.push(`- ${hostname}: ${[...ips].join(", ")}`);
  });
  lines.push("");
  
  lines.push("## Connections");
  connections.forEach((ports, ip) => {
    let hostname = "";
    dnsLookups.forEach((ips, host) => {
      if (ips.has(ip)) hostname = ` (${host})`;
    });
    lines.push(`- ${ip}${hostname}: ports [${[...ports].sort((a, b) => a - b).join(", ")}]`);
  });
  lines.push("");
  
  lines.push("## Raw Log (JSON)");
  lines.push("```json");
  lines.push(JSON.stringify(connectionLog, null, 2));
  lines.push("```");
  
  return lines.join("\n");
}

export const ConnectionLogger = {
  start(durationMs = 60000): void {
    discoveryStartTime = Date.now();
    discoveryDurationMs = durationMs;
    console.log(`[Discovery] Started network discovery for ${durationMs / 1000}s`);
    
    // Schedule summary after duration
    setTimeout(() => {
      printSummary();
    }, durationMs);
  },
  
  logDns,
  logConnect,
  
  isActive: isDiscoveryActive,
  
  getSummary: printSummary,
  getReport,
  
  getConnectionLog: () => connectionLog,
  getDnsLookups: () => dnsLookups,
  getConnections: () => connections,
  getUniqueEndpoints: () => uniqueEndpoints,
};
