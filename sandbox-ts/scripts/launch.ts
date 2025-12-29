#!/usr/bin/env bun

/**
 * Sandbox Development Launcher
 *
 * This script:
 * 1. Starts the sandbox server
 * 2. Builds the Frida agent with socket patching for sandbox
 * 3. Launches the game client with Frida injection
 *
 * Usage:
 *   bun run launch [--device <id>] [--attach|--await] [--restart-app]
 *     [--ip <ip>] [--tcp-port <port>] [--no-server] [--redirect-443]
 */

import { mkdir } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import { join } from "node:path";

// Auto-detect local network IP (for Android device on same network)
function getLocalNetworkIP(): string {
  const nets = networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] ?? []) {
      // Skip loopback and internal addresses
      if (net.family === "IPv4" && !net.internal) {
        return net.address;
      }
    }
  }
  return "127.0.0.1"; // Fallback
}

// Configuration defaults (override via CLI args below)
// No adb reverse needed - uses local network IP by default
const DEFAULT_SANDBOX_IP = getLocalNetworkIP();
const DEFAULT_TCP_PORT = 12020;
const DEFAULT_HTTP_PORT = 443;

// Parse arguments
const args = Bun.argv;
const deviceIndex = args.indexOf("--device");
const DEVICE_ID = deviceIndex !== -1 ? args[deviceIndex + 1] : undefined;
const ipIndex = args.indexOf("--ip");
const tcpPortIndex = args.indexOf("--tcp-port");
const USE_AWAIT = args.includes("--await");
const USE_ATTACH = args.includes("--attach");
const RESTART_APP = args.includes("--restart-app");
const NO_SERVER = args.includes("--no-server");
const REDIRECT_443 = args.includes("--redirect-443");
const ENSURE_FRIDA_SERVER = !args.includes("--no-frida-server");

if (deviceIndex !== -1 && (!DEVICE_ID || DEVICE_ID.startsWith("--"))) {
  console.error(`Missing value for --device (expected something like "127.0.0.1:26656").`);
  const list = Bun.spawnSync(["adb", "devices", "-l"], {
    stdin: "ignore",
    stdout: "inherit",
    stderr: "inherit",
  });
  process.exit(list.exitCode ?? 1);
}

if (USE_AWAIT && USE_ATTACH) {
  console.error(`Use either --attach or --await (not both).`);
  process.exit(1);
}

const SANDBOX_IP = ipIndex !== -1 ? (args[ipIndex + 1] ?? DEFAULT_SANDBOX_IP) : DEFAULT_SANDBOX_IP;
const TCP_PORT =
  tcpPortIndex !== -1 ? Number(args[tcpPortIndex + 1] ?? DEFAULT_TCP_PORT) : DEFAULT_TCP_PORT;

// Paths
const ROOT_DIR = join(import.meta.dir, "..", ".."); // archero-game-server root
const SANDBOX_DIR = join(ROOT_DIR, "sandbox");
const BUILD_DIR = join(ROOT_DIR, "client", "android", "build");
const AGENT_PATH = join(BUILD_DIR, "sandbox_agent.js");

console.log(`
╔═══════════════════════════════════════════════════════════╗
║           🎮 Archero Sandbox Development Mode 🎮          ║
╚═══════════════════════════════════════════════════════════╝
`);

// Step 1: Create sandbox Frida agent
console.log("[1/4] Creating sandbox Frida agent...");

const sandboxAgentCode = `
/**
 * Sandbox Agent - Redirects game client to local sandbox server
 * IP: ${SANDBOX_IP}  TCP: ${TCP_PORT}
 */

var SANDBOX_IP = "${SANDBOX_IP}";
var TCP_PORT = ${TCP_PORT};
var HTTP_PORT = ${DEFAULT_HTTP_PORT};
var REDIRECT_443 = ${REDIRECT_443};

function findExport(name) {
  // Some builds only expose Module.findGlobalExportByName.
  if (Module && typeof Module.findExportByName === "function") {
    return Module.findExportByName(null, name);
  }
  if (Module && typeof Module.findGlobalExportByName === "function") {
    return Module.findGlobalExportByName(name);
  }
  return null;
}

console.log("[Sandbox] Agent loaded - redirecting to " + SANDBOX_IP);
console.log("[Sandbox]   TCP port " + TCP_PORT + " -> " + SANDBOX_IP + ":" + TCP_PORT);
if (REDIRECT_443) console.log("[Sandbox]   HTTPS port 443 -> " + SANDBOX_IP + ":" + HTTP_PORT);

// ============================
// Raw socket redirect (connect)
// ============================

function findAnyExport(names) {
  for (var i = 0; i < names.length; i++) {
    var p = findExport(names[i]);
    if (p) return p;
  }
  return null;
}

var connectPtrs = [];
var connectNames = ["connect", "__connect", "connect64", "__connect64"];
for (var i = 0; i < connectNames.length; i++) {
  var p = findExport(connectNames[i]);
  if (p) connectPtrs.push(p);
}
// De-dupe
var connectPtrStrings = {};
connectPtrs = connectPtrs.filter(function (p) {
  var s = p.toString();
  if (connectPtrStrings[s]) return false;
  connectPtrStrings[s] = true;
  return true;
});

function readIpv4(sockaddr) {
  var b0 = sockaddr.add(4).readU8();
  var b1 = sockaddr.add(5).readU8();
  var b2 = sockaddr.add(6).readU8();
  var b3 = sockaddr.add(7).readU8();
  return b0 + "." + b1 + "." + b2 + "." + b3;
}

function writeIpv4(sockaddr, ip) {
  var parts = ip.split(".");
  if (parts.length !== 4) return false;
  sockaddr.add(4).writeU8(parseInt(parts[0], 10) & 0xff);
  sockaddr.add(5).writeU8(parseInt(parts[1], 10) & 0xff);
  sockaddr.add(6).writeU8(parseInt(parts[2], 10) & 0xff);
  sockaddr.add(7).writeU8(parseInt(parts[3], 10) & 0xff);
  return true;
}

function writePort(sockaddr, port) {
  sockaddr.add(2).writeU8((port >> 8) & 0xff);
  sockaddr.add(3).writeU8(port & 0xff);
}

function writeIpv6V4Mapped(sockaddr, ipV4) {
  var parts = ipV4.split(".");
  if (parts.length !== 4) return false;
  var base = sockaddr.add(8);
  // ::ffff:a.b.c.d
  for (var i = 0; i < 10; i++) base.add(i).writeU8(0);
  base.add(10).writeU8(0xff);
  base.add(11).writeU8(0xff);
  base.add(12).writeU8(parseInt(parts[0], 10) & 0xff);
  base.add(13).writeU8(parseInt(parts[1], 10) & 0xff);
  base.add(14).writeU8(parseInt(parts[2], 10) & 0xff);
  base.add(15).writeU8(parseInt(parts[3], 10) & 0xff);
  return true;
}

function portMap(port) {
  // Redirect game protocol port (12020)
  if (port === TCP_PORT) return TCP_PORT;
  // Redirect 443 to HTTP_PORT (keeps same port for HTTPS API calls)
  if (REDIRECT_443 && port === 443) return HTTP_PORT;
  return null;
}

if (connectPtrs.length > 0) {
  for (var i = 0; i < connectPtrs.length; i++) {
    (function (hookPtr) {
      Interceptor.attach(hookPtr, {
        onEnter: function (args) {
          var sockaddr = args[1];
          if (sockaddr.isNull()) return;
          var family = sockaddr.readU16();

          // AF_INET = 2
          if (family === 2) {
            var port = ((sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8()) & 0xffff;
            var newPort = portMap(port);
            if (newPort == null) return;

            var ip = readIpv4(sockaddr);
            writeIpv4(sockaddr, SANDBOX_IP);
            writePort(sockaddr, newPort);
            console.log("[Sandbox] connect(fd=" + args[0].toInt32() + ") " + ip + ":" + port + " -> " + SANDBOX_IP + ":" + newPort);
          }
          // AF_INET6 = 10
          else if (family === 10) {
            var port6 = ((sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8()) & 0xffff;
            var newPort6 = portMap(port6);
            if (newPort6 == null) return;

            // Best-effort: keep AF_INET6 but rewrite to v4-mapped sandbox IP.
            writeIpv6V4Mapped(sockaddr, SANDBOX_IP);
            writePort(sockaddr, newPort6);
            console.log(
              "[Sandbox] connect6(fd=" +
                args[0].toInt32() +
                ") :" +
                port6 +
                " -> " +
                SANDBOX_IP +
                ":" +
                newPort6
            );
          }
        },
      });
    })(connectPtrs[i]);
  }

  console.log("[Sandbox] Raw socket redirect installed (connect/__connect/connect64/__connect64)");
} else {
  console.log("[Sandbox] WARNING: connect not found");
}

// ============================
// SSL Certificate Pinning Bypass (optional)
// ============================

if (typeof Java !== "undefined" && Java.available) {
  Java.perform(function() {
    try {
      var CertificatePinner = Java.use("okhttp3.CertificatePinner");
      CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function() {
        console.log("[Sandbox] SSL: OkHttp pinning bypassed");
      };
      console.log("[Sandbox] SSL bypass installed");
    } catch (e) {
      // OkHttp not present or different version
    }
  });
} else {
  console.log("[Sandbox] Java not available - SSL bypass skipped");
}

console.log("");
console.log("╔═══════════════════════════════════════════╗");
console.log("║   🎯 Sandbox Agent Active                 ║");
console.log("╠═══════════════════════════════════════════╣");
console.log("║   TCP  -> " + SANDBOX_IP + ":" + TCP_PORT + "              ║");
console.log("╚═══════════════════════════════════════════╝");
console.log("");
`;

// Create build directory using Bun's fs
await mkdir(BUILD_DIR, { recursive: true });

// Write agent using Bun.write
await Bun.write(AGENT_PATH, sandboxAgentCode);
console.log(`   Agent written to: ${AGENT_PATH}`);

// Step 2: Skip frida-compile (raw JS works fine)
console.log("\n[2/4] Agent ready (no compilation needed)...");

// Step 3: Start sandbox server using Bun.spawn (optional)
let serverProcess: ReturnType<typeof Bun.spawn> | null = null;
if (NO_SERVER) {
  console.log("\n[3/4] Skipping sandbox server start (--no-server)...");
} else {
  console.log("\n[3/4] Starting sandbox server...");
  serverProcess = Bun.spawn(["bun", "run", "server.ts"], {
    cwd: SANDBOX_DIR,
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
    env: { ...process.env, FORCE_COLOR: "1" },
  });

  // Wait for server to start
  await Bun.sleep(2000);
}

// Step 4: Launch game with Frida injection using Bun.spawn
console.log("\n[4/4] Launching game client with Frida injection...");

const TARGET = "com.habby.archero";
const fridaArgs = DEVICE_ID
  ? USE_ATTACH
    ? ["-D", DEVICE_ID, "-N", TARGET, "-l", AGENT_PATH]
    : USE_AWAIT
      ? ["-D", DEVICE_ID, "-W", TARGET, "-l", AGENT_PATH]
      : ["-D", DEVICE_ID, "-f", TARGET, "-l", AGENT_PATH]
  : USE_ATTACH
    ? ["-U", "-N", TARGET, "-l", AGENT_PATH]
    : USE_AWAIT
      ? ["-U", "-W", TARGET, "-l", AGENT_PATH]
      : ["-U", "-f", TARGET, "-l", AGENT_PATH];

if (RESTART_APP && DEVICE_ID) {
  const state = Bun.spawnSync(["adb", "-s", DEVICE_ID, "get-state"], {
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  if (state.exitCode !== 0) {
    console.error(`[adb] Device not found: "${DEVICE_ID}"`);
    const list = Bun.spawnSync(["adb", "devices", "-l"], {
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
    });
    console.error(list.stdout.toString() || list.stderr.toString());
    console.error(`Tip: for MuMu this is often like "127.0.0.1:26656" (include the port).`);
    process.exit(1);
  }
}

function runAdb(args: string[]) {
  if (!DEVICE_ID) throw new Error("runAdb requires --device");
  return Bun.spawnSync(["adb", "-s", DEVICE_ID, ...args], {
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
}

async function ensureFridaServer() {
  if (!DEVICE_ID || !ENSURE_FRIDA_SERVER) return;

  // Best-effort root (MuMu is typically rooted; if not, this just fails silently).
  Bun.spawnSync(["adb", "-s", DEVICE_ID, "root"], {
    stdin: "ignore",
    stdout: "ignore",
    stderr: "ignore",
  });

  const pid = runAdb(["shell", "pidof", "frida-server"]);
  if (pid.exitCode === 0 && pid.stdout.toString().trim()) return;

  console.log("   Starting frida-server on device...");
  const start = runAdb([
    "shell",
    "sh",
    "-c",
    "chmod 755 /data/local/tmp/frida-server && nohup /data/local/tmp/frida-server > /data/local/tmp/frida-server.out 2>&1 &",
  ]);
  if (start.exitCode !== 0) {
    console.error(start.stderr.toString() || start.stdout.toString());
  }

  await Bun.sleep(600);
}

console.log(`   Command: frida ${fridaArgs.join(" ")}`);

async function restartViaAdb() {
  if (!DEVICE_ID) return;
  console.log("\n   Restarting app via adb...");
  Bun.spawn(["adb", "-s", DEVICE_ID, "reverse", `tcp:${TCP_PORT}`, `tcp:${TCP_PORT}`], {
    stdin: "ignore",
    stdout: "inherit",
    stderr: "inherit",
  });

  Bun.spawn(["adb", "-s", DEVICE_ID, "shell", "am", "force-stop", TARGET], {
    stdin: "ignore",
    stdout: "inherit",
    stderr: "inherit",
  });

  await Bun.sleep(500);

  Bun.spawn(
    [
      "adb",
      "-s",
      DEVICE_ID,
      "shell",
      "monkey",
      "-p",
      TARGET,
      "-c",
      "android.intent.category.LAUNCHER",
      "1",
    ],
    {
      stdin: "ignore",
      stdout: "inherit",
      stderr: "inherit",
    },
  );
}

if (RESTART_APP && USE_ATTACH && DEVICE_ID) {
  await ensureFridaServer();
  await restartViaAdb();
  await Bun.sleep(1500);
}

if (DEVICE_ID) {
  await ensureFridaServer();
}

const fridaProcess = Bun.spawn(["frida", ...fridaArgs], {
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
  onExit(_proc, exitCode, _signalCode, _error) {
    console.log(`\n[Frida] Process exited with code ${exitCode}`);
    serverProcess?.kill();
    process.exit(exitCode ?? 0);
  },
});

if (USE_AWAIT && RESTART_APP && DEVICE_ID) {
  await ensureFridaServer();
  await restartViaAdb();
}

console.log(`
╔═══════════════════════════════════════════════════════════╗
║   ${NO_SERVER ? "Sandbox server NOT started (--no-server)" : "Sandbox server running"}${NO_SERVER ? "   " : " on localhost:8080 & :12020"}       ║
║   Game client launching with Frida injection...           ║
║                                                           ║
║   Press Ctrl+C to stop                                    ║
╚═══════════════════════════════════════════════════════════╝
`);

// Handle cleanup
process.on("SIGINT", () => {
  console.log("\n[Cleanup] Shutting down...");
  fridaProcess.kill();
  serverProcess?.kill();
  process.exit(0);
});

process.on("SIGTERM", () => {
  fridaProcess.kill();
  serverProcess?.kill();
  process.exit(0);
});

// Keep process alive
await fridaProcess.exited;
