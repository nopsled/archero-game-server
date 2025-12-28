#!/usr/bin/env bun

/**
 * Sandbox Development Launcher
 *
 * This script:
 * 1. Starts the sandbox server
 * 2. Builds the Frida agent with socket patching for sandbox
 * 3. Launches the game client with Frida injection
 *
 * Usage: bun run launch [--device <id>]
 */

import { mkdir } from "node:fs/promises";
import { join } from "node:path";

// Configuration - using 127.0.0.1 with adb reverse for reliable connectivity
// Run: adb reverse tcp:12020 tcp:12020 && adb reverse tcp:8080 tcp:8080
const SANDBOX_IP = "127.0.0.1";
const TCP_PORT = 12020;
const HTTP_PORT = 8080;

// Parse arguments
const args = Bun.argv;
const deviceIndex = args.indexOf("--device");
const DEVICE_ID = deviceIndex !== -1 ? args[deviceIndex + 1] : undefined;

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
 * IP: ${SANDBOX_IP}  TCP: ${TCP_PORT}  HTTP: ${HTTP_PORT}
 */

var SANDBOX_IP = "${SANDBOX_IP}";
var TCP_PORT = ${TCP_PORT};
var HTTP_PORT = ${HTTP_PORT};

// Game server hosts to redirect
var GAME_HOSTS = [
  "*.habby.com",
  "*.habby.io", 
  "*.archero.com",
  "*habby*",
];

function hostMatches(rule, host) {
  var r = rule.toLowerCase();
  var h = host.toLowerCase();
  if (r.startsWith("*.")) {
    return h.endsWith(r.slice(1));
  }
  if (r.indexOf("*") !== -1) {
    var parts = r.split("*");
    if (parts.length === 2) {
      return h.indexOf(parts[0]) !== -1 && h.indexOf(parts[1]) !== -1;
    }
    return h.indexOf(r.replace(/\\*/g, "")) !== -1;
  }
  return h === r;
}

function shouldRedirect(host) {
  for (var i = 0; i < GAME_HOSTS.length; i++) {
    if (hostMatches(GAME_HOSTS[i], host)) return true;
  }
  return false;
}

console.log("[Sandbox] Agent loaded - redirecting to " + SANDBOX_IP + ":" + TCP_PORT);

// ============================
// DNS Redirect (getaddrinfo) using attach
// ============================

var getaddrinfoPtr = Module.findExportByName(null, "getaddrinfo");
if (getaddrinfoPtr) {
  Interceptor.attach(getaddrinfoPtr, {
    onEnter: function(args) {
      var hostname = args[0].readUtf8String() || "";
      if (shouldRedirect(hostname)) {
        console.log("[Sandbox] DNS: " + hostname + " -> " + SANDBOX_IP);
        // Overwrite the hostname pointer with our IP
        this.newName = Memory.allocUtf8String(SANDBOX_IP);
        args[0] = this.newName;
      }
    }
  });
  console.log("[Sandbox] DNS redirect installed");
} else {
  console.log("[Sandbox] WARNING: getaddrinfo not found");
}

// ============================
// Port Redirect (connect)
// ============================

var connectPtr = Module.findExportByName(null, "connect");
if (connectPtr) {
  Interceptor.attach(connectPtr, {
    onEnter: function(args) {
      var sockaddr = args[1];
      var family = sockaddr.readU16();
      
      // AF_INET = 2
      if (family === 2) {
        var port = ((sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8()) & 0xFFFF;
        var b0 = sockaddr.add(4).readU8();
        var b1 = sockaddr.add(5).readU8();
        var b2 = sockaddr.add(6).readU8();
        var b3 = sockaddr.add(7).readU8();
        var ip = b0 + "." + b1 + "." + b2 + "." + b3;
        
        // Check if this is a game server connection (any habby IP or targeting our sandbox IP)
        var isGameServer = (port === 443 || port === 12020 || port === 12021 || port === 80);
        
        if (isGameServer) {
          // Redirect to sandbox TCP port
          if (port === 443 || port === 12020 || port === 12021) {
            // Rewrite IP to sandbox IP
            var ipParts = SANDBOX_IP.split(".");
            sockaddr.add(4).writeU8(parseInt(ipParts[0]));
            sockaddr.add(5).writeU8(parseInt(ipParts[1]));
            sockaddr.add(6).writeU8(parseInt(ipParts[2]));
            sockaddr.add(7).writeU8(parseInt(ipParts[3]));
            // Rewrite port to sandbox TCP port
            sockaddr.add(2).writeU8((TCP_PORT >> 8) & 0xFF);
            sockaddr.add(3).writeU8(TCP_PORT & 0xFF);
            console.log("[Sandbox] connect: " + ip + ":" + port + " -> " + SANDBOX_IP + ":" + TCP_PORT);
          }
          // HTTP ports -> sandbox HTTP
          else if (port === 80) {
            var ipParts = SANDBOX_IP.split(".");
            sockaddr.add(4).writeU8(parseInt(ipParts[0]));
            sockaddr.add(5).writeU8(parseInt(ipParts[1]));
            sockaddr.add(6).writeU8(parseInt(ipParts[2]));
            sockaddr.add(7).writeU8(parseInt(ipParts[3]));
            sockaddr.add(2).writeU8((HTTP_PORT >> 8) & 0xFF);
            sockaddr.add(3).writeU8(HTTP_PORT & 0xFF);
            console.log("[Sandbox] connect: " + ip + ":" + port + " -> " + SANDBOX_IP + ":" + HTTP_PORT);
          }
        }
      }
    }
  });
  
  console.log("[Sandbox] Port redirect installed");
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
console.log("║   HTTP -> " + SANDBOX_IP + ":" + HTTP_PORT + "               ║");
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

// Step 3: Start sandbox server using Bun.spawn
console.log("\n[3/4] Starting sandbox server...");
const serverProcess = Bun.spawn(["bun", "run", "server.ts"], {
  cwd: SANDBOX_DIR,
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
  env: { ...process.env, FORCE_COLOR: "1" },
});

// Wait for server to start
await Bun.sleep(2000);

// Step 4: Launch game with Frida injection using Bun.spawn
console.log("\n[4/4] Launching game client with Frida injection...");

const fridaArgs = DEVICE_ID
  ? ["-D", DEVICE_ID, "-f", "com.habby.archero", "-l", AGENT_PATH]
  : ["-U", "-f", "com.habby.archero", "-l", AGENT_PATH];

console.log(`   Command: frida ${fridaArgs.join(" ")}`);

const fridaProcess = Bun.spawn(["frida", ...fridaArgs], {
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
  onExit(_proc, exitCode, _signalCode, _error) {
    console.log(`\n[Frida] Process exited with code ${exitCode}`);
    serverProcess.kill();
    process.exit(exitCode ?? 0);
  },
});

console.log(`
╔═══════════════════════════════════════════════════════════╗
║   Sandbox server running on localhost:8080 & :12020       ║
║   Game client launching with Frida injection...           ║
║                                                           ║
║   Press Ctrl+C to stop                                    ║
╚═══════════════════════════════════════════════════════════╝
`);

// Handle cleanup
process.on("SIGINT", () => {
  console.log("\n[Cleanup] Shutting down...");
  fridaProcess.kill();
  serverProcess.kill();
  process.exit(0);
});

process.on("SIGTERM", () => {
  fridaProcess.kill();
  serverProcess.kill();
  process.exit(0);
});

// Keep process alive
await fridaProcess.exited;
