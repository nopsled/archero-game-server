/// <reference path="../../frida.d.ts" />

/**
 * Port 443 Redirect Agent with Comprehensive SSL Pinning Bypass
 *
 * Combines NativeTlsBypass + FridaMultipleUnpinning + connect redirect.
 */

import { NativeTlsBypass } from "./native_tls_bypass";
import { FridaMultipleUnpinning } from "./multiple_unpinning";

const SANDBOX_IP = "10.0.1.22";
const TARGET_PORT = 443;
const DEBUG = true;

console.log("[ssl-bypass] Agent loaded - redirecting port 443 to " + SANDBOX_IP);

// ========== ENABLE EXISTING BYPASS MODULES ==========
console.log("[ssl-bypass] Loading NativeTlsBypass...");
NativeTlsBypass.enable(DEBUG);

console.log("[ssl-bypass] Loading FridaMultipleUnpinning...");
setTimeout(() => {
  try {
    FridaMultipleUnpinning.bypass(DEBUG);
  } catch (e) {
    console.log("[ssl-bypass] FridaMultipleUnpinning deferred load: " + e);
  }
}, 1000);

// ========== SOCKET HELPERS ==========
type NativePointerOrNull = NativePointer | null;

function findExport(name: string): NativePointerOrNull {
  const moduleApi = Module as unknown as {
    findExportByName?: (moduleName: string | null, exportName: string) => NativePointerOrNull;
    findGlobalExportByName?: (exportName: string) => NativePointerOrNull;
  };
  if (typeof moduleApi.findExportByName === "function") {
    return moduleApi.findExportByName(null, name);
  }
  if (typeof moduleApi.findGlobalExportByName === "function") {
    return moduleApi.findGlobalExportByName(name);
  }
  return null;
}

// Track redirected sockets
const redirectedFds = new Set<number>();

// Helper to parse sockaddr_in
function parseSockaddr(
  sockaddr: NativePointer
): { family: number; port: number; ip: string } | null {
  if (sockaddr.isNull()) return null;
  const family = sockaddr.readU16();
  if (family !== 2) return null; // Only AF_INET
  const port = ((sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8()) & 0xffff;
  const ip = [4, 5, 6, 7].map((i) => sockaddr.add(i).readU8()).join(".");
  return { family, port, ip };
}

// ========== SOCKET HOOKS ==========

// Hook connect() to redirect port 443
const connectPtr = findExport("connect");
if (connectPtr) {
  Interceptor.attach(connectPtr, {
    onEnter(args) {
      const fd = args[0].toInt32();
      const addr = parseSockaddr(args[1]);
      if (!addr) return;

      if (addr.port === TARGET_PORT) {
        // Redirect to sandbox
        const parts = SANDBOX_IP.split(".");
        for (let i = 0; i < 4; i++) {
          args[1].add(4 + i).writeU8(parseInt(parts[i], 10) & 0xff);
        }
        redirectedFds.add(fd);
        console.log(
          `[ssl-bypass] REDIRECT: ${addr.ip}:${addr.port} -> ${SANDBOX_IP}:${TARGET_PORT} (fd=${fd})`
        );
      }
    },
  });
  console.log("[ssl-bypass] connect() hook installed");
}

// Hook send to log outgoing data on redirected sockets
const sendPtr = findExport("send");
if (sendPtr) {
  Interceptor.attach(sendPtr, {
    onEnter(args) {
      const fd = args[0].toInt32();
      if (!redirectedFds.has(fd)) return;

      const len = args[2].toInt32();
      const buf = args[1];
      const preview = len > 0 ? buf.readByteArray(Math.min(len, 32)) : null;
      const hex = preview
        ? Array.from(new Uint8Array(preview))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("")
        : "";

      console.log(`[ssl-bypass] SEND fd=${fd} len=${len} hex=${hex}${len > 32 ? "..." : ""}`);
    },
  });
  console.log("[ssl-bypass] send() hook installed");
}

// Hook recv to log incoming data on redirected sockets
const recvPtr = findExport("recv");
if (recvPtr) {
  Interceptor.attach(recvPtr, {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.buf = args[1];
      this.tracked = redirectedFds.has(this.fd);
    },
    onLeave(retval) {
      if (!this.tracked) return;
      const len = retval.toInt32();
      if (len <= 0) return;

      const preview = this.buf.readByteArray(Math.min(len, 32));
      const hex = preview
        ? Array.from(new Uint8Array(preview))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("")
        : "";
      console.log(`[ssl-bypass] RECV fd=${this.fd} len=${len} hex=${hex}${len > 32 ? "..." : ""}`);
    },
  });
  console.log("[ssl-bypass] recv() hook installed");
}

// Hook close to clean up tracking
const closePtr = findExport("close");
if (closePtr) {
  Interceptor.attach(closePtr, {
    onEnter(args) {
      const fd = args[0].toInt32();
      if (redirectedFds.has(fd)) {
        console.log(`[ssl-bypass] CLOSE fd=${fd}`);
        redirectedFds.delete(fd);
      }
    },
  });
}

// ========== SNI HOSTNAME LOGGING ==========
const sslSetTlsextHostName = findExport("SSL_set_tlsext_host_name");
if (sslSetTlsextHostName) {
  Interceptor.attach(sslSetTlsextHostName, {
    onEnter(args) {
      const hostname = args[1].readCString();
      console.log(`[ssl-bypass] SNI hostname: ${hostname}`);
    },
  });
  console.log("[ssl-bypass] ✓ SSL_set_tlsext_host_name hooked");
}

console.log("[ssl-bypass] All hooks installed. Waiting for connections...");
