/// <reference path="../../frida.d.ts" />

/**
 * Comprehensive Socket Logger for Port 12020
 * 
 * Hooks socket creation, connect, send, recv, sendto, recvfrom
 * to discover how the game uses port 12020 (TCP or UDP).
 */

const SANDBOX_IP = "10.0.1.22";
const GAME_PORT = 12020;
const LOG_ALL_PORTS = true; // Set to true to log ALL connections initially

console.log("[socket-debug] Comprehensive socket logger loaded");

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

// Track socket types: fd -> { type: 'tcp'|'udp', port?: number }
const socketInfo = new Map<number, { type: string; port?: number; redirected?: boolean }>();

// Hook socket() to track what type of sockets are created
const socketPtr = findExport("socket");
if (socketPtr) {
  Interceptor.attach(socketPtr, {
    onEnter(args) {
      this.domain = args[0].toInt32();  // AF_INET = 2
      this.sockType = args[1].toInt32(); // SOCK_STREAM=1, SOCK_DGRAM=2
    },
    onLeave(retval) {
      const fd = retval.toInt32();
      if (fd >= 0 && this.domain === 2) { // AF_INET
        const typeStr = this.sockType === 1 ? 'TCP' : this.sockType === 2 ? 'UDP' : `type=${this.sockType}`;
        socketInfo.set(fd, { type: typeStr });
        console.log(`[socket-debug] socket() -> fd=${fd} ${typeStr}`);
      }
    }
  });
  console.log("[socket-debug] socket() hook installed");
}

// Helper to parse sockaddr_in
function parseSockaddr(sockaddr: NativePointer): { family: number; port: number; ip: string } | null {
  if (sockaddr.isNull()) return null;
  const family = sockaddr.readU16();
  if (family !== 2) return null; // Only AF_INET
  const port = ((sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8()) & 0xffff;
  const ip = [4,5,6,7].map(i => sockaddr.add(i).readU8()).join(".");
  return { family, port, ip };
}

// Hook connect() for TCP connections
const connectPtr = findExport("connect");
if (connectPtr) {
  Interceptor.attach(connectPtr, {
    onEnter(args) {
      const fd = args[0].toInt32();
      const addr = parseSockaddr(args[1]);
      if (!addr) return;
      
      const info = socketInfo.get(fd) || { type: 'unknown' };
      
      if (LOG_ALL_PORTS || addr.port === GAME_PORT) {
        console.log(`[socket-debug] connect() fd=${fd} ${info.type} -> ${addr.ip}:${addr.port}`);
      }
      
      // Redirect port 12020
      if (addr.port === GAME_PORT) {
        const parts = SANDBOX_IP.split(".");
        for (let i = 0; i < 4; i++) {
          args[1].add(4 + i).writeU8(parseInt(parts[i], 10) & 0xff);
        }
        info.port = addr.port;
        info.redirected = true;
        socketInfo.set(fd, info);
        console.log(`[socket-debug] REDIRECT: ${addr.ip}:${addr.port} -> ${SANDBOX_IP}:${GAME_PORT}`);
      }
    },
    onLeave(retval) {
      const result = retval.toInt32();
      if (result !== 0) {
        // console.log(`[socket-debug] connect() returned ${result}`);
      }
    }
  });
  console.log("[socket-debug] connect() hook installed");
}

// Hook send() for TCP
const sendPtr = findExport("send");
if (sendPtr) {
  Interceptor.attach(sendPtr, {
    onEnter(args) {
      const fd = args[0].toInt32();
      const info = socketInfo.get(fd);
      if (!info?.redirected && !LOG_ALL_PORTS) return;
      
      const len = args[2].toInt32();
      const buf = args[1];
      const preview = len > 0 ? buf.readByteArray(Math.min(len, 32)) : null;
      const hex = preview ? Array.from(new Uint8Array(preview)).map(b => b.toString(16).padStart(2, '0')).join('') : '';
      
      console.log(`[socket-debug] send() fd=${fd} len=${len} hex=${hex}${len > 32 ? "..." : ""}`);
    }
  });
  console.log("[socket-debug] send() hook installed");
}

// Hook recv() for TCP
const recvPtr = findExport("recv");
if (recvPtr) {
  Interceptor.attach(recvPtr, {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.buf = args[1];
      const info = socketInfo.get(this.fd);
      this.track = info?.redirected || LOG_ALL_PORTS;
    },
    onLeave(retval) {
      if (!this.track) return;
      const len = retval.toInt32();
      if (len <= 0) return;
      
      const preview = this.buf.readByteArray(Math.min(len, 32));
      const hex = preview ? Array.from(new Uint8Array(preview)).map(b => b.toString(16).padStart(2, '0')).join('') : '';
      console.log(`[socket-debug] recv() fd=${this.fd} len=${len} hex=${hex}${len > 32 ? "..." : ""}`);
    }
  });
  console.log("[socket-debug] recv() hook installed");
}

// Hook sendto() for UDP
const sendtoPtr = findExport("sendto");
if (sendtoPtr) {
  Interceptor.attach(sendtoPtr, {
    onEnter(args) {
      const fd = args[0].toInt32();
      const len = args[2].toInt32();
      const addr = parseSockaddr(args[4]);
      
      if (addr && (LOG_ALL_PORTS || addr.port === GAME_PORT)) {
        const buf = args[1];
        const preview = len > 0 ? buf.readByteArray(Math.min(len, 32)) : null;
        const hex = preview ? Array.from(new Uint8Array(preview)).map(b => b.toString(16).padStart(2, '0')).join('') : '';
        console.log(`[socket-debug] sendto() fd=${fd} -> ${addr.ip}:${addr.port} len=${len} hex=${hex}`);
        
        // Redirect UDP port 12020
        if (addr.port === GAME_PORT) {
          const parts = SANDBOX_IP.split(".");
          for (let i = 0; i < 4; i++) {
            args[4].add(4 + i).writeU8(parseInt(parts[i], 10) & 0xff);
          }
          console.log(`[socket-debug] REDIRECT sendto: -> ${SANDBOX_IP}:${GAME_PORT}`);
        }
      }
    }
  });
  console.log("[socket-debug] sendto() hook installed");
}

// Hook recvfrom() for UDP
const recvfromPtr = findExport("recvfrom");
if (recvfromPtr) {
  Interceptor.attach(recvfromPtr, {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.buf = args[1];
      this.addrPtr = args[4];
    },
    onLeave(retval) {
      const len = retval.toInt32();
      if (len <= 0) return;
      
      const addr = parseSockaddr(this.addrPtr);
      if (addr && (LOG_ALL_PORTS || addr.port === GAME_PORT)) {
        const preview = this.buf.readByteArray(Math.min(len, 32));
        const hex = preview ? Array.from(new Uint8Array(preview)).map(b => b.toString(16).padStart(2, '0')).join('') : '';
        console.log(`[socket-debug] recvfrom() fd=${this.fd} <- ${addr.ip}:${addr.port} len=${len} hex=${hex}`);
      }
    }
  });
  console.log("[socket-debug] recvfrom() hook installed");
}

// Hook close() to clean up tracking
const closePtr = findExport("close");
if (closePtr) {
  Interceptor.attach(closePtr, {
    onEnter(args) {
      const fd = args[0].toInt32();
      const info = socketInfo.get(fd);
      if (info) {
        console.log(`[socket-debug] close() fd=${fd} ${info.type} port=${info.port || 'N/A'}`);
        socketInfo.delete(fd);
      }
    }
  });
  console.log("[socket-debug] close() hook installed");
}

console.log("[socket-debug] All hooks installed. Waiting for socket activity...");
console.log("[socket-debug] LOG_ALL_PORTS=" + LOG_ALL_PORTS);
