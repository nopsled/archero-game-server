📦
6301 /android/patchers/port12020_lite.js
✄
// android/patchers/port12020_lite.ts
var SANDBOX_IP = "10.0.1.22";
var GAME_PORT = 12020;
var LOG_ALL_PORTS = true;
console.log("[socket-debug] Comprehensive socket logger loaded");
function findExport(name) {
  const moduleApi = Module;
  if (typeof moduleApi.findExportByName === "function") {
    return moduleApi.findExportByName(null, name);
  }
  if (typeof moduleApi.findGlobalExportByName === "function") {
    return moduleApi.findGlobalExportByName(name);
  }
  return null;
}
var socketInfo = /* @__PURE__ */ new Map();
var socketPtr = findExport("socket");
if (socketPtr) {
  Interceptor.attach(socketPtr, {
    onEnter(args) {
      this.domain = args[0].toInt32();
      this.sockType = args[1].toInt32();
    },
    onLeave(retval) {
      const fd = retval.toInt32();
      if (fd >= 0 && this.domain === 2) {
        const typeStr = this.sockType === 1 ? "TCP" : this.sockType === 2 ? "UDP" : `type=${this.sockType}`;
        socketInfo.set(fd, { type: typeStr });
        console.log(`[socket-debug] socket() -> fd=${fd} ${typeStr}`);
      }
    }
  });
  console.log("[socket-debug] socket() hook installed");
}
function parseSockaddr(sockaddr) {
  if (sockaddr.isNull())
    return null;
  const family = sockaddr.readU16();
  if (family !== 2)
    return null;
  const port = (sockaddr.add(2).readU8() << 8 | sockaddr.add(3).readU8()) & 65535;
  const ip = [4, 5, 6, 7].map((i) => sockaddr.add(i).readU8()).join(".");
  return { family, port, ip };
}
var connectPtr = findExport("connect");
if (connectPtr) {
  Interceptor.attach(connectPtr, {
    onEnter(args) {
      const fd = args[0].toInt32();
      const addr = parseSockaddr(args[1]);
      if (!addr)
        return;
      const info = socketInfo.get(fd) || { type: "unknown" };
      if (LOG_ALL_PORTS || addr.port === GAME_PORT) {
        console.log(`[socket-debug] connect() fd=${fd} ${info.type} -> ${addr.ip}:${addr.port}`);
      }
      if (addr.port === GAME_PORT) {
        const parts = SANDBOX_IP.split(".");
        for (let i = 0; i < 4; i++) {
          args[1].add(4 + i).writeU8(parseInt(parts[i], 10) & 255);
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
      }
    }
  });
  console.log("[socket-debug] connect() hook installed");
}
var sendPtr = findExport("send");
if (sendPtr) {
  Interceptor.attach(sendPtr, {
    onEnter(args) {
      const fd = args[0].toInt32();
      const info = socketInfo.get(fd);
      if (!info?.redirected && !LOG_ALL_PORTS)
        return;
      const len = args[2].toInt32();
      const buf = args[1];
      const preview = len > 0 ? buf.readByteArray(Math.min(len, 32)) : null;
      const hex = preview ? Array.from(new Uint8Array(preview)).map((b) => b.toString(16).padStart(2, "0")).join("") : "";
      console.log(`[socket-debug] send() fd=${fd} len=${len} hex=${hex}${len > 32 ? "..." : ""}`);
    }
  });
  console.log("[socket-debug] send() hook installed");
}
var recvPtr = findExport("recv");
if (recvPtr) {
  Interceptor.attach(recvPtr, {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.buf = args[1];
      const info = socketInfo.get(this.fd);
      this.track = info?.redirected || LOG_ALL_PORTS;
    },
    onLeave(retval) {
      if (!this.track)
        return;
      const len = retval.toInt32();
      if (len <= 0)
        return;
      const preview = this.buf.readByteArray(Math.min(len, 32));
      const hex = preview ? Array.from(new Uint8Array(preview)).map((b) => b.toString(16).padStart(2, "0")).join("") : "";
      console.log(`[socket-debug] recv() fd=${this.fd} len=${len} hex=${hex}${len > 32 ? "..." : ""}`);
    }
  });
  console.log("[socket-debug] recv() hook installed");
}
var sendtoPtr = findExport("sendto");
if (sendtoPtr) {
  Interceptor.attach(sendtoPtr, {
    onEnter(args) {
      const fd = args[0].toInt32();
      const len = args[2].toInt32();
      const addr = parseSockaddr(args[4]);
      if (addr && (LOG_ALL_PORTS || addr.port === GAME_PORT)) {
        const buf = args[1];
        const preview = len > 0 ? buf.readByteArray(Math.min(len, 32)) : null;
        const hex = preview ? Array.from(new Uint8Array(preview)).map((b) => b.toString(16).padStart(2, "0")).join("") : "";
        console.log(`[socket-debug] sendto() fd=${fd} -> ${addr.ip}:${addr.port} len=${len} hex=${hex}`);
        if (addr.port === GAME_PORT) {
          const parts = SANDBOX_IP.split(".");
          for (let i = 0; i < 4; i++) {
            args[4].add(4 + i).writeU8(parseInt(parts[i], 10) & 255);
          }
          console.log(`[socket-debug] REDIRECT sendto: -> ${SANDBOX_IP}:${GAME_PORT}`);
        }
      }
    }
  });
  console.log("[socket-debug] sendto() hook installed");
}
var recvfromPtr = findExport("recvfrom");
if (recvfromPtr) {
  Interceptor.attach(recvfromPtr, {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.buf = args[1];
      this.addrPtr = args[4];
    },
    onLeave(retval) {
      const len = retval.toInt32();
      if (len <= 0)
        return;
      const addr = parseSockaddr(this.addrPtr);
      if (addr && (LOG_ALL_PORTS || addr.port === GAME_PORT)) {
        const preview = this.buf.readByteArray(Math.min(len, 32));
        const hex = preview ? Array.from(new Uint8Array(preview)).map((b) => b.toString(16).padStart(2, "0")).join("") : "";
        console.log(`[socket-debug] recvfrom() fd=${this.fd} <- ${addr.ip}:${addr.port} len=${len} hex=${hex}`);
      }
    }
  });
  console.log("[socket-debug] recvfrom() hook installed");
}
var closePtr = findExport("close");
if (closePtr) {
  Interceptor.attach(closePtr, {
    onEnter(args) {
      const fd = args[0].toInt32();
      const info = socketInfo.get(fd);
      if (info) {
        console.log(`[socket-debug] close() fd=${fd} ${info.type} port=${info.port || "N/A"}`);
        socketInfo.delete(fd);
      }
    }
  });
  console.log("[socket-debug] close() hook installed");
}
console.log("[socket-debug] All hooks installed. Waiting for socket activity...");
console.log("[socket-debug] LOG_ALL_PORTS=" + LOG_ALL_PORTS);
