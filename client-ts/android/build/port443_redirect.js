📦
4835 /android/patchers/port443_redirect.js
✄
// android/patchers/port443_redirect.ts
var SANDBOX_IP = "10.0.1.22";
var TARGET_PORT = 443;
console.log("[443-redirect] Agent loaded - redirecting port 443 to " + SANDBOX_IP);
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
var redirectedFds = /* @__PURE__ */ new Set();
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
      if (addr.port === TARGET_PORT) {
        const parts = SANDBOX_IP.split(".");
        for (let i = 0; i < 4; i++) {
          args[1].add(4 + i).writeU8(parseInt(parts[i], 10) & 255);
        }
        redirectedFds.add(fd);
        console.log(`[443-redirect] REDIRECT: ${addr.ip}:${addr.port} -> ${SANDBOX_IP}:${TARGET_PORT} (fd=${fd})`);
      }
    }
  });
  console.log("[443-redirect] connect() hook installed");
}
var sendPtr = findExport("send");
if (sendPtr) {
  Interceptor.attach(sendPtr, {
    onEnter(args) {
      const fd = args[0].toInt32();
      if (!redirectedFds.has(fd))
        return;
      const len = args[2].toInt32();
      const buf = args[1];
      const preview = len > 0 ? buf.readByteArray(Math.min(len, 32)) : null;
      const hex = preview ? Array.from(new Uint8Array(preview)).map((b) => b.toString(16).padStart(2, "0")).join("") : "";
      console.log(`[443-redirect] SEND fd=${fd} len=${len} hex=${hex}${len > 32 ? "..." : ""}`);
    }
  });
  console.log("[443-redirect] send() hook installed");
}
var recvPtr = findExport("recv");
if (recvPtr) {
  Interceptor.attach(recvPtr, {
    onEnter(args) {
      this.fd = args[0].toInt32();
      this.buf = args[1];
      this.tracked = redirectedFds.has(this.fd);
    },
    onLeave(retval) {
      if (!this.tracked)
        return;
      const len = retval.toInt32();
      if (len <= 0)
        return;
      const preview = this.buf.readByteArray(Math.min(len, 32));
      const hex = preview ? Array.from(new Uint8Array(preview)).map((b) => b.toString(16).padStart(2, "0")).join("") : "";
      console.log(`[443-redirect] RECV fd=${this.fd} len=${len} hex=${hex}${len > 32 ? "..." : ""}`);
    }
  });
  console.log("[443-redirect] recv() hook installed");
}
var closePtr = findExport("close");
if (closePtr) {
  Interceptor.attach(closePtr, {
    onEnter(args) {
      const fd = args[0].toInt32();
      if (redirectedFds.has(fd)) {
        console.log(`[443-redirect] CLOSE fd=${fd}`);
        redirectedFds.delete(fd);
      }
    }
  });
}
var sslGetVerifyResult = findExport("SSL_get_verify_result");
if (sslGetVerifyResult) {
  Interceptor.replace(sslGetVerifyResult, new NativeCallback(function(ssl) {
    return 0;
  }, "long", ["pointer"]));
  console.log("[443-redirect] SSL_get_verify_result bypassed");
}
var sslCtxSetVerify = findExport("SSL_CTX_set_verify");
if (sslCtxSetVerify) {
  Interceptor.replace(sslCtxSetVerify, new NativeCallback(function(ctx, mode, callback) {
    const original = new NativeFunction(sslCtxSetVerify, "void", ["pointer", "int", "pointer"]);
    original(ctx, 0, NULL);
  }, "void", ["pointer", "int", "pointer"]));
  console.log("[443-redirect] SSL_CTX_set_verify bypassed");
}
var sslSetVerify = findExport("SSL_set_verify");
if (sslSetVerify) {
  Interceptor.replace(sslSetVerify, new NativeCallback(function(ssl, mode, callback) {
    const original = new NativeFunction(sslSetVerify, "void", ["pointer", "int", "pointer"]);
    original(ssl, 0, NULL);
  }, "void", ["pointer", "int", "pointer"]));
  console.log("[443-redirect] SSL_set_verify bypassed");
}
var x509VerifyCert = findExport("X509_verify_cert");
if (x509VerifyCert) {
  Interceptor.replace(x509VerifyCert, new NativeCallback(function(ctx) {
    return 1;
  }, "int", ["pointer"]));
  console.log("[443-redirect] X509_verify_cert bypassed");
}
var sslCtxSetCustomVerify = findExport("SSL_CTX_set_custom_verify");
if (sslCtxSetCustomVerify) {
  Interceptor.replace(sslCtxSetCustomVerify, new NativeCallback(function(ctx, mode, callback) {
  }, "void", ["pointer", "int", "pointer"]));
  console.log("[443-redirect] SSL_CTX_set_custom_verify bypassed");
}
console.log("[443-redirect] All hooks installed. Waiting for connections...");
