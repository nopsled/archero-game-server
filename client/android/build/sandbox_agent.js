
/**
 * Sandbox Agent - Redirects game client to local sandbox server
 * IP: 10.0.1.22  TCP: 12020
 */

var SANDBOX_IP = "10.0.1.22";
var TCP_PORT = 12020;
var HTTP_PORT = 443;
var REDIRECT_443 = true;

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
