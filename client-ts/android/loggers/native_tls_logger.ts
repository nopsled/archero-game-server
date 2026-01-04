/// <reference path="../../frida.d.ts" />

import { Patcher } from "../patchers/core/socket_patcher";

function hostMatches(rule: string, host: string) {
  const r = rule.toLowerCase();
  const h = host.toLowerCase();
  if (r.startsWith("*.")) return h.endsWith(r.slice(1));
  return h === r;
}

function matchesAny(rules: string[], host: string) {
  for (const rule of rules) if (hostMatches(rule, host)) return true;
  return false;
}

function ptrInfo(pointer: NativePointer | null) {
  return pointer == null ? "null" : pointer.toString();
}

function now() {
  return new Date().toISOString();
}

function findExport(exportName: string): NativePointer | null {
  const moduleApi = Module as unknown as {
    findExportByName?: (moduleName: string | null, exportName: string) => NativePointer | null;
    findGlobalExportByName?: (exportName: string) => NativePointer | null;
  };

  const findExportByName =
    typeof moduleApi.findExportByName === "function" ? moduleApi.findExportByName : null;
  const findGlobalExportByName =
    typeof moduleApi.findGlobalExportByName === "function"
      ? moduleApi.findGlobalExportByName
      : null;

  if (findExportByName) {
    const direct = findExportByName(null, exportName);
    if (direct != null) return direct;

    // Common Android TLS libraries (BoringSSL / Conscrypt / Cronet).
    for (const hint of [
      "libssl.so",
      "libboringssl.so",
      "libconscrypt_jni.so",
      "libconscrypt_openjdk_jni.so",
      "libcronet.so",
      "libgooglecrypto.so",
      "libcrypto.so",
    ]) {
      const p = findExportByName(hint, exportName);
      if (p != null) return p;
    }
  }

  if (findGlobalExportByName) {
    const p = findGlobalExportByName(exportName);
    if (p != null) return p;
  }

  return null;
}

function dump(buf: NativePointer, len: number, maxBytes: number) {
  const n = Math.min(len, maxBytes);
  const bytes = buf.readByteArray(n) as ArrayBuffer | null;
  if (!bytes) return "null";
  const u8 = new Uint8Array(bytes);
  let hex = "";
  let ascii = "";
  for (let i = 0; i < u8.length; i++) {
    hex += u8[i].toString(16).padStart(2, "0");
    const b = u8[i];
    ascii += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
  }
  const suffix = len > n ? `…(+${len - n}b)` : "";
  return `hex=${hex}${suffix} ascii="${ascii}"`;
}

function previewJavaByteArray(byteArray: any, offset: number, length: number, maxBytes: number) {
  const n = Math.min(length, maxBytes);
  let bytes: number[] = [];
  try {
    bytes = Java.array("byte", byteArray) as number[];
  } catch {
    return null;
  }

  let hex = "";
  let ascii = "";
  const end = Math.min(bytes.length, offset + n);
  for (let i = offset; i < end; i++) {
    const b = bytes[i] & 0xff;
    hex += b.toString(16).padStart(2, "0");
    ascii += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
  }
  const actualLen = Math.min(length, Math.max(0, bytes.length - offset));
  const suffix = actualLen > n ? `…(+${actualLen - n}b)` : "";
  return { hex, ascii, suffix, actualLen, previewLen: n };
}

function formatPreview(preview: { hex: string; ascii: string; suffix: string }) {
  return `hex=${preview.hex}${preview.suffix} ascii="${preview.ascii}"`;
}

function findHostInAscii(hostAllowlist: string[], ascii: string): string | null {
  const haystack = ascii.toLowerCase();
  for (const rule of hostAllowlist) {
    const r = rule.toLowerCase();
    const candidate = r.startsWith("*.") ? r.slice(2) : r;
    if (candidate && haystack.includes(candidate)) return candidate;
  }
  return null;
}

function getFdFromJavaFileDescriptor(fdObj: any): number | null {
  if (!fdObj) return null;
  try {
    if (fdObj.descriptor && typeof fdObj.descriptor.value === "number")
      return fdObj.descriptor.value | 0;
  } catch {
    // ignore
  }
  try {
    if (fdObj.fd && typeof fdObj.fd.value === "number") return fdObj.fd.value | 0;
  } catch {
    // ignore
  }
  return null;
}

function enableJavaTlsLogger(hostAllowlist: string[], maxBytes: number) {
  if (typeof Java === "undefined" || !Java.available) {
    console.log("[NativeTlsLogger] Java runtime not available; cannot fallback");
    return false;
  }

  Java.perform(() => {
    const candidates = [
      "com.android.org.conscrypt.NativeCrypto",
      "org.conscrypt.NativeCrypto",
      "com.google.android.gms.org.conscrypt.NativeCrypto",
    ];

    const observedHostByFd = new Map<number, string>();

    let hooked = 0;
    for (const className of candidates) {
      try {
        const NativeCrypto = Java.use(className);
        if (!NativeCrypto.SSL_write || !NativeCrypto.SSL_read) continue;

        console.log(`[NativeTlsLogger] Java TLS logger using ${className}`);

        // Hook all overloads; pick out the (FileDescriptor, byte[], offset, len) dynamically.
        for (const overload of NativeCrypto.SSL_write.overloads) {
          overload.implementation = function (...args: any[]) {
            try {
              const fdObj = args.find((a) => a && a.$className === "java.io.FileDescriptor");
              const fd = getFdFromJavaFileDescriptor(fdObj);

              const byteIdx = args.findIndex((a) => a && a.$className === "[B");
              const byteArray = byteIdx >= 0 ? args[byteIdx] : null;
              const offset = byteIdx >= 0 ? args[byteIdx + 1] | 0 : 0;
              const len = byteIdx >= 0 ? args[byteIdx + 2] | 0 : 0;

              if (byteArray && len > 0) {
                const preview = previewJavaByteArray(byteArray, offset, len, maxBytes);
                if (!preview) return overload.call(this, ...args);

                const trackedHost = fd != null ? Patcher.GetTrackedHost(fd) : null;
                const detectedHost = findHostInAscii(hostAllowlist, preview.ascii);
                const host =
                  trackedHost ??
                  (fd != null ? (observedHostByFd.get(fd) ?? null) : null) ??
                  detectedHost;

                if (!host) return overload.call(this, ...args);
                if (fd != null && detectedHost) observedHostByFd.set(fd, detectedHost);

                console.log(
                  `[${now()}] [NativeTlsLogger] JAVA_SSL_write host="${host}" fd=${fd ?? "?"} len=${len} ${formatPreview(
                    preview
                  )}`
                );
              }
            } catch {
              // ignore
            }
            return overload.call(this, ...args);
          };
        }

        for (const overload of NativeCrypto.SSL_read.overloads) {
          overload.implementation = function (...args: any[]) {
            const fdObj = args.find((a) => a && a.$className === "java.io.FileDescriptor");
            const fd = getFdFromJavaFileDescriptor(fdObj);
            const trackedHost = fd != null ? Patcher.GetTrackedHost(fd) : null;
            const host = trackedHost ?? (fd != null ? (observedHostByFd.get(fd) ?? null) : null);

            const byteIdx = args.findIndex((a) => a && a.$className === "[B");
            const byteArray = byteIdx >= 0 ? args[byteIdx] : null;
            const offset = byteIdx >= 0 ? args[byteIdx + 1] | 0 : 0;

            const rv = overload.call(this, ...args) as number;
            try {
              if (rv > 0 && host && matchesAny(hostAllowlist, host) && byteArray) {
                const preview = previewJavaByteArray(byteArray, offset, rv, maxBytes);
                if (!preview) return rv;
                console.log(
                  `[${now()}] [NativeTlsLogger] JAVA_SSL_read host="${host}" fd=${fd ?? "?"} len=${rv} ${formatPreview(
                    preview
                  )}`
                );
              }
            } catch {
              // ignore
            }
            return rv;
          };
        }

        hooked++;
      } catch {
        // ignore missing candidate
      }
    }

    console.log(`[NativeTlsLogger] Java TLS hooks installed: ${hooked}`);
  });

  return true;
}

export class NativeTlsLogger {
  static enable(hostAllowlist: string[], maxBytes = 1024): boolean {
    console.log(
      `[${now()}] [NativeTlsLogger] enable(hostAllowlist=${hostAllowlist.length}, maxBytes=${maxBytes})`
    );

    const sslSetSniPtr = findExport("SSL_set_tlsext_host_name");
    const sslSet1HostPtr = findExport("SSL_set1_host");
    const sslWritePtr = findExport("SSL_write");
    const sslReadPtr = findExport("SSL_read");
    const sslGetFdPtr = findExport("SSL_get_fd");

    console.log(
      `[NativeTlsLogger] exports SSL_set_tlsext_host_name=${ptrInfo(
        sslSetSniPtr
      )} SSL_set1_host=${ptrInfo(sslSet1HostPtr)} SSL_write=${ptrInfo(
        sslWritePtr
      )} SSL_read=${ptrInfo(sslReadPtr)} SSL_get_fd=${ptrInfo(sslGetFdPtr)}`
    );

    if (sslSetSniPtr == null || sslWritePtr == null || sslReadPtr == null) {
      console.log("[NativeTlsLogger] missing native SSL exports; falling back to Java TLS hooks");
      return enableJavaTlsLogger(hostAllowlist, maxBytes);
    }

    const sslGetFd =
      sslGetFdPtr != null ? new NativeFunction(sslGetFdPtr, "int", ["pointer"]) : null;

    const sslPtrToHost = new Map<string, string>();

    const rememberHost = (sslPtr: NativePointer, host: string, source: string) => {
      if (!host) return;
      if (!matchesAny(hostAllowlist, host)) return;
      sslPtrToHost.set(sslPtr.toString(), host);
      console.log(`[${now()}] [NativeTlsLogger] ${source} host="${host}" ssl=${sslPtr}`);
    };

    Interceptor.attach(sslSetSniPtr, {
      onEnter(args) {
        try {
          const sslPtr = args[0] as NativePointer;
          const namePtr = args[1] as NativePointer;
          const host = namePtr.readCString() ?? "";
          rememberHost(sslPtr, host, "SSL_set_tlsext_host_name");
        } catch {
          // ignore
        }
      },
    });

    if (sslSet1HostPtr != null) {
      Interceptor.attach(sslSet1HostPtr, {
        onEnter(args) {
          try {
            const sslPtr = args[0] as NativePointer;
            const namePtr = args[1] as NativePointer;
            const host = namePtr.readCString() ?? "";
            rememberHost(sslPtr, host, "SSL_set1_host");
          } catch {
            // ignore
          }
        },
      });
    }

    const logWrite = (
      dir: "write" | "read",
      sslPtr: NativePointer,
      buf: NativePointer,
      len: number
    ) => {
      const host = sslPtrToHost.get(sslPtr.toString());
      if (!host) return;
      let fd: number | null = null;
      try {
        fd = sslGetFd ? (sslGetFd(sslPtr) as number) : null;
      } catch {
        fd = null;
      }
      console.log(
        `[${now()}] [NativeTlsLogger] SSL_${dir} host="${host}" fd=${fd ?? "?"} len=${len} ${dump(buf, len, maxBytes)}`
      );
    };

    Interceptor.attach(sslWritePtr, {
      onEnter(args) {
        this.ssl = args[0];
        this.buf = args[1];
        this.len = args[2].toInt32();
        try {
          logWrite(
            "write",
            this.ssl as NativePointer,
            this.buf as NativePointer,
            this.len as number
          );
        } catch {
          // ignore
        }
      },
    });

    Interceptor.attach(sslReadPtr, {
      onEnter(args) {
        this.ssl = args[0];
        this.buf = args[1];
        this.len = args[2].toInt32();
      },
      onLeave(retval) {
        try {
          const n = retval.toInt32();
          if (n > 0) {
            logWrite("read", this.ssl as NativePointer, this.buf as NativePointer, n);
          }
        } catch {
          // ignore
        }
      },
    });

    return true;
  }
}
