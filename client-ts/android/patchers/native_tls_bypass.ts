/// <reference path="../../frida.d.ts" />

type NativePointerOrNull = NativePointer | null;

function findExport(exportName: string): NativePointerOrNull {
  const moduleApi = Module as unknown as {
    findExportByName?: (moduleName: string | null, exportName: string) => NativePointerOrNull;
    findGlobalExportByName?: (exportName: string) => NativePointerOrNull;
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

    // Common Android TLS libraries
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

  if (typeof moduleApi.findGlobalExportByName === "function") {
    return moduleApi.findGlobalExportByName(exportName);
  }
  if (typeof moduleApi.findExportByName === "function") {
    return moduleApi.findExportByName(null, exportName);
  }
  return null;
}

function ptrInfo(pointer: NativePointerOrNull) {
  return pointer == null ? "null" : pointer.toString();
}

export class NativeTlsBypass {
  // Keep callback alive to prevent GC
  private static certVerifyCallback: any = null;

  static enable(isDebugging = false) {
    const sslGetVerifyResult = findExport("SSL_get_verify_result");
    const x509VerifyCert = findExport("X509_verify_cert");
    const sslSetVerify = findExport("SSL_set_verify");
    const sslCtxSetVerify = findExport("SSL_CTX_set_verify");
    const sslSetCustomVerify = findExport("SSL_set_custom_verify");
    const sslCtxSetCustomVerify = findExport("SSL_CTX_set_custom_verify");

    // Initialize callback once
    if (!NativeTlsBypass.certVerifyCallback) {
      // int (*cb)(X509_STORE_CTX *, void *)
      NativeTlsBypass.certVerifyCallback = new NativeCallback((_ctx: any, _arg: any) => {
        if (isDebugging) console.log(`${ts()} [NativeTlsBypass] Custom cert verify callback -> OK`);
        return 1; // Success
      }, 'int', ['pointer', 'pointer']);
    }
    const certVerifyCallback = NativeTlsBypass.certVerifyCallback!;

    if (isDebugging) {
      console.log(
        `[NativeTlsBypass] exports SSL_get_verify_result=${ptrInfo(
          sslGetVerifyResult
        )} X509_verify_cert=${ptrInfo(x509VerifyCert)} SSL_set_verify=${ptrInfo(
          sslSetVerify
        )} SSL_CTX_set_verify=${ptrInfo(sslCtxSetVerify)} SSL_set_custom_verify=${ptrInfo(
          sslSetCustomVerify
        )} SSL_CTX_set_custom_verify=${ptrInfo(sslCtxSetCustomVerify)}`
      );
    }

    if (sslGetVerifyResult != null) {
      Interceptor.replace(
        sslGetVerifyResult,
        new NativeCallback(
          (_ssl) => { return 0; },
          "long",
          ["pointer"]
        )
      );
    }

    if (x509VerifyCert != null) {
      Interceptor.replace(
        x509VerifyCert,
        new NativeCallback(
          (_ctx) => { return 1; },
          "int",
          ["pointer"]
        )
      );
    }

    const disableVerifyMode = (name: string, target: NativePointerOrNull) => {
      if (target == null) return;
      Interceptor.attach(target, {
        onEnter(args) {
          args[1] = ptr(0); // mode = SSL_VERIFY_NONE
          args[2] = ptr(0); // callback = null
          if (isDebugging) console.log(`[NativeTlsBypass] ${name}() forcing SSL_VERIFY_NONE`);
        },
      });
    };

    disableVerifyMode("SSL_set_verify", sslSetVerify);
    disableVerifyMode("SSL_CTX_set_verify", sslCtxSetVerify);
    disableVerifyMode("SSL_set_custom_verify", sslSetCustomVerify);
    disableVerifyMode("SSL_CTX_set_custom_verify", sslCtxSetCustomVerify);

    const mbedVerify = findExport("mbedtls_x509_crt_verify");
    const mbedVerifyProfile = findExport("mbedtls_x509_crt_verify_with_profile");
    const mbedVerifyRestartable = findExport("mbedtls_x509_crt_verify_restartable");

    const replaceInt0 = (name: string, target: NativePointerOrNull) => {
      if (target == null) return;
      Interceptor.replace(
        target,
        new NativeCallback(
          () => {
            if (isDebugging) console.log(`[NativeTlsBypass] ${name}() forcing verify OK`);
            return 0;
          },
          "int",
          ["pointer", "pointer", "pointer", "pointer", "pointer", "pointer"]
        )
      );
    };

    replaceInt0("mbedtls_x509_crt_verify", mbedVerify);
    replaceInt0("mbedtls_x509_crt_verify_with_profile", mbedVerifyProfile);
    replaceInt0("mbedtls_x509_crt_verify_restartable", mbedVerifyRestartable);

    // Initial BoringSSL export scan
    const boringFunctions = [
      "ssl_verify_peer_cert",
      "SSL_do_handshake",
      "X509_verify_peer_cert_by_callback",
      "tls13_process_certificate_verify",
    ];
    for (const funcName of boringFunctions) {
      const ptr = findExport(funcName);
      if (ptr != null && isDebugging) {
        console.log(`[NativeTlsBypass] Found ${funcName} at ${ptr}`);
      }
    }

    // Helper to hook SSL_CTX_set_cert_verify_callback
    const hookCertVerifyCallback = (mod: any) => {
      const setCb = mod.findExportByName("SSL_CTX_set_cert_verify_callback");
      if (setCb) {
        Interceptor.attach(setCb, {
          onEnter(args) {
            if (isDebugging) console.log(`${ts()} [NativeTlsBypass] SSL_CTX_set_cert_verify_callback called in ${mod.name}. Replacing callback.`);
            args[1] = certVerifyCallback;
          }
        });
      }
      const setCb2 = mod.findExportByName("SSL_set_cert_verify_callback");
      if (setCb2) {
        Interceptor.attach(setCb2, {
          onEnter(args) {
            if (isDebugging) console.log(`${ts()} [NativeTlsBypass] SSL_set_cert_verify_callback called in ${mod.name}. Replacing callback.`);
            args[1] = certVerifyCallback;
          }
        });
      }
    };

    // Scan all loaded modules
    const modules = Process.enumerateModules();
    for (const mod of modules) {
      const name = mod.name.toLowerCase();

      if (!name.includes("ssl") && !name.includes("crypto") && !name.includes("tls") && !name.includes("boring") && !name.includes("conscrypt") && !name.includes("unity")) continue;

      if (isDebugging) console.log(`[NativeTlsBypass] Scanning module: ${mod.name}`);

      hookCertVerifyCallback(mod);

      try {
        const exports = mod.enumerateExports();
        for (const exp of exports) {
          const expName = exp.name.toLowerCase();
          if (expName.includes("verify") && (expName.includes("cert") || expName.includes("peer"))) {
            if (exp.name === "SSL_get_verify_result" || exp.name === "ssl_verify_peer_cert") {
              try {
                Interceptor.replace(
                  exp.address,
                  new NativeCallback(
                    (..._args) => {
                      if (isDebugging) console.log(`[NativeTlsBypass] ${exp.name}() -> forcing OK`);
                      return 0;
                    },
                    "long",
                    ["pointer"]
                  )
                );
              } catch (e) { }
            }
          }
        }
      } catch (e) {
      }

      const setVerifyPtr = mod.findExportByName("SSL_CTX_set_verify");
      if (setVerifyPtr) {
        Interceptor.attach(setVerifyPtr, {
          onEnter(args) {
            args[1] = ptr(0);
            args[2] = ptr(0);
            if (isDebugging) console.log(`[NativeTlsBypass] SSL_CTX_set_verify (${mod.name}) -> forcing SSL_VERIFY_NONE`);
          },
        });
      }
      const setVerifyPtr2 = mod.findExportByName("SSL_set_verify");
      if (setVerifyPtr2) {
        Interceptor.attach(setVerifyPtr2, {
          onEnter(args) {
            args[1] = ptr(0);
            args[2] = ptr(0);
            if (isDebugging) console.log(`[NativeTlsBypass] SSL_set_verify (${mod.name}) -> forcing SSL_VERIFY_NONE`);
          },
        });
      }

      // Manual hook for libunity.so (mbedtls verification)
      if (mod.name === "libunity.so") {
        const offset = 0xbc25b4;
        const target = mod.base.add(offset);
        console.log(`[NativeTlsBypass] Hooking libunity.so verify function at ${target} (base+${ptr(offset)})`);
        try {
          Interceptor.attach(target, {
            onEnter: function (args) {
              console.log(`[NativeTlsBypass] libunity.so verify function called (args: ${args[0]}, ${args[1]}, ${args[2]})`);
            },
            onLeave: function (retval) {
              console.log(`[NativeTlsBypass] libunity.so verify function returning: ${retval} -> forcing 0`);
              retval.replace(ptr(0));
            }
          });
        } catch (e) {
          console.log(`[NativeTlsBypass] Failed to hook libunity.so manual offset: ${e}`);
        }
      }
    }
  }
}

function ts(): string {
  const now = new Date();
  return `[${now.toISOString().split('T')[1].slice(0, -1)}]`;
}
