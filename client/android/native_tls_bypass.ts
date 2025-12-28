/// <reference path="../frida.d.ts" />

type NativePointerOrNull = NativePointer | null;

function findGlobal(name: string): NativePointerOrNull {
  const moduleApi = Module as unknown as {
    findExportByName?: (moduleName: string | null, exportName: string) => NativePointerOrNull;
    findGlobalExportByName?: (exportName: string) => NativePointerOrNull;
  };

  if (typeof moduleApi.findGlobalExportByName === "function") {
    return moduleApi.findGlobalExportByName(name);
  }
  if (typeof moduleApi.findExportByName === "function") {
    return moduleApi.findExportByName(null, name);
  }
  return null;
}

function ptrInfo(pointer: NativePointerOrNull) {
  return pointer == null ? "null" : pointer.toString();
}

export class NativeTlsBypass {
  static enable(isDebugging = false) {
    const sslGetVerifyResult = findGlobal("SSL_get_verify_result");
    const x509VerifyCert = findGlobal("X509_verify_cert");
    const sslSetVerify = findGlobal("SSL_set_verify");
    const sslCtxSetVerify = findGlobal("SSL_CTX_set_verify");
    const sslSetCustomVerify = findGlobal("SSL_set_custom_verify");
    const sslCtxSetCustomVerify = findGlobal("SSL_CTX_set_custom_verify");

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
        new NativeCallback((_ssl) => {
          // X509_V_OK
          return 0;
        }, "long", ["pointer"])
      );
    }

    if (x509VerifyCert != null) {
      Interceptor.replace(
        x509VerifyCert,
        new NativeCallback((_ctx) => {
          // success
          return 1;
        }, "int", ["pointer"])
      );
    }

    const disableVerifyMode = (name: string, target: NativePointerOrNull) => {
      if (target == null) return;
      Interceptor.attach(target, {
        onEnter(args) {
          // mode is int; set to 0 (SSL_VERIFY_NONE)
          args[1] = ptr(0);
          // callback pointer
          args[2] = ptr(0);
          if (isDebugging) console.log(`[NativeTlsBypass] ${name}() forcing SSL_VERIFY_NONE`);
        },
      });
    };

    disableVerifyMode("SSL_set_verify", sslSetVerify);
    disableVerifyMode("SSL_CTX_set_verify", sslCtxSetVerify);
    disableVerifyMode("SSL_set_custom_verify", sslSetCustomVerify);
    disableVerifyMode("SSL_CTX_set_custom_verify", sslCtxSetCustomVerify);
  }
}
