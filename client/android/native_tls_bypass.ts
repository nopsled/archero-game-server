/// <reference path="../frida.d.ts" />

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
  static enable(isDebugging = false) {
    const sslGetVerifyResult = findExport("SSL_get_verify_result");
    const x509VerifyCert = findExport("X509_verify_cert");
    const sslSetVerify = findExport("SSL_set_verify");
    const sslCtxSetVerify = findExport("SSL_CTX_set_verify");
    const sslSetCustomVerify = findExport("SSL_set_custom_verify");
    const sslCtxSetCustomVerify = findExport("SSL_CTX_set_custom_verify");

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
          (_ssl) => {
            // X509_V_OK
            return 0;
          },
          "long",
          ["pointer"]
        )
      );
    }

    if (x509VerifyCert != null) {
      Interceptor.replace(
        x509VerifyCert,
        new NativeCallback(
          (_ctx) => {
            // success
            return 1;
          },
          "int",
          ["pointer"]
        )
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

    // Unity/IL2CPP apps often use mbedTLS or UnityTLS rather than OpenSSL.
    // Best-effort: force x509 verify to succeed if these exports exist.
    const mbedVerify = findExport("mbedtls_x509_crt_verify");
    const mbedVerifyProfile = findExport("mbedtls_x509_crt_verify_with_profile");
    const mbedVerifyRestartable = findExport("mbedtls_x509_crt_verify_restartable");

    if (isDebugging) {
      console.log(
        `[NativeTlsBypass] exports mbedtls_x509_crt_verify=${ptrInfo(
          mbedVerify
        )} mbedtls_x509_crt_verify_with_profile=${ptrInfo(
          mbedVerifyProfile
        )} mbedtls_x509_crt_verify_restartable=${ptrInfo(mbedVerifyRestartable)}`
      );
    }

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
  }
}
