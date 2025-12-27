/*  Frida script to bypass multiple certificate pinning methods
    Run with: frida -U -f [APP_ID] -l frida_multiple_unpinning.js --no-pause
    Original author: Maurizio Siddu
    Modified by: @Nopsled for Rearchero project
*/

export class FridaMultipleUnpinning {
  public static bypass(isDebugging = false) {
    Java.perform(() => {
      console.log("");
      console.log("======");
      console.log("[#] Android Bypass for various Certificate Pinning methods [#]");
      console.log("======");

      var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
      var SSLContext = Java.use("javax.net.ssl.SSLContext");

      // TrustManager (Android < 7) //
      ////////////////////////////////
      var TrustManager = Java.registerClass({
        // Implement a custom TrustManager
        name: "dev.asd.test.TrustManager",
        implements: [X509TrustManager],
        methods: {
          checkClientTrusted: (chain, authType) => {},
          checkServerTrusted: (chain, authType) => {},
          getAcceptedIssuers: () => [],
        },
      });
      // Prepare the TrustManager array to pass to SSLContext.init()
      var TrustManagers = [TrustManager.$new()];
      // Get a handle on the init() on the SSLContext class
      var SSLContext_init = SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;",
        "java.security.SecureRandom"
      );
      try {
        // Override the init method, specifying the custom TrustManager
        SSLContext_init.implementation = function (
          keyManager: any,
          trustManager: any,
          secureRandom: any
        ) {
          if (isDebugging) console.log("[+] Bypassing Trustmanager (Android < 7) pinner");
          SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
        };
      } catch (err) {
        if (isDebugging) console.log("[-] TrustManager (Android < 7) pinner not found");
        //console.log(err);
      }

      // OkHTTPv3 (quadruple bypass) //
      /////////////////////////////////
      try {
        // Bypass OkHTTPv3 {1}
        var okhttp3_Activity_1 = Java.use("okhttp3.CertificatePinner");
        okhttp3_Activity_1.check.overload("java.lang.String", "java.util.List").implementation = (
          a: any,
          b: any
        ) => {
          if (isDebugging) console.log("[+] Bypassing OkHTTPv3 {1}: " + a);

          return;
        };
      } catch (err) {
        if (isDebugging) console.log("[-] OkHTTPv3 {1} pinner not found");
        //console.log(err);
      }
      try {
        // Bypass OkHTTPv3 {2}
        // This method of CertificatePinner.check is deprecated but could be found in some old Android apps
        var okhttp3_Activity_2 = Java.use("okhttp3.CertificatePinner");
        okhttp3_Activity_2.check.overload(
          "java.lang.String",
          "java.security.cert.Certificate"
        ).implementation = (a: any, b: any) => {
          if (isDebugging) console.log("[+] Bypassing OkHTTPv3 {2}: " + a);
          return;
        };
      } catch (err) {
        if (isDebugging) console.log("[-] OkHTTPv3 {2} pinner not found");
        //console.log(err);
      }
      try {
        // Bypass OkHTTPv3 {3}
        var okhttp3_Activity_3 = Java.use("okhttp3.CertificatePinner");
        okhttp3_Activity_3.check.overload(
          "java.lang.String",
          "[Ljava.security.cert.Certificate;"
        ).implementation = (a: any, b: any) => {
          if (isDebugging) console.log("[+] Bypassing OkHTTPv3 {3}: " + a);
          return;
        };
      } catch (err) {
        if (isDebugging) console.log("[-] OkHTTPv3 {3} pinner not found");
        //console.log(err);
      }
      try {
        // Bypass OkHTTPv3 {4}
        var okhttp3_Activity_4 = Java.use("okhttp3.CertificatePinner");
        //okhttp3_Activity_4['check$okhttp'].implementation = function(a, b) {
        okhttp3_Activity_4.check$okhttp.overload(
          "java.lang.String",
          "kotlin.jvm.functions.Function0"
        ).implementation = (a: any, b: any) => {
          if (isDebugging) console.log("[+] Bypassing OkHTTPv3 {4}: " + a);

          return;
        };
      } catch (err) {
        if (isDebugging) console.log("[-] OkHTTPv3 {4} pinner not found");
        //console.log(err);
      }

      // TrustManagerImpl (Android > 7) //
      ////////////////////////////////////
      try {
        // Bypass TrustManagerImpl (Android > 7) {1}
        var array_list = Java.use("java.util.ArrayList");
        var TrustManagerImpl_Activity_1 = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl_Activity_1.checkTrustedRecursive.implementation = (
          certs: any,
          ocspData: any,
          tlsSctData: any,
          host: any,
          clientAuth: any,
          untrustedChain: any,
          trustAnchorChain: any,
          used: any
        ) => {
          if (isDebugging)
            console.log(
              "[+] Bypassing TrustManagerImpl (Android > 7) checkTrustedRecursive check: " + host
            );
          return array_list.$new();
        };
      } catch (err) {
        if (isDebugging)
          console.log("[-] TrustManagerImpl (Android > 7) checkTrustedRecursive check not found");
        //console.log(err);
      }
      try {
        // Bypass TrustManagerImpl (Android > 7) {2} (probably no more necessary)
        var TrustManagerImpl_Activity_2 = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl_Activity_2.verifyChain.implementation = (
          untrustedChain: any,
          trustAnchorChain: any,
          host: any,
          clientAuth: any,
          ocspData: any,
          tlsSctData: any
        ) => {
          if (isDebugging)
            console.log("[+] Bypassing TrustManagerImpl (Android > 7) verifyChain check: " + host);
          return untrustedChain;
        };
      } catch (err) {
        if (isDebugging)
          console.log("[-] TrustManagerImpl (Android > 7) verifyChain check not found");
        //console.log(err);
      }
    });
  }
}
